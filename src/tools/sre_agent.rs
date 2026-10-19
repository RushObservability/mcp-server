//! `sre_agent` toolset: hand investigations to the Rush SRE agent, follow them
//! up, and turn natural language into Rush filters. Every tool here needs a
//! query key with agent access, and starting or continuing an investigation
//! (and parsing) spends the tenant's LLM budget.

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, NaiveDateTime, Utc};
use rmcp::{
    RoleServer,
    handler::server::wrapper::{Json, Parameters},
    model::CallToolResult,
    service::RequestContext,
    tool, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::api::{
    Filter, InvestigateRequest, InvestigationTemplate, InvestigationTurn, InvestigationWindow, Op,
    ParsedQuery, SessionDetail, SessionsResponse, SignalKind, TemplatesResponse, query_text,
};
use crate::client::{ApiError, ClientKey};
use crate::envelope::{Envelope, Hint, Trim, clip};
use crate::investigations::{Live, Progress, Step, follow};
use crate::links::{Signal, id_from};
use crate::server::{RushMcp, ToolError};
use crate::time::TimeArgs;
use crate::tools::{MAX_SEARCH_CHARS, pop, round2};

/// Longest a started run is followed, matching the agent's own limits.
const STREAM_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const DEFAULT_START_WAIT: u64 = 30;
const MAX_START_WAIT: u64 = 45;
const MAX_GET_WAIT: u64 = 120;
/// Extra time allowed for the agent to name a new session.
const SESSION_GRACE: Duration = Duration::from_secs(15);
/// A question with no report after this long has most likely failed.
const STALLED_AFTER_MINUTES: i64 = 20;
const MAX_QUESTION_CHARS: usize = 4_000;
const MAX_CONTEXT_CHARS: usize = 8_000;
const REPORT_CHARS: usize = 8_000;
const REPORT_FLOOR: usize = 1_500;

const AGENT_ACCESS_HELP: &str = "The key needs agent access: in Rush, open Settings → API Keys and create a query key with \"Allow SRE agent and natural-language search\" turned on. Admins can also limit which tenants may use the SRE agent.";

// ── Arguments ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StartInvestigationArgs {
    /// What to investigate, in plain language, e.g. "Why did checkout errors jump at 14:05?".
    /// Required unless `anomaly_event_id` is given.
    #[serde(default)]
    pub question: Option<String>,
    /// Template ID from list_investigation_templates, e.g. "alert_investigation" or "postmortem".
    #[serde(default)]
    pub template: Option<String>,
    /// Start from this anomaly event (see list_anomalies); the agent loads its rule and context.
    #[serde(default)]
    pub anomaly_event_id: Option<String>,
    /// Extra context for the agent: findings so far, links, what has been ruled out.
    #[serde(default)]
    pub context: Option<String>,
    /// Incident window. When set, the agent compares it with the same-length window just before it.
    /// Omit to let the agent choose.
    #[serde(flatten)]
    pub time: TimeArgs,
    /// Seconds to wait for a result before returning (default 30, max 45). The run continues
    /// after this; read it with get_investigation.
    #[serde(default)]
    pub wait_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ContinueInvestigationArgs {
    /// Session ID or Rush SRE agent link.
    pub session_id: String,
    /// Follow-up question or the answer to the agent's question.
    pub question: String,
    /// Narrow or move the incident window for this turn. Omit to keep the session's.
    #[serde(flatten)]
    pub time: TimeArgs,
    /// Seconds to wait for the answer (default 30, max 45).
    #[serde(default)]
    pub wait_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetInvestigationArgs {
    /// Session ID or Rush SRE agent link.
    pub session_id: String,
    /// Wait up to this many seconds for a running investigation to finish (default 0, max 120).
    #[serde(default)]
    pub wait_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListInvestigationsArgs {
    /// Most recent sessions to return (default 20, max 100).
    #[serde(default)]
    pub limit: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ParseQueryArgs {
    /// Plain-language description of what to find, e.g. "500 errors from checkout in production".
    pub query: String,
    /// Which data the filters are for (default logs).
    #[serde(default)]
    pub signal: Option<SignalKind>,
    /// Window for the Explore link (default the last hour).
    #[serde(flatten)]
    pub time: TimeArgs,
}

// ── Results ───────────────────────────────────────────────────────────────

/// One agent tool call and its result.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
pub struct StepOut {
    pub tool: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub input: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
}

impl From<Step> for StepOut {
    fn from(s: Step) -> Self {
        Self {
            tool: s.tool,
            input: s.input,
            result: s.result,
        }
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
pub struct Usage {
    /// Tokens the session has used so far, as Rush recorded them.
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub model: String,
    /// Agent rounds in the latest run, when this server followed it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rounds: Option<u32>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Investigation {
    pub session_id: String,
    pub title: String,
    /// running, completed (final report), preliminary (findings with open questions),
    /// needs_answer (the agent asked a question; answer with continue_investigation),
    /// failed, or stalled (no report after 20 minutes).
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    /// The latest question asked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub question: Option<String>,
    /// The latest report: the agent's findings, or its question back.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<String>,
    /// final, preliminary or question.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The evidence trail of the latest run: each tool the agent called, oldest first.
    pub steps: Vec<StepOut>,
    #[serde(skip_serializing_if = "is_zero")]
    pub steps_omitted: usize,
    /// Questions and reports in the session.
    pub turns: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub created_at: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub updated_at: String,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

impl Trim for Investigation {
    fn trim(&mut self) -> bool {
        if self.steps.pop().is_some() {
            self.steps_omitted += 1;
            return true;
        }
        if let Some(r) = self.report.as_mut() {
            let len = r.chars().count();
            if len > REPORT_FLOOR {
                *r = clip(r, (len / 2).max(REPORT_FLOOR));
                return true;
            }
        }
        if let Some(q) = self.question.as_mut() {
            if q.chars().count() > 300 {
                *q = clip(q, 300);
                return true;
            }
        }
        false
    }
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct InvestigationItem {
    pub session_id: String,
    pub title: String,
    /// running (followed by this server), active (open for follow-ups) or completed.
    pub status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub template_id: String,
    pub updated_at: String,
    pub tokens: u64,
    pub link: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct InvestigationList {
    /// Most recently updated first.
    pub investigations: Vec<InvestigationItem>,
}

impl Trim for InvestigationList {
    fn trim(&mut self) -> bool {
        pop(&mut self.investigations)
    }
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct TemplateList {
    pub templates: Vec<InvestigationTemplate>,
}

impl Trim for TemplateList {
    fn trim(&mut self) -> bool {
        pop(&mut self.templates)
    }
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ParsedQueryOut {
    pub signal: SignalKind,
    /// Ready to pass as `filters` to search_logs, search_spans or aggregate.
    pub filters: Vec<Filter>,
    /// Ready to pass as `search`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,
    /// The parser's confidence, 0 to 1. Below 0.6 the result is mostly free-text search.
    pub confidence: f64,
    /// Conditions the parser produced that this signal can't use.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dropped: Vec<String>,
}

impl Trim for ParsedQueryOut {
    fn trim(&mut self) -> bool {
        pop(&mut self.dropped)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn session_id(raw: &str) -> Result<String, ToolError> {
    id_from(raw, "sre-agent").ok_or_else(|| {
        ToolError::Input(format!(
            "`{raw}` is not an SRE agent session ID or a Rush SRE agent link"
        ))
    })
}

fn text_arg(raw: Option<&str>, name: &str, max: usize) -> Result<String, ToolError> {
    let s = raw.map(str::trim).unwrap_or_default();
    if s.chars().count() > max {
        return Err(ToolError::Input(format!(
            "{name} must be at most {max} characters"
        )));
    }
    Ok(s.to_string())
}

fn wait(raw: Option<u64>, default: u64, max: u64) -> Duration {
    Duration::from_secs(raw.unwrap_or(default).min(max))
}

/// The incident window, when the caller gave one.
fn window_arg(time: &TimeArgs) -> Result<Option<InvestigationWindow>, ToolError> {
    let set = |v: &Option<String>| v.as_deref().is_some_and(|s| !s.trim().is_empty());
    if !set(&time.last) && !set(&time.from) {
        return Ok(None);
    }
    Ok(Some(InvestigationWindow::from(&time.resolve()?)))
}

/// Explain refusals that come from the key lacking agent access.
fn agent_error(e: ApiError) -> ToolError {
    match e {
        ApiError::Forbidden(m) => ToolError::Input(format!(
            "Rush refused the SRE agent request ({m}). {AGENT_ACCESS_HELP}"
        )),
        other => ToolError::Api(other),
    }
}

/// Rush timestamps come as RFC3339 or `YYYY-MM-DD HH:MM:SS[.fff]` in UTC.
fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    DateTime::parse_from_rfc3339(s)
        .map(|t| t.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f")
                .ok()
                .map(|t| t.and_utc())
        })
}

fn report_status(kind: &str) -> &'static str {
    match kind {
        "preliminary" => "preliminary",
        "question" => "needs_answer",
        _ => "completed",
    }
}

/// Steps saved with an assistant turn (the run's tool events).
fn saved_steps(turn: &InvestigationTurn) -> Progress {
    let mut p = Progress::default();
    if let Ok(Value::Array(events)) = serde_json::from_str::<Value>(&turn.tool_calls) {
        for e in &events {
            p.apply(e);
        }
    }
    p
}

/// Combine Rush's stored session with this server's view of a live run.
pub fn build_investigation(
    id: &str,
    detail: &SessionDetail,
    live: Option<&Progress>,
    now: DateTime<Utc>,
) -> Investigation {
    let mut turns: Vec<&InvestigationTurn> = detail.turns.iter().collect();
    turns.sort_by_key(|t| t.turn_index);
    let last = turns.last().copied();
    let last_report = turns.iter().rev().find(|t| t.role == "assistant").copied();
    let question = turns
        .iter()
        .rev()
        .find(|t| t.role == "user")
        .map(|t| clip(t.content.trim(), 1_000));

    let mut status = match last {
        Some(t) if t.role == "assistant" => report_status(&t.report_kind),
        Some(t) => {
            let stalled = parse_time(&t.created_at)
                .is_some_and(|at| (now - at).num_minutes() >= STALLED_AFTER_MINUTES);
            if stalled { "stalled" } else { "running" }
        }
        None => "running",
    };
    // Only a report that answers the latest question is shown; an older one
    // belongs to an earlier turn.
    let answered = last.is_some_and(|t| t.role == "assistant");
    let stored = last_report
        .filter(|_| answered)
        .map(|t| (t.content.clone(), t.report_kind.clone()));
    let mut error = None;
    let mut rounds = None;
    let report;
    let (steps, steps_omitted);

    match live {
        Some(live) => {
            if !live.finished {
                status = "running";
                report = live.summary.clone();
            } else if let Some(e) = &live.error {
                status = "failed";
                error = Some(e.clone());
                report = None;
            } else if let Some((text, kind)) = &live.summary {
                status = report_status(kind);
                report = Some((text.clone(), kind.clone()));
            } else {
                report = stored;
            }
            rounds = live.done.as_ref().map(|d| d.rounds);
            (steps, steps_omitted) = (live.steps.clone(), live.steps_dropped);
        }
        None => {
            let saved = last_report.filter(|_| answered).map(saved_steps);
            (steps, steps_omitted) = saved
                .map(|p| (p.steps, p.steps_dropped))
                .unwrap_or_default();
            report = stored;
        }
    }

    let s = &detail.session;
    let usage =
        (s.prompt_tokens > 0 || s.completion_tokens > 0 || rounds.is_some()).then(|| Usage {
            prompt_tokens: s.prompt_tokens.max(0) as u64,
            completion_tokens: s.completion_tokens.max(0) as u64,
            model: s.llm_model.clone(),
            rounds,
        });
    Investigation {
        session_id: id.to_string(),
        title: s.title.clone(),
        status: status.to_string(),
        template_id: (!s.template_id.is_empty()).then(|| s.template_id.clone()),
        question,
        report_kind: report
            .as_ref()
            .map(|(_, k)| k.clone())
            .filter(|k| !k.is_empty()),
        report: report.map(|(t, _)| clip(t.trim(), REPORT_CHARS)),
        error,
        steps: steps.into_iter().map(StepOut::from).collect(),
        steps_omitted,
        turns: turns.len(),
        usage,
        created_at: s.created_at.clone(),
        updated_at: s.updated_at.clone(),
    }
}

fn summarize(inv: &Investigation) -> String {
    let title = if inv.title.is_empty() {
        "Investigation".to_string()
    } else {
        format!("\"{}\"", clip(&inv.title, 80))
    };
    let steps = inv.steps.len() + inv.steps_omitted;
    match inv.status.as_str() {
        "running" => format!(
            "{title} is still running ({steps} tool calls so far). Call get_investigation with wait_seconds to wait for the report."
        ),
        "completed" => format!("{title} finished with a final report after {steps} tool calls."),
        "preliminary" => format!(
            "{title} returned preliminary findings with open questions after {steps} tool calls."
        ),
        "needs_answer" => {
            format!("{title} needs an answer to its question; reply with continue_investigation.")
        }
        "failed" => format!(
            "{title} failed: {}",
            inv.error.as_deref().unwrap_or("unknown error")
        ),
        "stalled" => format!(
            "{title} has had no report for over {STALLED_AFTER_MINUTES} minutes; it most likely failed."
        ),
        other => format!("{title}: {other}."),
    }
}

fn hints_for(inv: &Investigation) -> Vec<Hint> {
    match inv.status.as_str() {
        "running" => vec![
            Hint::new("The agent keeps working after this call returns.")
                .action("Call get_investigation with wait_seconds up to 120")
                .action("Or open the link to watch it in Rush"),
        ],
        "preliminary" | "completed" => vec![
            Hint::new("The report is the agent's reading of the evidence; check the steps and links before acting on it.")
                .action("Ask a follow-up with continue_investigation"),
        ],
        "needs_answer" => vec![
            Hint::new("The agent asked a question.")
                .action("Answer it with continue_investigation"),
        ],
        "failed" | "stalled" => vec![
            Hint::new("The run ended without a report.")
                .action("Try again with continue_investigation, or start a narrower investigation"),
        ],
        _ => Vec::new(),
    }
}

impl RushMcp {
    async fn session_detail(
        &self,
        key: Option<&ClientKey>,
        tool: &str,
        id: &str,
    ) -> Result<SessionDetail, ToolError> {
        self.state
            .client
            .get(key, tool, &format!("/api/v1/sessions/{id}"), &[])
            .await
            .map_err(|e| match e {
                ApiError::NotFound(_) => ToolError::Input(format!(
                    "No SRE agent session `{id}` in this tenant; list_investigations shows recent ones"
                )),
                other => agent_error(other),
            })
    }

    /// Post an investigation, follow its stream in the background, and wait
    /// up to `wait` for it to finish. Returns the run and its session ID.
    async fn launch(
        &self,
        key: Option<&ClientKey>,
        tool: &'static str,
        req: InvestigateRequest,
        wait: Duration,
    ) -> Result<(Arc<Live>, String), ToolError> {
        let live = self
            .state
            .investigations
            .begin(key)
            .map_err(ToolError::Input)?;
        if !req.session_id.is_empty() {
            live.set_session(&req.session_id);
        }
        let resp = match self
            .state
            .client
            .post_stream(key, tool, "/api/v1/investigate", &req, STREAM_TIMEOUT)
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                live.abandon(e.to_string());
                return Err(agent_error(e));
            }
        };
        tokio::spawn(follow(resp, live.clone()));
        let started = Instant::now();
        live.wait_until(started + wait, |p| p.finished).await;
        live.wait_until(started + wait + SESSION_GRACE, |p| {
            p.session_id.is_some() || p.finished
        })
        .await;
        let (id, error) = {
            let p = live.progress();
            (p.session_id.clone(), p.error.clone())
        };
        match (id, error) {
            (Some(id), _) => Ok((live, id)),
            (None, Some(e)) => Err(ToolError::Input(format!("The SRE agent failed: {e}"))),
            (None, None) => Err(ToolError::Input(
                "The SRE agent accepted the request but hasn't named the session yet; call list_investigations in a moment".into(),
            )),
        }
    }

    /// The envelope for one investigation, reading Rush's stored session.
    async fn investigation_envelope(
        &self,
        key: Option<&ClientKey>,
        tool: &'static str,
        id: &str,
        live: Option<&Arc<Live>>,
    ) -> Result<Envelope<Investigation>, ToolError> {
        let (detail, note) = match self.session_detail(key, tool, id).await {
            Ok(d) => (d, None),
            // The run is known from its stream even if the read fails.
            Err(e) if live.is_some() => (SessionDetail::default(), Some(e.to_string())),
            Err(e) => return Err(e),
        };
        let inv = {
            let progress = live.map(|l| l.progress());
            build_investigation(id, &detail, progress.as_deref(), Utc::now())
        };
        let links = self.links(key).await;
        let mut env =
            Envelope::new(summarize(&inv), inv).link("investigation", links.sre_session(id));
        for h in hints_for(&env.result) {
            env = env.hint(h);
        }
        if let Some(n) = note {
            env = env.hint(Hint::new(format!(
                "Couldn't read the stored session from Rush: {n}"
            )));
        }
        Ok(env)
    }
}

fn normalize_filter(signal: SignalKind, f: &crate::api::ParsedFilter) -> Result<Filter, String> {
    let shown = format!("{} {} {}", f.field, f.op, f.value);
    let op = Op::parse(&f.op).ok_or_else(|| format!("{shown} (unknown operator)"))?;
    let field = f.field.trim();
    if field.is_empty() {
        return Err(format!("{shown} (no field)"));
    }
    let value = f.value.clone();
    let level = || value.as_str().unwrap_or_default().to_ascii_lowercase();
    let (field, op, value) = match (signal, field) {
        (SignalKind::Logs, "level") => ("severity".to_string(), op, value.clone()),
        (SignalKind::Spans, "status_code") => ("http_status_code".to_string(), op, value.clone()),
        (SignalKind::Spans, "level") if level() == "error" => {
            ("error".to_string(), Op::Eq, Value::from(1))
        }
        (SignalKind::Spans, "level") => return Err(format!("{shown} (spans have no log level)")),
        (_, other) => (other.to_string(), op, value.clone()),
    };
    Ok(Filter { field, op, value })
}

// ── Tools ─────────────────────────────────────────────────────────────────

#[tool_router(router = sre_agent_router, vis = "pub(crate)")]
impl RushMcp {
    #[tool(
        description = "Hand an investigation to the Rush SRE agent, which queries logs, traces, metrics, deploys and alerts on its own and writes a report. Give a question, or an anomaly event ID, optionally a template and an incident window. Waits up to wait_seconds (default 30) and returns the report if it finished, otherwise the evidence so far and a session ID for get_investigation. Spends the tenant's LLM budget; needs a key with agent access.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn start_investigation(
        &self,
        Parameters(args): Parameters<StartInvestigationArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<Investigation>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("start_investigation", async {
            let key = key.as_ref();
            let question = text_arg(args.question.as_deref(), "question", MAX_QUESTION_CHARS)?;
            let event_id = match args
                .anomaly_event_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                Some(raw) => id_from(raw, "anomaly").ok_or_else(|| {
                    ToolError::Input(format!("`{raw}` is not an anomaly event ID"))
                })?,
                None => String::new(),
            };
            if question.is_empty() && event_id.is_empty() {
                return Err(ToolError::Input(
                    "give a question, or an anomaly_event_id to investigate".into(),
                ));
            }
            let context = text_arg(args.context.as_deref(), "context", MAX_CONTEXT_CHARS)?;
            let template_id = text_arg(args.template.as_deref(), "template", 64)?;
            if !template_id.is_empty() {
                let known: TemplatesResponse = self
                    .state
                    .client
                    .get(
                        key,
                        "start_investigation",
                        "/api/v1/investigation-templates",
                        &[],
                    )
                    .await
                    .map_err(agent_error)?;
                if !known.templates.iter().any(|t| t.id == template_id) {
                    return Err(ToolError::Input(format!(
                        "unknown template `{template_id}`; known templates: {}",
                        known
                            .templates
                            .iter()
                            .map(|t| t.id.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )));
                }
            }
            let req = InvestigateRequest {
                question,
                event_id,
                additional_context: context,
                template_id,
                window: window_arg(&args.time)?,
                ..Default::default()
            };
            let wait = wait(args.wait_seconds, DEFAULT_START_WAIT, MAX_START_WAIT);
            let (live, id) = self.launch(key, "start_investigation", req, wait).await?;
            self.investigation_envelope(key, "start_investigation", &id, Some(&live))
                .await
        })
        .await
    }

    #[tool(
        description = "Ask the Rush SRE agent a follow-up in an existing investigation, or answer its question. The agent keeps the session's evidence and memory. Waits up to wait_seconds (default 30) like start_investigation. Spends the tenant's LLM budget.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn continue_investigation(
        &self,
        Parameters(args): Parameters<ContinueInvestigationArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<Investigation>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("continue_investigation", async {
            let key = key.as_ref();
            let id = session_id(&args.session_id)?;
            let question = text_arg(Some(&args.question), "question", MAX_QUESTION_CHARS)?;
            if question.is_empty() {
                return Err(ToolError::Input("question is required".into()));
            }
            if self
                .state
                .investigations
                .find(key, &id)
                .is_some_and(|l| !l.progress().finished)
            {
                return Err(ToolError::Input(format!(
                    "investigation `{id}` is still running; wait for it with get_investigation before asking a follow-up"
                )));
            }
            let req = InvestigateRequest {
                session_id: id.clone(),
                question,
                window: window_arg(&args.time)?,
                ..Default::default()
            };
            let wait = wait(args.wait_seconds, DEFAULT_START_WAIT, MAX_START_WAIT);
            let (live, id) = self.launch(key, "continue_investigation", req, wait).await?;
            self.investigation_envelope(key, "continue_investigation", &id, Some(&live))
                .await
        })
        .await
    }

    #[tool(
        description = "Read an SRE agent investigation: status, the latest question and report, the evidence trail (each tool the agent called with a one-line result) and token use. Set wait_seconds (max 120) to wait for a running investigation to finish.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn get_investigation(
        &self,
        Parameters(args): Parameters<GetInvestigationArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<Investigation>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("get_investigation", async {
            let key = key.as_ref();
            let id = session_id(&args.session_id)?;
            let deadline = Instant::now() + wait(args.wait_seconds, 0, MAX_GET_WAIT);
            let live = self.state.investigations.find(key, &id);
            match &live {
                Some(l) => {
                    l.wait_until(deadline, |p| p.finished).await;
                }
                None => {
                    // Another server, or an older run: poll the stored session.
                    while Instant::now() < deadline {
                        let detail = self.session_detail(key, "get_investigation", &id).await?;
                        if build_investigation(&id, &detail, None, Utc::now()).status != "running" {
                            break;
                        }
                        let left = deadline.saturating_duration_since(Instant::now());
                        tokio::time::sleep(left.min(Duration::from_secs(5))).await;
                    }
                }
            }
            self.investigation_envelope(key, "get_investigation", &id, live.as_ref())
                .await
        })
        .await
    }

    #[tool(
        description = "List recent SRE agent investigations in this tenant, most recently updated first, with title, status, template, token use and a Rush link.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn list_investigations(
        &self,
        Parameters(args): Parameters<ListInvestigationsArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<InvestigationList>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("list_investigations", async {
            let key = key.as_ref();
            let limit = args.limit.unwrap_or(20).clamp(1, 100);
            let resp: SessionsResponse = self
                .state
                .client
                .get(
                    key,
                    "list_investigations",
                    "/api/v1/sessions",
                    &[("limit", limit.to_string())],
                )
                .await
                .map_err(agent_error)?;
            let running = self.state.investigations.running(key);
            let links = self.links(key).await;
            let investigations: Vec<InvestigationItem> = resp
                .sessions
                .into_iter()
                .take(limit as usize)
                .map(|s| InvestigationItem {
                    status: if running.contains(&s.id) {
                        "running".into()
                    } else {
                        s.status
                    },
                    link: links.sre_session(&s.id),
                    title: clip(&s.title, 120),
                    template_id: s.template_id,
                    updated_at: s.updated_at,
                    tokens: (s.prompt_tokens.max(0) + s.completion_tokens.max(0)) as u64,
                    session_id: s.id,
                })
                .collect();
            let n_running = investigations
                .iter()
                .filter(|i| i.status == "running")
                .count();
            let summary = match investigations.len() {
                0 => "No SRE agent investigations in this tenant yet.".to_string(),
                n if n_running > 0 => {
                    format!("{n} investigations, {n_running} running on this server.")
                }
                n => format!("{n} investigations."),
            };
            Ok(Envelope::new(summary, InvestigationList { investigations })
                .link("sre_agent", links.sre_agent()))
        })
        .await
    }

    #[tool(
        description = "List the SRE agent's investigation templates (alert investigation, postmortem, capacity review, deploy review, security review) with what each does. Pass a template's id to start_investigation.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn list_investigation_templates(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<TemplateList>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("list_investigation_templates", async {
            let key = key.as_ref();
            let resp: TemplatesResponse = self
                .state
                .client
                .get(
                    key,
                    "list_investigation_templates",
                    "/api/v1/investigation-templates",
                    &[],
                )
                .await
                .map_err(agent_error)?;
            let summary = format!(
                "{} templates: {}.",
                resp.templates.len(),
                resp.templates
                    .iter()
                    .map(|t| t.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            Ok(Envelope::new(
                summary,
                TemplateList {
                    templates: resp.templates,
                },
            ))
        })
        .await
    }

    #[tool(
        description = "Turn a plain-language request (\"500 errors from checkout in production\") into Rush filters and free-text search for logs or spans, with an Explore link. Pass the result to search_logs, search_spans or aggregate. Uses the Rush LLM gateway; needs a key with agent access.",
        annotations(
            read_only_hint = true,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn parse_query(
        &self,
        Parameters(args): Parameters<ParseQueryArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<ParsedQueryOut>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("parse_query", async {
            let key = key.as_ref();
            let query = args.query.trim();
            if query.is_empty() || query.len() > 4_096 {
                return Err(ToolError::Input(
                    "query must be between 1 and 4096 bytes".into(),
                ));
            }
            let signal = args.signal.unwrap_or(SignalKind::Logs);
            let window = args.time.resolve()?;
            let parsed: ParsedQuery = self
                .state
                .client
                .post(
                    key,
                    "parse_query",
                    "/api/v1/parse-query",
                    &serde_json::json!({ "query": query }),
                )
                .await
                .map_err(|e| match e {
                    ApiError::Upstream(501, _) => ToolError::Input(
                        "Natural-language parsing is turned off in this Rush deployment (no LLM provider is configured). Build filters with list_fields instead.".into(),
                    ),
                    other => agent_error(other),
                })?;
            let mut filters = Vec::new();
            let mut dropped = Vec::new();
            for f in parsed.filters.iter().take(30) {
                match normalize_filter(signal, f) {
                    Ok(f) => filters.push(f),
                    Err(d) => dropped.push(d),
                }
            }
            let search = Some(clip(parsed.search.trim(), MAX_SEARCH_CHARS)).filter(|s| !s.is_empty());
            let confidence = round2(parsed.confidence.clamp(0.0, 1.0));
            let link_signal = match signal {
                SignalKind::Logs => Signal::Logs,
                SignalKind::Spans => Signal::Spans,
            };
            let links = self.links(key).await;
            let explore = links.explore(
                link_signal,
                &query_text(&filters, search.as_deref()),
                &window,
                None,
            );
            let summary = format!(
                "{} filter{}{}; confidence {confidence}.",
                filters.len(),
                if filters.len() == 1 { "" } else { "s" },
                search
                    .as_deref()
                    .map(|s| format!(" and search \"{}\"", clip(s, 80)))
                    .unwrap_or_default()
            );
            let mut env = Envelope::new(
                summary,
                ParsedQueryOut {
                    signal,
                    filters,
                    search,
                    confidence,
                    dropped,
                },
            )
            .window(&window)
            .link("explore", explore);
            if confidence < 0.6 {
                env = env.hint(
                    Hint::new("The parser mostly fell back to free-text search.")
                        .action("Check field names and values with list_fields and list_field_values"),
                );
            }
            Ok(env)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{InvestigationSession, ParsedFilter};
    use serde_json::json;

    fn turn(i: i64, role: &str, content: &str, kind: &str, at: &str) -> InvestigationTurn {
        InvestigationTurn {
            turn_index: i,
            role: role.into(),
            content: content.into(),
            tool_calls: "[]".into(),
            report_kind: kind.into(),
            created_at: at.into(),
        }
    }

    fn detail(turns: Vec<InvestigationTurn>) -> SessionDetail {
        SessionDetail {
            session: InvestigationSession {
                id: "s1".into(),
                title: "Checkout errors".into(),
                status: "active".into(),
                prompt_tokens: 1_000,
                completion_tokens: 200,
                llm_model: "m".into(),
                ..Default::default()
            },
            turns,
        }
    }

    fn now() -> DateTime<Utc> {
        parse_time("2026-10-18T15:00:00Z").unwrap()
    }

    #[test]
    fn status_comes_from_the_latest_turn() {
        let mut report = turn(
            1,
            "assistant",
            "Pool exhausted",
            "final",
            "2026-10-18 14:10:00",
        );
        report.tool_calls = json!([
            {"type":"tool_call","name":"search_logs","args":{"service":"checkout"}},
            {"type":"tool_result","name":"search_logs","data":"12 errors"}
        ])
        .to_string();
        let done = build_investigation(
            "s1",
            &detail(vec![
                report,
                turn(0, "user", "Why errors?", "", "2026-10-18 14:00:00"),
            ]),
            None,
            now(),
        );
        assert_eq!(done.status, "completed");
        assert_eq!(done.report.as_deref(), Some("Pool exhausted"));
        assert_eq!(done.question.as_deref(), Some("Why errors?"));
        assert_eq!(done.steps.len(), 1);
        assert_eq!(done.steps[0].result.as_deref(), Some("12 errors"));
        assert_eq!(done.usage.as_ref().map(|u| u.prompt_tokens), Some(1_000));

        let asking = build_investigation(
            "s1",
            &detail(vec![
                turn(0, "user", "q", "", "2026-10-18 14:00:00"),
                turn(
                    1,
                    "assistant",
                    "Which region?",
                    "question",
                    "2026-10-18 14:01:00",
                ),
            ]),
            None,
            now(),
        );
        assert_eq!(asking.status, "needs_answer");

        // A follow-up waiting on the agent hides the older report.
        let follow_up = build_investigation(
            "s1",
            &detail(vec![
                turn(0, "user", "q", "", "2026-10-18 14:00:00"),
                turn(1, "assistant", "old", "preliminary", "2026-10-18 14:01:00"),
                turn(2, "user", "and now?", "", "2026-10-18 14:55:00"),
            ]),
            None,
            now(),
        );
        assert_eq!(follow_up.status, "running");
        assert_eq!(follow_up.report, None);
        assert_eq!(follow_up.question.as_deref(), Some("and now?"));

        let stalled = build_investigation(
            "s1",
            &detail(vec![turn(0, "user", "q", "", "2026-10-18T14:00:00Z")]),
            None,
            now(),
        );
        assert_eq!(stalled.status, "stalled");
    }

    #[test]
    fn a_live_run_overrides_the_stored_state() {
        let stored = detail(vec![turn(0, "user", "q", "", "2026-10-18 14:00:00")]);
        let mut live = Progress::default();
        live.apply(&json!({"type":"session_created","session_id":"s1"}));
        live.apply(&json!({"type":"tool_call","name":"get_service","args":{"name":"checkout"}}));
        let running = build_investigation("s1", &stored, Some(&live), now());
        assert_eq!(running.status, "running");
        assert_eq!(running.steps[0].tool, "get_service");

        // Finished before Rush stored the report: the stream's report wins.
        live.apply(&json!({"type":"summary","text":"Found it","kind":"preliminary"}));
        live.apply(&json!({"type":"done","rounds":2,"tool_calls":1,"prompt_tokens":5,"completion_tokens":1,"session_id":"s1","model":"m"}));
        let mut finished = live;
        finished.finished = true;
        let inv = build_investigation("s1", &stored, Some(&finished), now());
        assert_eq!(inv.status, "preliminary");
        assert_eq!(inv.report.as_deref(), Some("Found it"));
        assert_eq!(inv.usage.and_then(|u| u.rounds), Some(2));

        let mut failed = Progress::default();
        failed.finished = true;
        failed.error = Some("provider unavailable".into());
        failed.session_id = Some("s1".into());
        let inv = build_investigation("s1", &stored, Some(&failed), now());
        assert_eq!(inv.status, "failed");
        assert!(summarize(&inv).contains("provider unavailable"));
    }

    #[test]
    fn trimming_drops_steps_then_shortens_the_report() {
        let mut inv = build_investigation("s1", &detail(Vec::new()), None, now());
        inv.steps = vec![
            StepOut {
                tool: "a".into(),
                input: String::new(),
                result: None
            };
            2
        ];
        inv.report = Some("x".repeat(6_000));
        assert!(inv.trim());
        assert_eq!((inv.steps.len(), inv.steps_omitted), (1, 1));
        assert!(inv.trim() && inv.trim());
        assert_eq!(inv.report.as_ref().unwrap().chars().count(), 3_000);
    }

    #[test]
    fn parsed_filters_use_the_signal_field_names() {
        let f = |field: &str, op: &str, value: Value| ParsedFilter {
            field: field.into(),
            op: op.into(),
            value,
        };
        let logs = normalize_filter(SignalKind::Logs, &f("level", "=", json!("error"))).unwrap();
        assert_eq!(logs.field, "severity");
        let spans =
            normalize_filter(SignalKind::Spans, &f("status_code", ">=", json!(500))).unwrap();
        assert_eq!(
            (spans.field.as_str(), spans.op),
            ("http_status_code", Op::Gte)
        );
        let err = normalize_filter(SignalKind::Spans, &f("level", "=", json!("error"))).unwrap();
        assert_eq!((err.field.as_str(), err.value), ("error", json!(1)));
        assert!(normalize_filter(SignalKind::Spans, &f("level", "=", json!("warn"))).is_err());
        assert!(normalize_filter(SignalKind::Logs, &f("service_name", "~=", json!("x"))).is_err());
    }

    #[test]
    fn windows_are_sent_only_when_asked_for() {
        assert_eq!(window_arg(&TimeArgs::default()).unwrap(), None);
        let w = window_arg(&TimeArgs {
            from: Some("2026-10-18T14:00:00Z".into()),
            to: Some("2026-10-18T14:30:00Z".into()),
            ..Default::default()
        })
        .unwrap()
        .unwrap();
        assert_eq!(w.baseline_start, "2026-10-18T13:30:00Z");
        assert_eq!(w.baseline_end, "2026-10-18T14:00:00Z");
        assert_eq!(w.selection_reason, "user_provided_range");
    }

    #[test]
    fn session_ids_come_from_ids_or_links() {
        assert_eq!(session_id("abc-123").unwrap(), "abc-123");
        assert_eq!(
            session_id("https://rush.example.com/sre-agent/abc-123?tenant=prod").unwrap(),
            "abc-123"
        );
        assert!(session_id("../etc").is_err());
    }
}
