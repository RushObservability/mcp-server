//! `analysis` toolset: cohort and window comparison, latency breakdown, and
//! single log records with their surrounding lines.

use std::collections::BTreeMap;

use rmcp::{
    RoleServer,
    handler::server::wrapper::{Json, Parameters},
    model::CallToolResult,
    service::RequestContext,
    tool, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::api::{
    BubbleUpRequest, BubbleUpResponse, ExploreRequest, LatencyHistogram, LogContextAnchor,
    LogContextRequest, LogContextResponse, LogRecord, LogRef, LogRow, SignalKind, TimeBreakdown,
    TimeRange, TimeseriesRequest, TimeseriesResponse, query_text,
};
use crate::client::ClientKey;
use crate::envelope::{Envelope, Hint, Trim, clip};
use crate::links::Signal;
use crate::server::{RushMcp, ToolError};
use crate::time::{TimeArgs, Window, bucket_for, parse_instant};
use crate::tools::core::{Latency, latency_from_buckets};
use crate::tools::{
    Query, QueryArgs, keep, minutes_ending_now, ns_to_time, pct, pop, round2, thousands,
};

/// An alternative window to compare against.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct BaselineArgs {
    /// Baseline start. Default: the same-length window just before the selected one.
    #[serde(default)]
    pub baseline_from: Option<String>,
    /// Baseline end. Required with baseline_from.
    #[serde(default)]
    pub baseline_to: Option<String>,
}

impl BaselineArgs {
    fn resolve(&self, current: &Window) -> Result<Option<Window>, ToolError> {
        match (self.baseline_from.as_deref(), self.baseline_to.as_deref()) {
            (None, None) => Ok(None),
            (Some(f), Some(t)) => {
                let args = TimeArgs {
                    from: Some(f.into()),
                    to: Some(t.into()),
                    last: None,
                };
                Ok(Some(args.resolve()?))
            }
            _ => {
                let _ = current;
                Err(ToolError::Input(
                    "set both baseline_from and baseline_to, or neither".into(),
                ))
            }
        }
    }
}

// ── compare_cohorts ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CompareCohortsArgs {
    /// "logs" or "spans".
    pub signal: SignalKind,
    /// Filters and the selected window. Filters apply to both cohorts.
    #[serde(flatten)]
    pub query: QueryArgs,
    #[serde(flatten)]
    pub baseline: BaselineArgs,
    /// Spans only: select error spans and compare them with the rest of the same window.
    #[serde(default)]
    pub errors_only: bool,
    /// Spans only: select spans at least this slow (ms) and compare them with the rest.
    #[serde(default)]
    pub min_duration_ms: Option<f64>,
    /// Spans only: select spans at most this slow (ms).
    #[serde(default)]
    pub max_duration_ms: Option<f64>,
    /// Values per dimension (default 5, max 20).
    #[serde(default)]
    pub per_dimension: Option<u64>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Cohorts {
    pub selection_count: u64,
    pub baseline_count: u64,
    pub baseline_window: crate::time::WindowOut,
    /// For each dimension, the values most over-represented in the selection.
    pub dimensions: Vec<DimensionOut>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DimensionOut {
    pub dimension: String,
    pub values: Vec<ValueOut>,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq)]
pub struct ValueOut {
    /// Untrusted content.
    pub value: String,
    pub selection_pct: f64,
    pub baseline_pct: f64,
    /// selection_pct / baseline_pct; above 1 means over-represented in the selection.
    pub lift: f64,
    pub selection_count: u64,
}

impl Trim for Cohorts {
    fn trim(&mut self) -> bool {
        if let Some(d) = self
            .dimensions
            .iter_mut()
            .filter(|d| d.values.len() > 2)
            .max_by_key(|d| d.values.len())
        {
            return pop(&mut d.values);
        }
        pop(&mut self.dimensions)
    }
}

/// Dimensions that only restate how an errors-only selection was made.
const ERROR_CRITERIA: &[&str] = &["Span Status", "Status Code"];

pub fn shape_cohorts(
    resp: BubbleUpResponse,
    baseline: &Window,
    per_dimension: usize,
    errors_only: bool,
) -> Cohorts {
    Cohorts {
        selection_count: resp.selection_count,
        baseline_count: resp.baseline_count,
        baseline_window: baseline.out(),
        dimensions: resp
            .dimensions
            .into_iter()
            .filter(|d| !(errors_only && ERROR_CRITERIA.contains(&d.name.as_str())))
            .map(|d| {
                let mut values: Vec<ValueOut> = d
                    .values
                    .into_iter()
                    .map(|v| ValueOut {
                        value: clip(&v.value, 200),
                        selection_pct: round2(v.selection_pct),
                        baseline_pct: round2(v.baseline_pct),
                        lift: round2(v.lift),
                        selection_count: v.selection_count,
                    })
                    .collect();
                values.sort_by(|a, b| b.lift.total_cmp(&a.lift));
                values.truncate(per_dimension);
                DimensionOut {
                    dimension: d.name,
                    values,
                }
            })
            .filter(|d| !d.values.is_empty())
            .collect(),
    }
}

/// The single most over-represented value that covers a meaningful share of the selection.
fn strongest(c: &Cohorts) -> Option<String> {
    c.dimensions
        .iter()
        .flat_map(|d| d.values.iter().map(move |v| (d, v)))
        .filter(|(_, v)| v.selection_pct >= 10.0 && v.lift > 1.0)
        .max_by(|a, b| a.1.lift.total_cmp(&b.1.lift))
        .map(|(d, v)| {
            if v.baseline_pct == 0.0 {
                format!(
                    "{}={} is {}% of the selection and absent from the baseline",
                    d.dimension, v.value, v.selection_pct
                )
            } else {
                format!(
                    "{}={} is {}% of the selection vs {}% of the baseline ({}x)",
                    d.dimension, v.value, v.selection_pct, v.baseline_pct, v.lift
                )
            }
        })
}

// ── compare_windows ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CompareWindowsArgs {
    /// Filters and the current window (for example last="1h", or from/to around an incident).
    #[serde(flatten)]
    pub query: QueryArgs,
    #[serde(flatten)]
    pub baseline: BaselineArgs,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct WindowComparison {
    pub current: WindowStats,
    pub baseline: WindowStats,
    pub change: Changes,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct WindowStats {
    pub window: crate::time::WindowOut,
    pub spans: u64,
    pub span_errors: u64,
    pub error_rate_pct: f64,
    pub latency_ms_approx: Latency,
    pub logs: u64,
    pub error_logs: u64,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq)]
pub struct Changes {
    /// Percent change in span count (rate-adjusted when windows differ in length).
    pub spans_pct: Option<f64>,
    /// Change in error rate, in percentage points.
    pub error_rate_points: f64,
    pub p95_pct: Option<f64>,
    pub logs_pct: Option<f64>,
    pub error_logs_pct: Option<f64>,
}

impl Trim for WindowComparison {
    fn trim(&mut self) -> bool {
        false
    }
}

fn pct_change(current: f64, baseline: f64) -> Option<f64> {
    (baseline > 0.0).then(|| round2((current - baseline) * 100.0 / baseline))
}

pub fn changes(current: &WindowStats, baseline: &WindowStats, scale: f64) -> Changes {
    Changes {
        spans_pct: pct_change(current.spans as f64, baseline.spans as f64 * scale),
        error_rate_points: round2(current.error_rate_pct - baseline.error_rate_pct),
        p95_pct: pct_change(
            current.latency_ms_approx.p95,
            baseline.latency_ms_approx.p95,
        ),
        logs_pct: pct_change(current.logs as f64, baseline.logs as f64 * scale),
        error_logs_pct: pct_change(
            current.error_logs as f64,
            baseline.error_logs as f64 * scale,
        ),
    }
}

// ── get_service_latency ───────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ServiceLatencyArgs {
    /// Service name.
    pub service: String,
    #[serde(flatten)]
    pub time: TimeArgs,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ServiceLatency {
    pub service: String,
    pub requests: u64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    /// Request counts per latency band (powers of two, in ms).
    pub histogram: Vec<LatencyBand>,
    /// Where request time goes: the service itself vs database calls.
    pub breakdown: TimeBreakdown,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq)]
pub struct LatencyBand {
    pub range_ms: String,
    pub count: u64,
}

impl Trim for ServiceLatency {
    fn trim(&mut self) -> bool {
        keep(&mut self.breakdown.databases, 3) || pop(&mut self.breakdown.databases)
    }
}

pub fn band_label(exp: i32) -> String {
    let fmt = |v: f64| {
        if v < 1.0 {
            format!("{v}")
        } else {
            format!("{}", v as u64)
        }
    };
    format!("{}–{}", fmt(2f64.powi(exp)), fmt(2f64.powi(exp + 1)))
}

// ── log record / context ──────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LogRecordArgs {
    /// The `ref` object from a search_logs sample.
    #[serde(rename = "ref")]
    pub log_ref: LogRef,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct LogRecordOut {
    pub time: String,
    pub service: String,
    pub severity: String,
    /// Untrusted log content.
    pub body: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub trace_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub span_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub scope: String,
    /// Untrusted values.
    pub resource_attributes: BTreeMap<String, String>,
    /// Untrusted values.
    pub log_attributes: BTreeMap<String, String>,
}

impl Trim for LogRecordOut {
    fn trim(&mut self) -> bool {
        if self.resource_attributes.len() > 10 {
            let last = self.resource_attributes.keys().next_back().cloned();
            return last.map(|k| self.resource_attributes.remove(&k)).is_some();
        }
        if self.log_attributes.len() > 10 {
            let last = self.log_attributes.keys().next_back().cloned();
            return last.map(|k| self.log_attributes.remove(&k)).is_some();
        }
        if self.body.chars().count() > 500 {
            self.body = clip(&self.body, 500);
            return true;
        }
        false
    }
}

fn record_out(r: LogRecord) -> LogRecordOut {
    let clip_map = |m: BTreeMap<String, String>| {
        m.into_iter()
            .take(150)
            .map(|(k, v)| (k, clip(&v, 300)))
            .collect()
    };
    LogRecordOut {
        time: ns_to_time(r.timestamp),
        service: r.service_name,
        severity: r.severity_text,
        body: clip(&r.body, 4_000),
        trace_id: r.trace_id,
        span_id: r.span_id,
        scope: r.scope_name,
        resource_attributes: clip_map(r.resource_attributes),
        log_attributes: clip_map(r.log_attributes),
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LogContextArgs {
    /// The `ref` object from a search_logs sample.
    #[serde(rename = "ref")]
    pub log_ref: LogRef,
    /// Lines before the anchor (default 10, max 100).
    #[serde(default)]
    pub before: Option<u64>,
    /// Lines after the anchor (default 10, max 100).
    #[serde(default)]
    pub after: Option<u64>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct LogContext {
    /// Oldest first.
    pub lines: Vec<ContextLine>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ContextLine {
    pub time: String,
    pub service: String,
    pub severity: String,
    /// Untrusted log content.
    pub body: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub anchor: bool,
}

impl Trim for LogContext {
    fn trim(&mut self) -> bool {
        if self.lines.len() <= 3 {
            return false;
        }
        // Drop from whichever end is farther from the anchor.
        let anchor = self
            .lines
            .iter()
            .position(|l| l.anchor)
            .unwrap_or(self.lines.len() / 2);
        if anchor >= self.lines.len() - 1 - anchor {
            self.lines.remove(0);
        } else {
            self.lines.pop();
        }
        true
    }
}

fn log_window(ts_ns: &str) -> Result<Window, ToolError> {
    let at = parse_instant(
        ts_ns
            .get(..ts_ns.len().saturating_sub(9))
            .filter(|s| !s.is_empty())
            .unwrap_or(ts_ns),
        chrono::Utc::now(),
    )
    .map_err(|_| ToolError::Input("ref.timestamp_ns is not a nanosecond timestamp".into()))?;
    Ok(Window {
        from: at - chrono::Duration::minutes(30),
        to: at + chrono::Duration::minutes(30),
        relative_minutes: None,
    })
}

// ── Tools ─────────────────────────────────────────────────────────────────

impl RushMcp {
    async fn window_stats(
        &self,
        key: Option<&ClientKey>,
        q: &Query,
        window: &Window,
    ) -> Result<WindowStats, ToolError> {
        let c = &self.state.client;
        let ts = TimeseriesRequest {
            time_range: TimeRange::from(window),
            filters: &q.filters,
            interval: bucket_for(window, 12),
            group_by: None,
            search: q.search.as_deref(),
        };
        let logs = ExploreRequest {
            signal: SignalKind::Logs,
            time_range: TimeRange::from(window),
            filters: &q.filters,
            search: q.search.as_deref(),
            limit: 1,
            interval: bucket_for(window, 12),
            group_by: None,
            include_rows: false,
            include_summary: true,
        };
        let (ts, logs) = tokio::join!(
            c.post::<_, TimeseriesResponse>(
                key,
                "compare_windows",
                "/api/v1/query/timeseries",
                &ts
            ),
            c.explore::<LogRow>(key, "compare_windows", &logs),
        );
        let buckets = ts?.buckets;
        let logs = logs?;
        let spans: u64 = buckets.iter().map(|b| b.count).sum();
        let span_errors: u64 = buckets.iter().map(|b| b.error_count).sum();
        Ok(WindowStats {
            window: window.out(),
            spans,
            span_errors,
            error_rate_pct: pct(span_errors, spans),
            latency_ms_approx: latency_from_buckets(&buckets),
            logs: logs.count.value,
            error_logs: logs
                .summary
                .facets
                .statuses
                .iter()
                .find(|k| k.key == "error")
                .map(|k| k.count)
                .unwrap_or(0),
        })
    }

    async fn log_detail(
        &self,
        key: Option<&ClientKey>,
        tool: &str,
        r: &LogRef,
    ) -> Result<LogRecord, ToolError> {
        self.state
            .client
            .post(key, tool, "/api/v1/logs/detail", r)
            .await
            .map_err(|e| {
                if e.is_not_found() {
                    ToolError::Input(
                        "that log line is no longer available (retention or a stale ref); search again for a fresh ref"
                            .into(),
                    )
                } else {
                    e.into()
                }
            })
    }
}

#[tool_router(router = analysis_router, vis = "pub(crate)")]
impl RushMcp {
    #[tool(
        description = "BubbleUp: find which attributes (service, operation, path, status, severity, namespace…) are over-represented in a selection compared with a baseline. Select by window (vs the previous window by default), or for spans by errors_only/min_duration_ms (vs the rest of the same window).",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn compare_cohorts(
        &self,
        Parameters(args): Parameters<CompareCohortsArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<Cohorts>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("compare_cohorts", async {
            let key = key.as_ref();
            let q = args.query.resolve()?;
            let cohort = args.errors_only || args.min_duration_ms.is_some() || args.max_duration_ms.is_some();
            if cohort && args.signal == SignalKind::Logs {
                return Err(ToolError::Input("errors_only and duration bounds apply to spans only; for logs, compare windows".into()));
            }
            let explicit = args.baseline.resolve(&q.window)?;
            let (baseline, exclude) = match (explicit, cohort) {
                (Some(b), _) => (b, false),
                (None, true) => (q.window, true),
                (None, false) => (q.window.previous(), false),
            };
            let to_ns = |v: Option<f64>| v.filter(|m| *m > 0.0).map(|m| (m * 1_000_000.0) as u64);
            let req = BubbleUpRequest {
                selection: TimeRange::from(&q.window),
                baseline: TimeRange::from(&baseline),
                signal: args.signal,
                filters: &q.filters,
                top_k: 10,
                selection_min_duration_ns: to_ns(args.min_duration_ms),
                selection_max_duration_ns: to_ns(args.max_duration_ms),
                selection_errors_only: args.errors_only,
                exclude_selection_from_baseline: exclude,
            };
            let resp: BubbleUpResponse = self.state.client.post(key, "compare_cohorts", "/api/v1/bubbleup", &req).await?;
            let result = shape_cohorts(resp, &baseline, args.per_dimension.unwrap_or(5).clamp(1, 20) as usize, args.errors_only);
            let summary = match strongest(&result) {
                Some(s) => format!("Strongest difference: {s}."),
                None => format!(
                    "No value stands out ({} selected vs {} baseline records).",
                    thousands(result.selection_count),
                    thousands(result.baseline_count)
                ),
            };
            let links = self.links(key).await;
            let signal = match args.signal {
                SignalKind::Logs => Signal::Logs,
                SignalKind::Spans => Signal::Spans,
            };
            let mut env = Envelope::new(summary, result)
                .window(&q.window)
                .link("explore", links.explore(signal, &query_text(&q.filters, q.search.as_deref()), &q.window, None));
            if env.result.selection_count == 0 {
                env = env.hint(Hint::new("The selection is empty.").action("Widen the window or relax the cohort settings"));
            }
            Ok(env)
        })
        .await
    }

    #[tool(
        description = "Compare a window with a baseline (the previous window of the same length by default): span volume, error rate, approximate p95, log volume and error-level logs, with percent changes.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn compare_windows(
        &self,
        Parameters(args): Parameters<CompareWindowsArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<WindowComparison>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("compare_windows", async {
            let key = key.as_ref();
            let q = args.query.resolve()?;
            let baseline = args
                .baseline
                .resolve(&q.window)?
                .unwrap_or_else(|| q.window.previous());
            let (cur, base) = tokio::join!(
                self.window_stats(key, &q, &q.window),
                self.window_stats(key, &q, &baseline)
            );
            let (cur, base) = (cur?, base?);
            let scale = q.window.duration().num_seconds() as f64
                / baseline.duration().num_seconds().max(1) as f64;
            let change = changes(&cur, &base, scale);
            let fmt = |v: Option<f64>| v.map(|p| format!("{p:+}%")).unwrap_or_else(|| "n/a".into());
            let summary = format!(
                "Spans {}, error rate {:+} pts ({}% vs {}%), p95 {}, error logs {}.",
                fmt(change.spans_pct),
                change.error_rate_points,
                cur.error_rate_pct,
                base.error_rate_pct,
                fmt(change.p95_pct),
                fmt(change.error_logs_pct)
            );
            Ok(Envelope::new(
                summary,
                WindowComparison {
                    current: cur,
                    baseline: base,
                    change,
                },
            )
            .window(&q.window))
        })
        .await
    }

    #[tool(
        description = "Latency distribution for one service (p50/p95/p99 and counts per latency band) and where request time goes: the service itself vs database calls, per database.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn get_service_latency(
        &self,
        Parameters(args): Parameters<ServiceLatencyArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<ServiceLatency>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("get_service_latency", async {
            let key = key.as_ref();
            let service = args.service.trim().to_string();
            if service.is_empty() {
                return Err(ToolError::Input("service is required".into()));
            }
            let window = args.time.resolve()?;
            let (minutes, note) = minutes_ending_now(&window);
            let params = [("service", service.clone()), ("minutes", minutes.to_string())];
            let c = &self.state.client;
            let (hist, breakdown) = tokio::join!(
                c.get::<LatencyHistogram>(key, "get_service_latency", "/api/v1/services/latency-histogram", &params),
                c.get::<TimeBreakdown>(key, "get_service_latency", "/api/v1/services/time-breakdown", &params),
            );
            let hist = hist?;
            let mut breakdown = breakdown.unwrap_or_default();
            breakdown.databases.sort_by(|a, b| b.total_ms.total_cmp(&a.total_ms));
            breakdown.databases.truncate(10);
            let result = ServiceLatency {
                service: service.clone(),
                requests: hist.total,
                p50_ms: round2(hist.p50_ms),
                p95_ms: round2(hist.p95_ms),
                p99_ms: round2(hist.p99_ms),
                histogram: hist.buckets.iter().filter(|b| b.count > 0).map(|b| LatencyBand { range_ms: band_label(b.exp), count: b.count }).collect(),
                breakdown,
            };
            let db_share = pct(result.breakdown.database_time_ms as u64, result.breakdown.wall_time_ms.max(1.0) as u64);
            let links = self.links(key).await;
            let mut env = Envelope::new(
                format!("{service}: p50 {} ms, p95 {} ms, p99 {} ms over {} requests; {}% of time in database calls.", result.p50_ms, result.p95_ms, result.p99_ms, thousands(result.requests), db_share),
                result,
            )
            .window(&window)
            .link("service", links.service(&service, &window));
            if let Some(n) = note {
                env = env.hint(Hint::new(n));
            }
            if env.result.requests == 0 {
                env = env.hint(Hint::new(format!("No requests for `{service}`.")).action("Check the name with list_services"));
            }
            Ok(env)
        })
        .await
    }

    #[tool(
        description = "Full detail of one log line (body plus resource and log attributes), from the `ref` in a search_logs sample.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn get_log_record(
        &self,
        Parameters(args): Parameters<LogRecordArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<LogRecordOut>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("get_log_record", async {
            let key = key.as_ref();
            let record = self
                .log_detail(key, "get_log_record", &args.log_ref)
                .await?;
            let out = record_out(record);
            let links = self.links(key).await;
            let mut env = Envelope::new(
                format!(
                    "{} {} log from {} at {}.",
                    out.severity,
                    if out.trace_id.is_empty() {
                        "untraced"
                    } else {
                        "traced"
                    },
                    out.service,
                    out.time
                ),
                out,
            );
            if !env.result.trace_id.is_empty() && env.result.trace_id.len() == 32 {
                let url = links.trace(
                    &env.result.trace_id,
                    (!env.result.span_id.is_empty()).then_some(env.result.span_id.as_str()),
                );
                env = env.link("trace", url);
            }
            Ok(env)
        })
        .await
    }

    #[tool(
        description = "Log lines written just before and after one log line, oldest first, with the original line marked. Takes the `ref` from a search_logs sample.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn get_log_context(
        &self,
        Parameters(args): Parameters<LogContextArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<LogContext>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("get_log_context", async {
            let key = key.as_ref();
            let r = &args.log_ref;
            // Rush matches the anchor on its exact body, which search samples clip.
            let record = self.log_detail(key, "get_log_context", r).await?;
            let window = log_window(&r.timestamp_ns)?;
            let req = LogContextRequest {
                time_range: TimeRange::from(&window),
                anchor: LogContextAnchor {
                    timestamp_ns: &r.timestamp_ns,
                    service_name: &record.service_name,
                    trace_id: &record.trace_id,
                    span_id: &record.span_id,
                    body: &record.body,
                },
                before: args.before.unwrap_or(10).clamp(1, 100),
                after: args.after.unwrap_or(10).clamp(1, 100),
            };
            let resp: LogContextResponse = self
                .state
                .client
                .post(key, "get_log_context", "/api/v1/logs/context", &req)
                .await?;
            let mut lines: Vec<ContextLine> = resp
                .rows
                .iter()
                .map(|row| ContextLine {
                    time: ns_to_time(row.timestamp),
                    service: row.service_name.clone(),
                    severity: row.severity_text.clone(),
                    body: clip(&row.body, 300),
                    anchor: row.body_hash == r.body_hash
                        && (row.timestamp_ns == r.timestamp_ns
                            || row.timestamp.to_string() == r.timestamp_ns),
                })
                .collect();
            lines.reverse();
            Ok(Envelope::new(
                format!(
                    "{} lines around the log at {}.",
                    lines.len(),
                    ns_to_time(record.timestamp)
                ),
                LogContext { lines },
            )
            .window(&window))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{Dimension, DimensionValue};

    #[test]
    fn cohorts_keep_the_highest_lift_values_per_dimension() {
        let v = |value: &str, sel: f64, base: f64, lift: f64| DimensionValue {
            value: value.into(),
            selection_pct: sel,
            baseline_pct: base,
            lift,
            selection_count: 1,
            baseline_count: 1,
        };
        let resp = BubbleUpResponse {
            selection_count: 100,
            baseline_count: 1000,
            dimensions: vec![
                Dimension {
                    name: "Service".into(),
                    values: vec![
                        v("auth", 5.0, 5.0, 1.0),
                        v("checkout", 85.0, 12.0, 7.08),
                        v("cart", 10.0, 83.0, 0.12),
                    ],
                },
                Dimension {
                    name: "Path".into(),
                    values: vec![],
                },
            ],
        };
        let base = TimeArgs::default().resolve().unwrap();
        let c = shape_cohorts(resp, &base, 2, false);
        assert_eq!(c.dimensions.len(), 1, "empty dimensions are dropped");
        assert_eq!(c.dimensions[0].values[0].value, "checkout");
        assert_eq!(c.dimensions[0].values.len(), 2);
        assert!(strongest(&c).unwrap().contains("Service=checkout"));

        // Errors-only selections don't report the error status as a finding.
        let status = BubbleUpResponse {
            dimensions: vec![
                Dimension {
                    name: "Span Status".into(),
                    values: vec![v("STATUS_CODE_ERROR", 90.0, 0.0, 9000.0)],
                },
                Dimension {
                    name: "Service".into(),
                    values: vec![v("db", 60.0, 0.0, 6000.0)],
                },
            ],
            ..Default::default()
        };
        let c = shape_cohorts(status, &base, 5, true);
        assert_eq!(c.dimensions.len(), 1);
        assert!(strongest(&c).unwrap().contains("absent from the baseline"));
    }

    #[test]
    fn window_changes_scale_for_unequal_windows() {
        let stats = |spans, err_rate: f64, p95, logs| WindowStats {
            window: TimeArgs::default().resolve().unwrap().out(),
            spans,
            span_errors: 0,
            error_rate_pct: err_rate,
            latency_ms_approx: Latency {
                p95,
                ..Default::default()
            },
            logs,
            error_logs: 0,
        };
        // Current is twice as long as the baseline, so baseline counts are doubled.
        let c = changes(
            &stats(200, 5.0, 150.0, 100),
            &stats(100, 1.0, 100.0, 50),
            2.0,
        );
        assert_eq!(c.spans_pct, Some(0.0));
        assert_eq!(c.error_rate_points, 4.0);
        assert_eq!(c.p95_pct, Some(50.0));
        assert_eq!(c.error_logs_pct, None, "no baseline to compare");
    }

    #[test]
    fn latency_bands_are_readable() {
        assert_eq!(band_label(3), "8–16");
        assert_eq!(band_label(-1), "0.5–1");
    }

    #[test]
    fn baseline_needs_both_ends() {
        let w = TimeArgs::default().resolve().unwrap();
        let half = BaselineArgs {
            baseline_from: Some("now-3h".into()),
            baseline_to: None,
        };
        assert!(half.resolve(&w).is_err());
        assert!(BaselineArgs::default().resolve(&w).unwrap().is_none());
    }

    #[test]
    fn context_trim_keeps_the_anchor_centered() {
        let line = |anchor| ContextLine {
            time: String::new(),
            service: String::new(),
            severity: String::new(),
            body: String::new(),
            anchor,
        };
        let mut ctx = LogContext {
            lines: vec![
                line(false),
                line(false),
                line(false),
                line(true),
                line(false),
            ],
        };
        assert!(ctx.trim());
        assert_eq!(ctx.lines.len(), 4);
        assert!(ctx.lines[2].anchor);
    }

    #[test]
    fn log_windows_center_on_the_line() {
        let w = log_window("1760796000123456789").unwrap();
        assert_eq!(w.duration(), chrono::Duration::hours(1));
        assert!(log_window("abc").is_err());
    }
}
