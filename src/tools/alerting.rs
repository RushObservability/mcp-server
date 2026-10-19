//! `alerting` toolset: monitors, SLOs and anomaly events.

use std::collections::{BTreeMap, HashSet};

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
    AnomalyEvent, AnomalyEventsResponse, AnomalyRule, AnomalyRuleResponse, Correlations, Monitor,
    MonitorDetailResponse, MonitorEvent, MonitorsResponse, PreviewRequest, PreviewResponse, Slo,
    SloDetailResponse, SlosResponse,
};
use crate::client::ApiError;
use crate::envelope::{Envelope, Hint, Trim, clip};
use crate::links::id_from;
use crate::server::{RushMcp, ToolError};
use crate::time::parse_duration;
use crate::tools::{keep, pop, round2};

fn severity_rank(state: &str, enabled: bool) -> u8 {
    if !enabled {
        return 4;
    }
    match state {
        "alert" => 0,
        "warn" => 1,
        "no_data" => 2,
        _ => 3,
    }
}

fn opt_time(t: &Option<String>) -> Option<String> {
    t.as_ref().filter(|s| !s.is_empty()).cloned()
}

fn string_list(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

// ── Monitors ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MonitorStateFilter {
    Alert,
    Warn,
    NoData,
    Ok,
    Muted,
    /// alert, warn or no_data.
    Problem,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListMonitorsArgs {
    /// Only monitors in this state.
    #[serde(default)]
    pub state: Option<MonitorStateFilter>,
    /// Only monitors whose name or tags contain this text.
    #[serde(default)]
    pub contains: Option<String>,
    /// How many to return, worst state first (default 25, max 200).
    #[serde(default)]
    pub limit: Option<u64>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct MonitorList {
    /// Monitor counts per state across all monitors ("muted" counts disabled monitors).
    pub by_state: BTreeMap<String, usize>,
    pub monitors: Vec<MonitorBrief>,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq)]
pub struct MonitorBrief {
    pub id: String,
    pub name: String,
    /// metric, log, apm or composite.
    #[serde(rename = "type")]
    pub monitor_type: String,
    /// ok, warn, alert or no_data (worst across groups).
    pub state: String,
    pub muted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Groups currently in warn or alert (at most 5).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub problem_groups: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_triggered_at: Option<String>,
}

impl Trim for MonitorList {
    fn trim(&mut self) -> bool {
        let n = self.monitors.len();
        n > 5 && keep(&mut self.monitors, n * 2 / 3)
    }
}

fn problem_groups(m: &Monitor) -> Vec<String> {
    let mut groups: Vec<String> = m
        .group_states
        .as_object()
        .map(|o| {
            o.iter()
                .filter(|(_, v)| matches!(v.as_str(), Some("alert" | "warn")))
                .map(|(k, v)| format!("{k} ({})", v.as_str().unwrap_or_default()))
                .collect()
        })
        .unwrap_or_default();
    groups.sort();
    groups.truncate(5);
    groups
}

pub fn brief(m: &Monitor) -> MonitorBrief {
    MonitorBrief {
        id: m.id.clone(),
        name: m.name.clone(),
        monitor_type: m.monitor_type.clone(),
        state: m.state.clone(),
        muted: !m.enabled,
        priority: m.priority,
        tags: string_list(&m.tags),
        problem_groups: problem_groups(m),
        last_triggered_at: opt_time(&m.last_triggered_at),
    }
}

fn matches_state(m: &Monitor, f: MonitorStateFilter) -> bool {
    match f {
        MonitorStateFilter::Muted => !m.enabled,
        MonitorStateFilter::Problem => {
            m.enabled && matches!(m.state.as_str(), "alert" | "warn" | "no_data")
        }
        MonitorStateFilter::Alert => m.enabled && m.state == "alert",
        MonitorStateFilter::Warn => m.enabled && m.state == "warn",
        MonitorStateFilter::NoData => m.enabled && m.state == "no_data",
        MonitorStateFilter::Ok => m.enabled && m.state == "ok",
    }
}

pub fn shape_monitor_list(mut monitors: Vec<Monitor>, args: &ListMonitorsArgs) -> MonitorList {
    let mut by_state = BTreeMap::new();
    for m in &monitors {
        let key = if m.enabled {
            m.state.clone()
        } else {
            "muted".to_string()
        };
        *by_state.entry(key).or_insert(0) += 1;
    }
    let needle = args
        .contains
        .as_deref()
        .map(|c| c.trim().to_lowercase())
        .filter(|c| !c.is_empty());
    monitors.retain(|m| {
        args.state.is_none_or(|s| matches_state(m, s))
            && needle.as_ref().is_none_or(|n| {
                m.name.to_lowercase().contains(n)
                    || string_list(&m.tags)
                        .iter()
                        .any(|t| t.to_lowercase().contains(n))
            })
    });
    monitors.sort_by(|a, b| {
        severity_rank(&a.state, a.enabled)
            .cmp(&severity_rank(&b.state, b.enabled))
            .then(a.priority.unwrap_or(9).cmp(&b.priority.unwrap_or(9)))
            .then(a.name.cmp(&b.name))
    });
    monitors.truncate(args.limit.unwrap_or(25).clamp(1, 200) as usize);
    MonitorList {
        by_state,
        monitors: monitors.iter().map(brief).collect(),
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetMonitorArgs {
    /// Monitor ID or a Rush monitor link (/alerts/<id>).
    pub monitor: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct MonitorDetail {
    #[serde(flatten)]
    pub monitor: MonitorBrief,
    /// Query definition (shape depends on the type).
    pub query: serde_json::Value,
    pub thresholds: Thresholds,
    pub eval_window_secs: i64,
    pub eval_interval_secs: i64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub group_by: Vec<String>,
    /// Non-ok groups first (at most 20).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub group_states: BTreeMap<String, String>,
    pub no_data_action: String,
    /// Notification message template.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_eval_at: Option<String>,
    /// Recent state changes, newest first.
    pub recent_events: Vec<MonitorEventOut>,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq)]
pub struct Thresholds {
    /// above, above_or_equal, equal, below_or_equal or below.
    pub comparator: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub critical: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub critical_recovery: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning_recovery: Option<f64>,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq)]
pub struct MonitorEventOut {
    pub time: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub group: String,
    pub from: String,
    pub to: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,
}

impl Trim for MonitorDetail {
    fn trim(&mut self) -> bool {
        keep(&mut self.recent_events, 5)
            || {
                if self.group_states.len() > 5 {
                    let last = self.group_states.keys().next_back().cloned();
                    last.map(|k| self.group_states.remove(&k)).is_some()
                } else {
                    false
                }
            }
            || pop(&mut self.recent_events)
    }
}

fn event_out(e: &MonitorEvent) -> MonitorEventOut {
    MonitorEventOut {
        time: e.created_at.clone(),
        group: e.group_key.clone(),
        from: e.prev_state.clone(),
        to: e.new_state.clone(),
        value: e.value.map(round2),
        threshold: e.threshold,
    }
}

pub fn shape_monitor(m: &Monitor, events: &[MonitorEvent]) -> MonitorDetail {
    let mut states: Vec<(String, String)> = m
        .group_states
        .as_object()
        .map(|o| {
            o.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                .collect()
        })
        .unwrap_or_default();
    states.sort_by_key(|(k, v)| (severity_rank(v, true), k.clone()));
    MonitorDetail {
        monitor: brief(m),
        query: m.query_config.clone(),
        thresholds: Thresholds {
            comparator: m.comparator.clone(),
            critical: m.critical,
            critical_recovery: m.critical_recovery,
            warning: m.warning,
            warning_recovery: m.warning_recovery,
        },
        eval_window_secs: m.eval_window_secs,
        eval_interval_secs: m.eval_interval_secs,
        group_by: string_list(&m.group_by),
        group_states: states.into_iter().take(20).collect(),
        no_data_action: m.no_data_action.clone(),
        message: clip(&m.message, 500),
        last_eval_at: opt_time(&m.last_eval_at),
        recent_events: events.iter().take(20).map(event_out).collect(),
    }
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MonitorType {
    Metric,
    Log,
    Apm,
}

impl MonitorType {
    fn as_str(self) -> &'static str {
        match self {
            MonitorType::Metric => "metric",
            MonitorType::Log => "log",
            MonitorType::Apm => "apm",
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PreviewMonitorArgs {
    /// metric, log or apm.
    #[serde(rename = "type")]
    pub monitor_type: MonitorType,
    /// metric: {"type":"promql","expr":"<PromQL>"} or {"metric_name","aggregation":"avg|sum|max|min|count","filters":[{"key","value"}]}.
    /// log: any of {"search","service","severities":["ERROR"],"filters":[{"field","op","value"}]}.
    /// apm: {"service","metric":"error_rate|error_count|request_rate|p50|p95|p99","endpoint_filter"}.
    pub query_config: serde_json::Value,
    /// Critical threshold.
    #[serde(default)]
    pub critical: Option<f64>,
    #[serde(default)]
    pub warning: Option<f64>,
    #[serde(default)]
    pub critical_recovery: Option<f64>,
    #[serde(default)]
    pub warning_recovery: Option<f64>,
    /// above (default), above_or_equal, equal, below_or_equal or below.
    #[serde(default)]
    pub comparator: Option<String>,
    /// Evaluation window, e.g. "5m" (default; 1m to 7d).
    #[serde(default)]
    pub eval_window: Option<String>,
    /// How far back to simulate, e.g. "3h" (default; 5m to 7d).
    #[serde(default)]
    pub lookback: Option<String>,
    /// Fields to evaluate separately (at most 5).
    #[serde(default)]
    pub group_by: Vec<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct MonitorPreview {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_value: Option<f64>,
    /// Latest value per group, highest first.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<GroupValue>,
    /// Per group: min, max and last over the lookback.
    pub series: Vec<SeriesRange>,
    /// State changes the monitor would have made over the lookback, oldest first.
    pub would_have_fired: Vec<SimulatedOut>,
    pub bucket_secs: i64,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq)]
pub struct GroupValue {
    pub group: String,
    pub value: f64,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq)]
pub struct SeriesRange {
    pub group: String,
    pub min: f64,
    pub max: f64,
    pub last: f64,
    pub points: usize,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq)]
pub struct SimulatedOut {
    pub time: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub group: String,
    pub from: String,
    pub to: String,
    pub value: f64,
}

impl Trim for MonitorPreview {
    fn trim(&mut self) -> bool {
        keep(&mut self.groups, 5) || keep(&mut self.series, 5) || {
            let n = self.would_have_fired.len();
            n > 5 && keep(&mut self.would_have_fired, n / 2)
        }
    }
}

pub fn shape_preview(p: PreviewResponse) -> MonitorPreview {
    let mut groups: Vec<GroupValue> = p
        .groups
        .into_iter()
        .map(|(group, value)| GroupValue {
            group,
            value: round2(value),
        })
        .collect();
    groups.sort_by(|a, b| b.value.total_cmp(&a.value));
    groups.truncate(20);
    MonitorPreview {
        current_value: p.current_value.map(round2),
        groups,
        series: p
            .series
            .iter()
            .filter(|s| !s.points.is_empty())
            .take(20)
            .map(|s| {
                let vals: Vec<f64> = s.points.iter().map(|p| p.value).collect();
                SeriesRange {
                    group: s.group_key.clone(),
                    min: round2(vals.iter().copied().fold(f64::INFINITY, f64::min)),
                    max: round2(vals.iter().copied().fold(f64::NEG_INFINITY, f64::max)),
                    last: round2(*vals.last().unwrap_or(&0.0)),
                    points: vals.len(),
                }
            })
            .collect(),
        would_have_fired: p
            .simulated_events
            .iter()
            .take(100)
            .map(|e| SimulatedOut {
                time: e.timestamp.clone(),
                group: e.group_key.clone(),
                from: e.previous_state.clone(),
                to: e.state.clone(),
                value: round2(e.value),
            })
            .collect(),
        bucket_secs: p.bucket_secs,
    }
}

fn secs(
    raw: Option<&str>,
    default: &str,
    min: i64,
    max: i64,
    name: &str,
) -> Result<i64, ToolError> {
    let d = parse_duration(
        raw.map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(default),
    )
    .map_err(ToolError::Input)?;
    let s = d.num_seconds();
    if !(min..=max).contains(&s) {
        return Err(ToolError::Input(format!(
            "{name} must be between {min}s and {max}s"
        )));
    }
    Ok(s)
}

// ── SLOs ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListSlosArgs {
    /// Only SLOs in this state: compliant, breaching or no_data.
    #[serde(default)]
    pub state: Option<String>,
    /// Only SLOs whose name or service contains this text.
    #[serde(default)]
    pub contains: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SloList {
    pub by_state: BTreeMap<String, usize>,
    /// Breaching first, then least budget left.
    pub slos: Vec<SloBrief>,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq)]
pub struct SloBrief {
    pub id: String,
    pub name: String,
    /// compliant, breaching or no_data.
    pub state: String,
    pub enabled: bool,
    /// availability, latency or threshold, measured from traces or metrics.
    pub indicator: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub service: String,
    /// rolling_1h, rolling_24h, rolling_7d or rolling_30d.
    pub window: String,
    pub target_pct: f64,
    /// Measured success rate: 100 × (1 − errors / total).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sli_pct: Option<f64>,
    /// Error budget left: 100 is untouched, 0 or less is exhausted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_remaining_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_threshold_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_breached_at: Option<String>,
}

impl Trim for SloList {
    fn trim(&mut self) -> bool {
        let n = self.slos.len();
        n > 5 && keep(&mut self.slos, n * 2 / 3)
    }
}

pub fn slo_brief(s: &Slo) -> SloBrief {
    let sli = match (s.error_count, s.total_count) {
        (Some(e), Some(t)) if t > 0.0 => Some(round2(100.0 * (1.0 - e / t))),
        _ => None,
    };
    SloBrief {
        id: s.id.clone(),
        name: s.name.clone(),
        state: s.state.clone(),
        enabled: s.enabled,
        indicator: format!(
            "{} ({})",
            s.indicator_type,
            if s.slo_type.is_empty() {
                "trace"
            } else {
                &s.slo_type
            }
        ),
        service: s.service_name.clone(),
        window: s.window_type.clone(),
        target_pct: s.target_percentage,
        sli_pct: sli,
        budget_remaining_pct: s.error_budget_remaining.map(|b| round2(b * 100.0)),
        latency_threshold_ms: s.threshold_ms,
        last_breached_at: opt_time(&s.last_breached_at),
    }
}

pub fn shape_slo_list(slos: &[Slo], state: Option<&str>, contains: Option<&str>) -> SloList {
    let mut by_state = BTreeMap::new();
    for s in slos {
        *by_state.entry(s.state.clone()).or_insert(0) += 1;
    }
    let needle = contains
        .map(|c| c.trim().to_lowercase())
        .filter(|c| !c.is_empty());
    let mut list: Vec<SloBrief> = slos
        .iter()
        .filter(|s| state.is_none_or(|st| s.state.eq_ignore_ascii_case(st.trim())))
        .filter(|s| {
            needle.as_ref().is_none_or(|n| {
                s.name.to_lowercase().contains(n) || s.service_name.to_lowercase().contains(n)
            })
        })
        .map(slo_brief)
        .collect();
    list.sort_by(|a, b| {
        (a.state != "breaching")
            .cmp(&(b.state != "breaching"))
            .then(
                a.budget_remaining_pct
                    .unwrap_or(f64::MAX)
                    .total_cmp(&b.budget_remaining_pct.unwrap_or(f64::MAX)),
            )
    });
    SloList {
        by_state,
        slos: list,
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetSloArgs {
    /// SLO ID or a Rush SLO link (/slos/<id>).
    pub slo: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SloDetail {
    #[serde(flatten)]
    pub slo: SloBrief,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<f64>,
    /// State changes, newest first.
    pub recent_events: Vec<SloEventOut>,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq)]
pub struct SloEventOut {
    pub time: String,
    pub state: String,
    pub budget_remaining_pct: f64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub message: String,
}

impl Trim for SloDetail {
    fn trim(&mut self) -> bool {
        keep(&mut self.recent_events, 5) || pop(&mut self.recent_events)
    }
}

// ── Anomalies ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListAnomaliesArgs {
    /// Include resolved anomalies and every recent state change (default: only open anomalies).
    #[serde(default)]
    pub include_resolved: bool,
    /// Only rules whose name or metric contains this text.
    #[serde(default)]
    pub contains: Option<String>,
    /// How many to return (default 20, max 100).
    #[serde(default)]
    pub limit: Option<u64>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct AnomalyList {
    /// Rules whose latest event is anomalous.
    pub open: usize,
    pub anomalies: Vec<AnomalyOut>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
pub struct AnomalyOut {
    /// Pass to get_anomaly.
    pub event_id: String,
    pub rule_id: String,
    pub rule: String,
    /// anomalous or normal.
    pub state: String,
    pub metric: String,
    pub value: f64,
    pub expected: f64,
    /// Distance from the expected value, in standard deviations.
    pub deviation_sigma: f64,
    pub time: String,
}

impl Trim for AnomalyList {
    fn trim(&mut self) -> bool {
        let n = self.anomalies.len();
        n > 5 && keep(&mut self.anomalies, n * 2 / 3)
    }
}

fn anomaly_out(e: &AnomalyEvent) -> AnomalyOut {
    AnomalyOut {
        event_id: e.id.clone(),
        rule_id: e.rule_id.clone(),
        rule: e.rule_name.clone(),
        state: e.state.clone(),
        metric: clip(&e.metric, 200),
        value: round2(e.value),
        expected: round2(e.expected),
        deviation_sigma: round2(e.deviation),
        time: e.created_at.clone(),
    }
}

/// Events arrive newest first. A rule is open when its newest event is anomalous.
pub fn shape_anomalies(events: &[AnomalyEvent], args: &ListAnomaliesArgs) -> AnomalyList {
    let needle = args
        .contains
        .as_deref()
        .map(|c| c.trim().to_lowercase())
        .filter(|c| !c.is_empty());
    let mut seen = HashSet::new();
    let latest: Vec<&AnomalyEvent> = events
        .iter()
        .filter(|e| seen.insert(e.rule_id.clone()))
        .collect();
    let open = latest.iter().filter(|e| e.state == "anomalous").count();
    let wanted = |e: &&AnomalyEvent| {
        needle.as_ref().is_none_or(|n| {
            e.rule_name.to_lowercase().contains(n) || e.metric.to_lowercase().contains(n)
        })
    };
    let limit = args.limit.unwrap_or(20).clamp(1, 100) as usize;
    let anomalies = if args.include_resolved {
        events
            .iter()
            .filter(wanted)
            .take(limit)
            .map(anomaly_out)
            .collect()
    } else {
        latest
            .into_iter()
            .filter(|e| e.state == "anomalous")
            .filter(wanted)
            .take(limit)
            .map(anomaly_out)
            .collect()
    };
    AnomalyList { open, anomalies }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetAnomalyArgs {
    /// Anomaly event ID (from list_anomalies).
    pub event_id: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct AnomalyDetail {
    #[serde(flatten)]
    pub event: AnomalyOut,
    /// Untrusted content.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<AnomalyRule>,
    /// For HTTP status anomalies: the services emitting that status and sample logs around the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlations: Option<CorrelationOut>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CorrelationOut {
    pub status_code: u16,
    pub services: Vec<crate::api::KeyCount>,
    pub logs: Vec<CorrelatedLogOut>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CorrelatedLogOut {
    pub time: String,
    pub service: String,
    pub severity: String,
    /// Untrusted log content.
    pub body: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub trace_id: String,
}

impl Trim for AnomalyDetail {
    fn trim(&mut self) -> bool {
        match &mut self.correlations {
            Some(c) if c.logs.len() > 3 => pop(&mut c.logs),
            Some(c) => keep(&mut c.services, 3),
            None => false,
        }
    }
}

fn correlations_out(c: Correlations) -> Option<CorrelationOut> {
    (c.status_code != 0).then(|| CorrelationOut {
        status_code: c.status_code,
        services: c
            .services
            .into_iter()
            .take(10)
            .map(|s| crate::api::KeyCount {
                key: s.name,
                count: s.total,
            })
            .collect(),
        logs: c
            .logs
            .into_iter()
            .take(10)
            .map(|l| CorrelatedLogOut {
                time: l.timestamp,
                service: l.service_name,
                severity: l.severity_text,
                body: clip(&l.body, 300),
                trace_id: l.trace_id,
            })
            .collect(),
    })
}

// ── Tools ─────────────────────────────────────────────────────────────────

fn needs_id(raw: &str, segment: &str, what: &str) -> Result<String, ToolError> {
    id_from(raw, segment).ok_or_else(|| {
        ToolError::Input(format!("`{raw}` is not a {what} ID or a Rush {what} link"))
    })
}

#[tool_router(router = alerting_router, vis = "pub(crate)")]
impl RushMcp {
    #[tool(
        description = "List monitors with their state (alert, warn, no_data, ok) and whether they are muted, worst first, with counts per state. Filter by state or text.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn list_monitors(
        &self,
        Parameters(args): Parameters<ListMonitorsArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<MonitorList>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("list_monitors", async {
            let key = key.as_ref();
            let resp: MonitorsResponse = self
                .state
                .client
                .get(key, "list_monitors", "/api/v1/monitors", &[])
                .await?;
            let result = shape_monitor_list(resp.monitors, &args);
            let counts = |s: &str| result.by_state.get(s).copied().unwrap_or(0);
            let summary = format!(
                "{} monitors: {} alert, {} warn, {} no data, {} muted.",
                result.by_state.values().sum::<usize>(),
                counts("alert"),
                counts("warn"),
                counts("no_data"),
                counts("muted")
            );
            let links = self.links(key).await;
            Ok(Envelope::new(summary, result).link("monitors", links.monitors()))
        })
        .await
    }

    #[tool(
        description = "One monitor in full: query, thresholds, evaluation settings, state per group, notification message and recent state changes. Takes a monitor ID or Rush link.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn get_monitor(
        &self,
        Parameters(args): Parameters<GetMonitorArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<MonitorDetail>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("get_monitor", async {
            let key = key.as_ref();
            let id = needs_id(&args.monitor, "alerts", "monitor")?;
            let resp: MonitorDetailResponse = self
                .state
                .client
                .get(key, "get_monitor", &format!("/api/v1/monitors/{id}"), &[])
                .await?;
            let result = shape_monitor(&resp.monitor, &resp.events);
            let m = &result.monitor;
            let summary = format!(
                "{} ({} monitor) is {}{}; {} recent state changes.",
                m.name,
                m.monitor_type,
                m.state,
                if m.muted { ", muted" } else { "" },
                result.recent_events.len()
            );
            let never = result.last_eval_at.is_none();
            let links = self.links(key).await;
            let mut env = Envelope::new(summary, result).link("monitor", links.monitor(&id));
            if never {
                env = env.hint(Hint::new("This monitor hasn't been evaluated yet."));
            }
            Ok(env)
        })
        .await
    }

    #[tool(
        description = "Simulate a proposed monitor over recent data without saving it: current value per group, value ranges, and the alerts it would have raised. Rush requires a write-role API key for previews.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn preview_monitor(
        &self,
        Parameters(args): Parameters<PreviewMonitorArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<MonitorPreview>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("preview_monitor", async {
            if !args.query_config.is_object() {
                return Err(ToolError::Input("query_config must be a JSON object".into()));
            }
            if args.group_by.len() > 5 {
                return Err(ToolError::Input("group_by allows at most 5 fields".into()));
            }
            let comparator = args.comparator.as_deref().map(str::trim).filter(|c| !c.is_empty()).unwrap_or("above");
            if !matches!(comparator, "above" | "above_or_equal" | "equal" | "below_or_equal" | "below") {
                return Err(ToolError::Input("comparator must be above, above_or_equal, equal, below_or_equal or below".into()));
            }
            let req = PreviewRequest {
                monitor_type: args.monitor_type.as_str(),
                query_config: &args.query_config,
                eval_window_secs: secs(args.eval_window.as_deref(), "5m", 60, 604_800, "eval_window")?,
                lookback_secs: secs(args.lookback.as_deref(), "3h", 300, 604_800, "lookback")?,
                group_by: &args.group_by,
                critical: args.critical,
                critical_recovery: args.critical_recovery,
                warning: args.warning,
                warning_recovery: args.warning_recovery,
                comparator,
            };
            let resp: PreviewResponse = self.state.client.post(key.as_ref(), "preview_monitor", "/api/v1/monitors/preview", &req).await.map_err(|e| match e {
                ApiError::Forbidden(_) => ToolError::Input("monitor previews need a write-role Rush API key; this key is read-only".into()),
                other => other.into(),
            })?;
            let result = shape_preview(resp);
            let fired = result.would_have_fired.iter().filter(|e| e.to == "alert").count();
            let summary = format!(
                "Current value {}; it would have alerted {fired} times over the lookback ({} state changes).",
                result.current_value.map(|v| v.to_string()).unwrap_or_else(|| "n/a".into()),
                result.would_have_fired.len()
            );
            let mut env = Envelope::new(summary, result);
            if env.result.series.is_empty() {
                env = env.hint(Hint::new("The query returned no data over the lookback.").action("Check the query with query_metrics, search_logs or search_spans first"));
            }
            Ok(env)
        })
        .await
    }

    #[tool(
        description = "List SLOs with state, target, measured success rate and error budget left, breaching and lowest-budget first.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn list_slos(
        &self,
        Parameters(args): Parameters<ListSlosArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<SloList>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("list_slos", async {
            let key = key.as_ref();
            let resp: SlosResponse = self
                .state
                .client
                .get(key, "list_slos", "/api/v1/slos", &[])
                .await?;
            let result =
                shape_slo_list(&resp.slos, args.state.as_deref(), args.contains.as_deref());
            let breaching = result.by_state.get("breaching").copied().unwrap_or(0);
            let worst = result
                .slos
                .first()
                .and_then(|s| {
                    s.budget_remaining_pct
                        .map(|b| format!("; least budget left: {} ({b}%)", s.name))
                })
                .unwrap_or_default();
            let links = self.links(key).await;
            Ok(Envelope::new(
                format!("{} SLOs, {breaching} breaching{worst}.", resp.slos.len()),
                result,
            )
            .link("slos", links.slos()))
        })
        .await
    }

    #[tool(
        description = "One SLO in full: target, measured success rate, error and total counts, error budget left, and recent state changes. Takes an SLO ID or Rush link.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn get_slo(
        &self,
        Parameters(args): Parameters<GetSloArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<SloDetail>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("get_slo", async {
            let key = key.as_ref();
            let id = needs_id(&args.slo, "slos", "SLO")?;
            let resp: SloDetailResponse = self
                .state
                .client
                .get(key, "get_slo", &format!("/api/v1/slos/{id}"), &[])
                .await?;
            let s = &resp.slo;
            let result = SloDetail {
                slo: slo_brief(s),
                description: clip(&s.description, 500),
                errors: s.error_count,
                total: s.total_count,
                recent_events: resp
                    .events
                    .iter()
                    .take(20)
                    .map(|e| SloEventOut {
                        time: e.created_at.clone(),
                        state: e.state.clone(),
                        budget_remaining_pct: round2(e.error_budget_remaining * 100.0),
                        message: clip(&e.message, 200),
                    })
                    .collect(),
            };
            let b = &result.slo;
            let summary = format!(
                "{} is {}: target {}%, measured {}, {} of the error budget left.",
                b.name,
                b.state,
                b.target_pct,
                b.sli_pct
                    .map(|v| format!("{v}%"))
                    .unwrap_or_else(|| "n/a".into()),
                b.budget_remaining_pct
                    .map(|v| format!("{v}%"))
                    .unwrap_or_else(|| "n/a".into())
            );
            let links = self.links(key).await;
            Ok(Envelope::new(summary, result).link("slo", links.slo(&id)))
        })
        .await
    }

    #[tool(
        description = "List anomaly detections. By default returns rules that are currently anomalous, with value, expected value and deviation in standard deviations; set include_resolved for recent history.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn list_anomalies(
        &self,
        Parameters(args): Parameters<ListAnomaliesArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<AnomalyList>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("list_anomalies", async {
            let key = key.as_ref();
            let resp: AnomalyEventsResponse = self
                .state
                .client
                .get(key, "list_anomalies", "/api/v1/anomaly-events", &[])
                .await?;
            let result = shape_anomalies(&resp.events, &args);
            let summary = match result.anomalies.first().filter(|_| !args.include_resolved) {
                Some(top) => format!(
                    "{} open anomalies; e.g. {} at {}σ.",
                    result.open, top.rule, top.deviation_sigma
                ),
                None if args.include_resolved => format!(
                    "{} recent anomaly events; {} rules currently anomalous.",
                    result.anomalies.len(),
                    result.open
                ),
                None => "No open anomalies.".to_string(),
            };
            let links = self.links(key).await;
            Ok(Envelope::new(summary, result).link("anomalies", links.anomalies()))
        })
        .await
    }

    #[tool(
        description = "One anomaly event with its detection rule and, for HTTP status anomalies, the services emitting that status and sample logs around the time.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn get_anomaly(
        &self,
        Parameters(args): Parameters<GetAnomalyArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<AnomalyDetail>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("get_anomaly", async {
            let key = key.as_ref();
            let id = needs_id(&args.event_id, "anomaly-events", "anomaly event")?;
            let c = &self.state.client;
            let event: AnomalyEvent = c
                .get(
                    key,
                    "get_anomaly",
                    &format!("/api/v1/anomaly-events/{id}"),
                    &[],
                )
                .await?;
            let rule_path = format!("/api/v1/anomaly-rules/{}", event.rule_id);
            let corr_path = format!("/api/v1/anomaly-events/{id}/correlations");
            let (rule, corr) = tokio::join!(
                c.get::<AnomalyRuleResponse>(key, "get_anomaly", &rule_path, &[]),
                c.get::<Correlations>(key, "get_anomaly", &corr_path, &[]),
            );
            let rule = rule.ok().map(|r| r.rule);
            let mut out = anomaly_out(&event);
            if let Some(r) = &rule {
                out.rule = r.name.clone();
            }
            let result = AnomalyDetail {
                event: out,
                message: clip(&event.message, 500),
                rule,
                correlations: corr.ok().and_then(correlations_out),
            };
            let e = &result.event;
            let summary = format!(
                "{} ({}): value {} vs expected {} ({}σ) at {}.",
                e.rule, e.state, e.value, e.expected, e.deviation_sigma, e.time
            );
            let links = self.links(key).await;
            Ok(Envelope::new(summary, result)
                .link("anomaly_rule", links.anomaly_rule(&event.rule_id)))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn monitor(id: &str, state: &str, enabled: bool, priority: Option<i64>) -> Monitor {
        Monitor {
            id: id.into(),
            name: format!("m-{id}"),
            monitor_type: "apm".into(),
            state: state.into(),
            enabled,
            priority,
            group_states: serde_json::json!({"svc=a": "alert", "svc=b": "ok"}),
            tags: serde_json::json!(["team:pay"]),
            last_triggered_at: Some(String::new()),
            ..Default::default()
        }
    }

    #[test]
    fn monitors_sort_worst_first_and_muted_last() {
        let args = ListMonitorsArgs {
            state: None,
            contains: None,
            limit: None,
        };
        let list = shape_monitor_list(
            vec![
                monitor("ok", "ok", true, None),
                monitor("muted", "alert", false, None),
                monitor("warn", "warn", true, None),
                monitor("alert", "alert", true, Some(1)),
            ],
            &args,
        );
        assert_eq!(
            list.monitors
                .iter()
                .map(|m| m.id.as_str())
                .collect::<Vec<_>>(),
            ["alert", "warn", "ok", "muted"]
        );
        assert_eq!(list.by_state.get("muted"), Some(&1));
        assert_eq!(list.monitors[0].problem_groups, vec!["svc=a (alert)"]);
        assert_eq!(
            list.monitors[0].last_triggered_at, None,
            "empty timestamps become None"
        );
    }

    #[test]
    fn monitor_filters_by_state_and_tag() {
        let ms = vec![
            monitor("a", "alert", true, None),
            monitor("b", "ok", true, None),
            monitor("c", "warn", false, None),
        ];
        let problem = shape_monitor_list(
            ms.clone(),
            &ListMonitorsArgs {
                state: Some(MonitorStateFilter::Problem),
                contains: None,
                limit: None,
            },
        );
        assert_eq!(problem.monitors.len(), 1, "muted monitors are not problems");
        let tag = shape_monitor_list(
            ms,
            &ListMonitorsArgs {
                state: None,
                contains: Some("TEAM:PAY".into()),
                limit: Some(2),
            },
        );
        assert_eq!(tag.monitors.len(), 2);
    }

    #[test]
    fn slo_sli_and_budget_are_percentages() {
        let s = Slo {
            id: "s".into(),
            name: "checkout".into(),
            state: "breaching".into(),
            target_percentage: 99.9,
            error_count: Some(30.0),
            total_count: Some(10_000.0),
            error_budget_remaining: Some(-2.7),
            indicator_type: "availability".into(),
            ..Default::default()
        };
        let b = slo_brief(&s);
        assert_eq!(b.sli_pct, Some(99.7));
        assert_eq!(b.budget_remaining_pct, Some(-270.0));
        assert_eq!(b.indicator, "availability (trace)");
        let list = shape_slo_list(
            &[
                Slo {
                    state: "compliant".into(),
                    error_budget_remaining: Some(0.1),
                    ..Default::default()
                },
                s,
            ],
            None,
            None,
        );
        assert_eq!(list.slos[0].state, "breaching");
    }

    #[test]
    fn open_anomalies_come_from_each_rules_latest_event() {
        let e = |id: &str, rule: &str, state: &str| AnomalyEvent {
            id: id.into(),
            rule_id: rule.into(),
            rule_name: format!("r-{rule}"),
            state: state.into(),
            ..Default::default()
        };
        // Newest first: rule 1 resolved after opening, rule 2 is open.
        let events = vec![
            e("3", "1", "normal"),
            e("2", "2", "anomalous"),
            e("1", "1", "anomalous"),
        ];
        let open = shape_anomalies(
            &events,
            &ListAnomaliesArgs {
                include_resolved: false,
                contains: None,
                limit: None,
            },
        );
        assert_eq!(open.open, 1);
        assert_eq!(
            open.anomalies
                .iter()
                .map(|a| a.event_id.as_str())
                .collect::<Vec<_>>(),
            ["2"]
        );
        let all = shape_anomalies(
            &events,
            &ListAnomaliesArgs {
                include_resolved: true,
                contains: None,
                limit: None,
            },
        );
        assert_eq!(all.anomalies.len(), 3);
    }

    #[test]
    fn preview_counts_alerts_and_ranges() {
        let p: PreviewResponse = serde_json::from_value(serde_json::json!({
            "current_value": 4.567, "groups": [["a", 1.0], ["b", 9.0]],
            "series": [{"group_key": "a", "points": [{"timestamp": "t1", "value": 1.0}, {"timestamp": "t2", "value": 3.0}]}],
            "simulated_events": [{"timestamp": "t2", "group_key": "a", "previous_state": "ok", "state": "alert", "value": 3.0}],
            "bucket_secs": 300
        }))
        .unwrap();
        let out = shape_preview(p);
        assert_eq!(
            out.groups[0],
            GroupValue {
                group: "b".into(),
                value: 9.0
            }
        );
        assert_eq!(
            out.series[0],
            SeriesRange {
                group: "a".into(),
                min: 1.0,
                max: 3.0,
                last: 3.0,
                points: 2
            }
        );
        assert_eq!(out.current_value, Some(4.57));
        assert_eq!(out.would_have_fired[0].to, "alert");
    }

    #[test]
    fn durations_are_bounded() {
        assert_eq!(secs(None, "5m", 60, 604_800, "w").unwrap(), 300);
        assert!(secs(Some("10s"), "5m", 60, 604_800, "w").is_err());
        assert!(secs(Some("30d"), "5m", 60, 604_800, "w").is_err());
    }
}
