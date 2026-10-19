//! Request and response types for the Rush query API endpoints the tools use.
//!
//! Response structs default every field so a newer or older Rush that adds or
//! drops a field still decodes.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::client::{ApiError, ClientKey, RushClient};
use crate::time::Window;

// ── Shared ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct TimeRange {
    pub from: String,
    pub to: String,
}

impl From<&Window> for TimeRange {
    fn from(w: &Window) -> Self {
        Self {
            from: w.from_rfc3339(),
            to: w.to_rfc3339(),
        }
    }
}

/// Comparison operators the Rush API accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum Op {
    #[serde(rename = "=")]
    Eq,
    #[serde(rename = "!=")]
    Ne,
    #[serde(rename = ">")]
    Gt,
    #[serde(rename = ">=")]
    Gte,
    #[serde(rename = "<")]
    Lt,
    #[serde(rename = "<=")]
    Lte,
    /// SQL LIKE; use % as the wildcard.
    #[serde(rename = "LIKE")]
    Like,
    #[serde(rename = "NOT LIKE")]
    NotLike,
    /// Value is a comma-separated list.
    #[serde(rename = "IN")]
    In,
    #[serde(rename = "NOT IN")]
    NotIn,
}

impl Op {
    pub fn symbol(self) -> &'static str {
        match self {
            Op::Eq => "=",
            Op::Ne => "!=",
            Op::Gt => ">",
            Op::Gte => ">=",
            Op::Lt => "<",
            Op::Lte => "<=",
            Op::Like => " LIKE ",
            Op::NotLike => " NOT LIKE ",
            Op::In => " IN ",
            Op::NotIn => " NOT IN ",
        }
    }

    /// Parse the operators used in saved queries and the Explore search bar.
    pub fn parse(s: &str) -> Option<Op> {
        Some(match s.trim().to_ascii_uppercase().as_str() {
            "=" | "==" => Op::Eq,
            "!=" => Op::Ne,
            ">" => Op::Gt,
            ">=" => Op::Gte,
            "<" => Op::Lt,
            "<=" => Op::Lte,
            "LIKE" | "~" => Op::Like,
            "NOT LIKE" | "!~" => Op::NotLike,
            "IN" => Op::In,
            "NOT IN" => Op::NotIn,
            _ => return None,
        })
    }
}

/// One filter condition.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Filter {
    /// Field name. Spans: service_name, span_name, http_method, http_path,
    /// http_status_code, status, duration_ns, kind, error (0/1), or
    /// attributes.<key>. Logs: service_name, severity, body, trace_id, span_id,
    /// resource.<key>, log.<key>, or a bare attribute key.
    pub field: String,
    pub op: Op,
    /// Value to compare. Numbers may be sent as strings.
    pub value: serde_json::Value,
}

impl Filter {
    pub fn eq(field: &str, value: &str) -> Self {
        Self {
            field: field.into(),
            op: Op::Eq,
            value: serde_json::Value::String(value.into()),
        }
    }

    /// `field=value` token for the Explore search bar.
    pub fn as_query_token(&self) -> String {
        let value = match &self.value {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        let value = if value.chars().any(char::is_whitespace) {
            format!("\"{}\"", value.replace('"', "\\\""))
        } else {
            value
        };
        format!("{}{}{}", self.field, self.op.symbol(), value)
    }
}

/// Explore search-bar text for a set of filters plus free text.
pub fn query_text(filters: &[Filter], search: Option<&str>) -> String {
    let mut parts: Vec<String> = filters.iter().map(Filter::as_query_token).collect();
    if let Some(s) = search.map(str::trim).filter(|s| !s.is_empty()) {
        parts.push(s.to_string());
    }
    parts.join(" ")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SignalKind {
    Logs,
    Spans,
}

// ── Explore ───────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ExploreRequest<'a> {
    pub signal: SignalKind,
    pub time_range: TimeRange,
    pub filters: &'a [Filter],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<&'a str>,
    pub limit: u64,
    pub interval: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_by: Option<&'a str>,
    pub include_rows: bool,
    pub include_summary: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ExploreResponse<T> {
    pub rows: Vec<T>,
    pub next_cursor: Option<String>,
    pub count: ExploreCount,
    pub summary: ExploreSummary,
    pub errors: BTreeMap<String, String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ExploreCount {
    pub value: u64,
    pub kind: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ExploreSummary {
    pub histogram: Vec<CountBucket>,
    pub facets: Facets,
    pub groups: Vec<KeyCount>,
    pub interval_secs: u64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Facets {
    pub services: Vec<KeyCount>,
    pub statuses: Vec<KeyCount>,
    pub methods: Vec<KeyCount>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(default)]
pub struct KeyCount {
    pub key: String,
    pub count: u64,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct CountBucket {
    pub bucket: String,
    pub count: u64,
    pub error_count: u64,
}

/// A span row from Explore.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct SpanRow {
    pub timestamp: i64,
    pub service_name: String,
    pub span_name: String,
    pub http_method: String,
    pub http_path: String,
    pub http_status_code: u16,
    pub duration_ns: u64,
    pub status: String,
    pub trace_id: String,
    pub span_id: String,
}

/// A log row from Explore (PascalCase keys).
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct LogRow {
    pub timestamp: i64,
    pub trace_id: String,
    pub span_id: String,
    pub severity_text: String,
    pub severity_number: u8,
    pub service_name: String,
    pub body: String,
    pub timestamp_ns: String,
    pub block_number: String,
    pub block_offset: String,
    pub body_hash: String,
}

// ── Span queries ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct GroupRequest<'a> {
    pub time_range: TimeRange,
    pub filters: &'a [Filter],
    pub group_by: [&'a str; 1],
    pub limit: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<&'a str>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct GroupResponse {
    /// Each item is `{ "<field>": "<value>", "count": n }`.
    pub groups: Vec<serde_json::Map<String, serde_json::Value>>,
}

impl GroupResponse {
    pub fn pairs(&self, field: &str) -> Vec<KeyCount> {
        self.groups
            .iter()
            .map(|g| KeyCount {
                key: match g.get(field) {
                    Some(serde_json::Value::String(s)) => s.clone(),
                    Some(serde_json::Value::Null) | None => String::new(),
                    Some(other) => other.to_string(),
                },
                count: g
                    .get("count")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0),
            })
            .collect()
    }
}

#[derive(Debug, Serialize)]
pub struct TimeseriesRequest<'a> {
    pub time_range: TimeRange,
    pub filters: &'a [Filter],
    pub interval: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_by: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<&'a str>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct TimeseriesResponse {
    pub buckets: Vec<TimeseriesBucket>,
    pub grouped: bool,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct TimeseriesBucket {
    pub bucket: String,
    pub count: u64,
    pub error_count: u64,
    pub avg_duration_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub group_key: String,
}

#[derive(Debug, Serialize)]
pub struct WideQueryRequest<'a> {
    pub time_range: TimeRange,
    pub filters: &'a [Filter],
    pub limit: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<&'a str>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct WideQueryResponse {
    pub rows: Vec<WideRow>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct WideRow {
    /// JSON object encoded as a string.
    pub attributes: String,
}

// ── Logs ──────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct LogsRequest<'a> {
    pub time_range: TimeRange,
    pub filters: &'a [Filter],
    pub limit: u64,
    pub slim: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct LogsResponse {
    pub rows: Vec<LogRecord>,
}

/// A full log record (`/logs/detail`, `/logs` with slim=false).
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct LogRecord {
    pub timestamp: i64,
    pub trace_id: String,
    pub span_id: String,
    pub severity_text: String,
    pub severity_number: u8,
    pub service_name: String,
    pub body: String,
    pub resource_attributes: BTreeMap<String, String>,
    pub scope_name: String,
    pub log_attributes: BTreeMap<String, String>,
}

/// Locator for one log line, taken from a search result row.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct LogRef {
    pub timestamp_ns: String,
    pub block_number: String,
    pub block_offset: String,
    pub body_hash: String,
    pub service_name: String,
    pub severity_text: String,
    #[serde(default)]
    pub trace_id: String,
    #[serde(default)]
    pub span_id: String,
}

impl From<&LogRow> for LogRef {
    fn from(r: &LogRow) -> Self {
        Self {
            timestamp_ns: if r.timestamp_ns.is_empty() {
                r.timestamp.to_string()
            } else {
                r.timestamp_ns.clone()
            },
            block_number: r.block_number.clone(),
            block_offset: r.block_offset.clone(),
            body_hash: r.body_hash.clone(),
            service_name: r.service_name.clone(),
            severity_text: r.severity_text.clone(),
            trace_id: r.trace_id.clone(),
            span_id: r.span_id.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct LogContextRequest<'a> {
    pub time_range: TimeRange,
    pub anchor: LogContextAnchor<'a>,
    pub before: u64,
    pub after: u64,
}

#[derive(Debug, Serialize)]
pub struct LogContextAnchor<'a> {
    pub timestamp_ns: &'a str,
    pub service_name: &'a str,
    pub trace_id: &'a str,
    pub span_id: &'a str,
    pub body: &'a str,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct LogContextResponse {
    pub rows: Vec<LogRow>,
}

// ── Traces ────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct TraceResponse {
    pub trace_id: String,
    pub spans: Vec<SpanNode>,
    pub span_count: usize,
    pub duration_ns: u64,
    pub services: Vec<String>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct SpanNode {
    pub span_id: String,
    pub parent_span_id: String,
    pub service_name: String,
    pub span_name: String,
    pub kind: String,
    pub http_method: String,
    pub http_path: String,
    pub http_status_code: u16,
    pub duration_ns: u64,
    pub status: String,
    pub timestamp: String,
    pub attributes: serde_json::Value,
    pub events: Vec<SpanEvent>,
    pub children: Vec<SpanNode>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct SpanEvent {
    pub timestamp: String,
    pub name: String,
    pub attributes: serde_json::Value,
}

// ── Services ──────────────────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ServiceGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct GraphNode {
    pub service_name: String,
    pub request_count: u64,
    pub error_count: u64,
    pub avg_duration_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct GraphEdge {
    pub source: String,
    pub target: String,
    pub request_count: u64,
    pub error_count: u64,
    pub avg_duration_ms: f64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ServicesList {
    pub services: Vec<ServiceEntry>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct ServiceEntry {
    pub service_name: String,
    pub last_seen: String,
    pub request_count: u64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct EndpointsResponse {
    pub endpoints: Vec<EndpointRow>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct EndpointRow {
    pub endpoint: String,
    pub method: String,
    pub path: String,
    pub req: u64,
    pub errors: u64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ErrorsResponse {
    pub groups: Vec<ErrorGroup>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct ErrorGroup {
    pub key: String,
    pub status_code: u16,
    pub method: String,
    pub path: String,
    pub severity: String,
    pub example: String,
    pub count: u64,
    pub last_seen: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct LatencyHistogram {
    pub buckets: Vec<LatencyBucket>,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub total: u64,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct LatencyBucket {
    pub exp: i32,
    pub count: u64,
}

#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default)]
pub struct TimeBreakdown {
    pub request_count: u64,
    pub wall_time_ms: f64,
    pub application_time_ms: f64,
    pub database_time_ms: f64,
    pub database_call_time_ms: f64,
    pub database_calls: u64,
    pub databases: Vec<DatabaseTime>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default)]
pub struct DatabaseTime {
    pub system: String,
    pub target: String,
    pub calls: u64,
    pub total_ms: f64,
    pub p95_ms: f64,
}

// ── BubbleUp ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct BubbleUpRequest<'a> {
    pub selection: TimeRange,
    pub baseline: TimeRange,
    pub signal: SignalKind,
    pub filters: &'a [Filter],
    pub top_k: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selection_min_duration_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selection_max_duration_ns: Option<u64>,
    pub selection_errors_only: bool,
    pub exclude_selection_from_baseline: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct BubbleUpResponse {
    pub dimensions: Vec<Dimension>,
    pub selection_count: u64,
    pub baseline_count: u64,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct Dimension {
    pub name: String,
    pub values: Vec<DimensionValue>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct DimensionValue {
    pub value: String,
    pub selection_count: u64,
    pub baseline_count: u64,
    pub selection_pct: f64,
    pub baseline_pct: f64,
    pub lift: f64,
}

// ── Prometheus ────────────────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct PromEnvelope<T> {
    pub status: String,
    pub data: T,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct PromData {
    #[serde(rename = "resultType")]
    pub result_type: String,
    pub result: serde_json::Value,
}

// ── Deploys, saved queries, identity ──────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct DeploysResponse {
    pub deploys: Vec<Deploy>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default)]
pub struct Deploy {
    pub id: String,
    pub service_name: String,
    pub version: String,
    pub commit_sha: String,
    pub description: String,
    pub environment: String,
    pub deployed_by: String,
    pub deployed_at: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct SavedQueriesResponse {
    pub saved_queries: Vec<SavedQuery>,
    pub groups: Vec<NamedGroup>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct NamedGroup {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct SavedQuery {
    pub id: String,
    pub name: String,
    pub description: String,
    pub visibility: String,
    pub group_id: String,
    pub owner_name: String,
    pub query: SavedQueryBody,
    pub updated_at: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct SavedQueryBody {
    pub filters: Vec<SavedFilter>,
    pub search: String,
    pub group_by: String,
    pub time_preset: u32,
    pub view_mode: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct SavedFilter {
    pub field: String,
    pub op: String,
    pub value: String,
}

#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default)]
pub struct WhoAmI {
    pub tenant_id: String,
    pub principal: Principal,
    pub capabilities: Capabilities,
}

#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default)]
pub struct Principal {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
    pub name: String,
    pub role: String,
}

#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default)]
pub struct Capabilities {
    pub read: bool,
    pub write: bool,
}

// ── Monitors ──────────────────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct MonitorsResponse {
    pub monitors: Vec<Monitor>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct MonitorDetailResponse {
    pub monitor: Monitor,
    pub events: Vec<MonitorEvent>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct Monitor {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub monitor_type: String,
    pub query_config: serde_json::Value,
    pub critical: Option<f64>,
    pub critical_recovery: Option<f64>,
    pub warning: Option<f64>,
    pub warning_recovery: Option<f64>,
    pub comparator: String,
    pub eval_window_secs: i64,
    pub eval_interval_secs: i64,
    pub group_by: serde_json::Value,
    pub state: String,
    pub group_states: serde_json::Value,
    pub no_data_action: String,
    pub message: String,
    pub tags: serde_json::Value,
    pub priority: Option<i64>,
    /// false means muted.
    pub enabled: bool,
    pub composite_formula: String,
    pub last_eval_at: Option<String>,
    pub last_triggered_at: Option<String>,
    pub created_by: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct MonitorEvent {
    pub group_key: String,
    pub prev_state: String,
    pub new_state: String,
    pub value: Option<f64>,
    pub threshold: Option<f64>,
    pub message: String,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct PreviewRequest<'a> {
    #[serde(rename = "type")]
    pub monitor_type: &'a str,
    pub query_config: &'a serde_json::Value,
    pub eval_window_secs: i64,
    pub lookback_secs: i64,
    pub group_by: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub critical: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub critical_recovery: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning_recovery: Option<f64>,
    pub comparator: &'a str,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct PreviewResponse {
    pub current_value: Option<f64>,
    /// `[group_key, value]` pairs.
    pub groups: Vec<(String, f64)>,
    pub series: Vec<PreviewSeries>,
    pub simulated_events: Vec<SimulatedEvent>,
    pub bucket_secs: i64,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct PreviewSeries {
    pub group_key: String,
    pub points: Vec<PreviewPoint>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct PreviewPoint {
    pub timestamp: String,
    pub value: f64,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct SimulatedEvent {
    pub timestamp: String,
    pub group_key: String,
    pub previous_state: String,
    pub state: String,
    pub value: f64,
    pub threshold: Option<f64>,
}

// ── SLOs ──────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct SlosResponse {
    pub slos: Vec<Slo>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct SloDetailResponse {
    pub slo: Slo,
    pub events: Vec<SloEvent>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct Slo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub slo_type: String,
    pub indicator_type: String,
    pub service_name: String,
    pub metric_name: String,
    pub window_type: String,
    pub target_percentage: f64,
    pub threshold_ms: Option<f64>,
    pub state: String,
    /// Fraction of budget left: 1.0 full, 0 or below exhausted.
    pub error_budget_remaining: Option<f64>,
    pub error_count: Option<f64>,
    pub total_count: Option<f64>,
    pub last_eval_at: Option<String>,
    pub last_breached_at: Option<String>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct SloEvent {
    pub state: String,
    pub error_count: f64,
    pub total_count: f64,
    pub error_budget_remaining: f64,
    pub message: String,
    pub created_at: String,
}

// ── Anomalies ─────────────────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct AnomalyEventsResponse {
    pub events: Vec<AnomalyEvent>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct AnomalyEvent {
    pub id: String,
    pub rule_id: String,
    pub rule_name: String,
    /// "anomalous" opens an anomaly; a later "normal" for the same rule resolves it.
    pub state: String,
    pub metric: String,
    pub value: f64,
    pub expected: f64,
    /// Distance from the expected value in standard deviations.
    pub deviation: f64,
    pub message: String,
    pub created_at: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct AnomalyRuleResponse {
    pub rule: AnomalyRule,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default)]
pub struct AnomalyRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub source: String,
    pub query: String,
    pub service_name: String,
    pub apm_metric: String,
    pub sensitivity: f64,
    pub state: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Correlations {
    pub status_code: u16,
    pub services: Vec<CorrelatedService>,
    pub logs: Vec<CorrelatedLog>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct CorrelatedService {
    pub name: String,
    pub total: u64,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct CorrelatedLog {
    pub timestamp: String,
    pub service_name: String,
    pub severity_text: String,
    pub body: String,
    pub trace_id: String,
}

// ── Dashboards ────────────────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct DashboardsResponse {
    pub dashboards: Vec<Dashboard>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct Dashboard {
    pub id: String,
    pub name: String,
    pub description: String,
    pub visibility: String,
    pub tags: serde_json::Value,
    pub variables: serde_json::Value,
    pub defaults: serde_json::Value,
    pub updated_at: String,
    pub widgets: Vec<Widget>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct Widget {
    pub id: String,
    pub title: String,
    pub widget_type: String,
    pub query_config: serde_json::Value,
    pub display_config: serde_json::Value,
}

// ── Client helpers ────────────────────────────────────────────────────────

impl RushClient {
    /// The Rush API answers its health endpoint (no key needed).
    pub async fn ping(&self) -> Result<(), ApiError> {
        let url = self
            .base()
            .join("healthz")
            .map_err(|e| ApiError::Config(e.to_string()))?;
        let resp = reqwest::Client::new()
            .get(url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| ApiError::Network(self.base().to_string(), e.to_string()))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(ApiError::Unavailable(resp.status().to_string()))
        }
    }

    pub async fn explore<T: serde::de::DeserializeOwned + Default>(
        &self,
        key: Option<&ClientKey>,
        tool: &str,
        req: &ExploreRequest<'_>,
    ) -> Result<ExploreResponse<T>, ApiError> {
        self.post(key, tool, "/api/v1/explore/search", req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_render_as_search_bar_tokens() {
        let filters = vec![
            Filter::eq("service.name", "checkout"),
            Filter {
                field: "http_status_code".into(),
                op: Op::Gte,
                value: serde_json::json!(500),
            },
            Filter::eq("log.message", "card declined"),
        ];
        assert_eq!(
            query_text(&filters, Some("timeout")),
            "service.name=checkout http_status_code>=500 log.message=\"card declined\" timeout"
        );
    }

    #[test]
    fn ops_serialize_as_the_api_expects() {
        assert_eq!(serde_json::to_value(Op::NotLike).unwrap(), "NOT LIKE");
        assert_eq!(Op::parse("not like"), Some(Op::NotLike));
        assert_eq!(Op::parse("=="), Some(Op::Eq));
        assert_eq!(Op::parse("contains"), None);
    }

    #[test]
    fn group_items_are_read_by_field_name() {
        let resp: GroupResponse = serde_json::from_value(serde_json::json!({
            "groups": [{"service_name": "checkout", "count": 12}, {"service_name": null, "count": 1}]
        }))
        .unwrap();
        assert_eq!(
            resp.pairs("service_name"),
            vec![
                KeyCount {
                    key: "checkout".into(),
                    count: 12
                },
                KeyCount {
                    key: "".into(),
                    count: 1
                }
            ]
        );
    }

    #[test]
    fn log_rows_decode_pascal_case_and_tolerate_missing_fields() {
        let row: LogRow = serde_json::from_value(serde_json::json!({
            "Timestamp": 1760796000000000000_i64, "ServiceName": "api", "Body": "boom",
            "TimestampNs": "1760796000000000001", "SeverityText": "ERROR", "Extra": 1
        }))
        .unwrap();
        assert_eq!(row.service_name, "api");
        assert_eq!(LogRef::from(&row).timestamp_ns, "1760796000000000001");
    }
}
