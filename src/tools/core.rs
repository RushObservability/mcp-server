//! `core` toolset: context, time, field discovery, search, aggregation,
//! traces, services, metrics and links.

use std::collections::{BTreeMap, HashMap};

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
    self, EndpointsResponse, ErrorsResponse, ExploreRequest, ExploreResponse, Filter, GroupRequest,
    GroupResponse, KeyCount, LogRecord, LogRef, LogRow, LogsRequest, LogsResponse, Op, PromData,
    PromEnvelope, ServiceGraph, SignalKind, SpanNode, SpanRow, TimeRange, TimeseriesBucket,
    TimeseriesRequest, TimeseriesResponse, TraceResponse, WhoAmI, WideQueryRequest,
    WideQueryResponse, query_text,
};
use crate::client::ClientKey;
use crate::envelope::{Envelope, Hint, Trim, clip, halve};
use crate::links::{Links, Signal, trace_id_from};
use crate::server::{RushMcp, ToolError};
use crate::time::{TimeArgs, bucket_for, parse_duration};
use crate::tools::{
    Point, Query, QueryArgs, compress, keep, minutes_ending_now, ms, ns_to_time, pct, pop, round2,
    thin, thousands, top,
};

fn signal_link(kind: SignalKind) -> Signal {
    match kind {
        SignalKind::Logs => Signal::Logs,
        SignalKind::Spans => Signal::Spans,
    }
}

fn kind_name(kind: SignalKind) -> &'static str {
    match kind {
        SignalKind::Logs => "logs",
        SignalKind::Spans => "spans",
    }
}

fn empty_hint(kind: SignalKind) -> Hint {
    Hint::new(format!("No {} matched.", kind_name(kind)))
        .action("Widen the window (for example last=\"24h\")")
        .action("Check field names with list_fields and values with list_field_values")
        .action("Remove filters one at a time to find the one excluding everything")
}

// ── get_context ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize, JsonSchema)]
pub struct Context {
    pub server_time: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<WhoAmI>,
    pub web_url: String,
    pub toolsets: Vec<String>,
    /// Optional Rush features turned on for this deployment.
    pub features: serde_json::Value,
    /// Records received in the last hour, to show which signals have data.
    pub last_hour: SignalCounts,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SignalCounts {
    pub logs: Option<u64>,
    pub spans: Option<u64>,
}

impl Trim for Context {
    fn trim(&mut self) -> bool {
        if !self.features.is_null() {
            self.features = serde_json::Value::Null;
            return true;
        }
        false
    }
}

// ── resolve_time ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize, JsonSchema)]
pub struct ResolvedTime {
    pub from: String,
    pub to: String,
    pub duration_minutes: i64,
    /// True when the window ends at "now" and moves forward.
    pub relative: bool,
    /// A bucket size giving about 60 points across the window.
    pub suggested_interval: String,
}

impl Trim for ResolvedTime {
    fn trim(&mut self) -> bool {
        false
    }
}

// ── list_fields / list_field_values ───────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListFieldsArgs {
    /// "logs" or "spans".
    pub signal: SignalKind,
    /// Only fields whose name contains this text (case-insensitive).
    #[serde(default)]
    pub contains: Option<String>,
    /// Only sample records from this service.
    #[serde(default)]
    pub service: Option<String>,
    #[serde(flatten)]
    pub time: TimeArgs,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct FieldList {
    pub signal: SignalKind,
    /// Built-in fields every record has.
    pub standard: Vec<FieldDoc>,
    /// Attribute fields seen in a sample of recent records, with how many of
    /// the sampled records carried each. Rare fields may be missing.
    pub attributes: Vec<KeyCount>,
    pub sampled_records: usize,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct FieldDoc {
    pub name: &'static str,
    pub about: &'static str,
}

impl Trim for FieldList {
    fn trim(&mut self) -> bool {
        let n = self.attributes.len();
        n > 10 && keep(&mut self.attributes, n * 2 / 3)
    }
}

const SPAN_FIELDS: &[FieldDoc] = &[
    FieldDoc {
        name: "service_name",
        about: "service that emitted the span",
    },
    FieldDoc {
        name: "span_name",
        about: "operation name",
    },
    FieldDoc {
        name: "kind",
        about: "SPAN_KIND_SERVER, SPAN_KIND_CLIENT, …",
    },
    FieldDoc {
        name: "status",
        about: "STATUS_CODE_OK, STATUS_CODE_ERROR or STATUS_CODE_UNSET",
    },
    FieldDoc {
        name: "error",
        about: "1 when status is error or HTTP status ≥ 500, else 0",
    },
    FieldDoc {
        name: "http_method",
        about: "HTTP method",
    },
    FieldDoc {
        name: "http_path",
        about: "HTTP route or path",
    },
    FieldDoc {
        name: "http_status_code",
        about: "HTTP response status (number)",
    },
    FieldDoc {
        name: "duration_ns",
        about: "span duration in nanoseconds",
    },
    FieldDoc {
        name: "trace_id",
        about: "32-hex trace ID",
    },
    FieldDoc {
        name: "span_id",
        about: "16-hex span ID",
    },
    FieldDoc {
        name: "parent_span_id",
        about: "parent span ID",
    },
];

const LOG_FIELDS: &[FieldDoc] = &[
    FieldDoc {
        name: "service_name",
        about: "service that emitted the log",
    },
    FieldDoc {
        name: "severity",
        about: "severity text, e.g. ERROR, WARN, INFO",
    },
    FieldDoc {
        name: "severity_number",
        about: "OpenTelemetry severity number (17+ error, 13+ warn, 9+ info)",
    },
    FieldDoc {
        name: "body",
        about: "log message",
    },
    FieldDoc {
        name: "body.<path>",
        about: "field inside a JSON body",
    },
    FieldDoc {
        name: "trace_id",
        about: "trace the log belongs to",
    },
    FieldDoc {
        name: "span_id",
        about: "span the log belongs to",
    },
    FieldDoc {
        name: "scope_name",
        about: "instrumentation scope",
    },
    FieldDoc {
        name: "resource.<key>",
        about: "resource attribute, e.g. resource.k8s.namespace.name",
    },
    FieldDoc {
        name: "log.<key>",
        about: "log attribute",
    },
];

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FieldValuesArgs {
    /// "logs" or "spans".
    pub signal: SignalKind,
    /// Field to list values for, e.g. "service_name" or "attributes.http.route".
    pub field: String,
    /// Only values containing this text.
    #[serde(default)]
    pub contains: Option<String>,
    /// How many values to return (default 20, max 100).
    #[serde(default)]
    pub limit: Option<u64>,
    #[serde(flatten)]
    pub query: QueryArgs,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct FieldValues {
    pub field: String,
    /// Most common values first, with record counts in the window.
    pub values: Vec<KeyCount>,
}

impl Trim for FieldValues {
    fn trim(&mut self) -> bool {
        let n = self.values.len();
        n > 5 && keep(&mut self.values, n / 2)
    }
}

// ── search_logs ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchLogsArgs {
    #[serde(flatten)]
    pub query: QueryArgs,
    /// Number of sample log lines to return, newest first (default 10, max 50).
    #[serde(default)]
    pub samples: Option<u64>,
    /// Also count records per value of this field.
    #[serde(default)]
    pub group_by: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct LogSearch {
    pub total: u64,
    /// error, warn, info and other, by severity number.
    pub by_severity: Vec<KeyCount>,
    pub by_service: Vec<KeyCount>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<KeyCount>,
    pub over_time: Vec<Point>,
    pub samples: Vec<LogSample>,
    #[serde(skip)]
    body_limit: usize,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct LogSample {
    pub time: String,
    pub service: String,
    pub severity: String,
    /// Untrusted log content.
    pub body: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub trace_id: String,
    /// Pass to get_log_record or get_log_context.
    #[serde(rename = "ref")]
    pub log_ref: LogRef,
    #[serde(skip)]
    full_body: String,
}

impl Trim for LogSearch {
    fn trim(&mut self) -> bool {
        if self.samples.len() > 5 {
            return pop(&mut self.samples);
        }
        if halve(&mut self.body_limit, 80) {
            for s in &mut self.samples {
                s.body = clip(&s.full_body, self.body_limit);
            }
            return true;
        }
        thin(&mut self.over_time)
            || keep(&mut self.groups, 5)
            || keep(&mut self.by_service, 5)
            || pop(&mut self.samples)
    }
}

pub fn shape_log_search(resp: ExploreResponse<LogRow>, samples: usize) -> LogSearch {
    let body_limit = 500;
    let rows: Vec<LogSample> = resp
        .rows
        .iter()
        .take(samples)
        .map(|r| LogSample {
            time: ns_to_time(r.timestamp),
            service: r.service_name.clone(),
            severity: r.severity_text.clone(),
            body: clip(&r.body, body_limit),
            trace_id: r.trace_id.clone(),
            log_ref: LogRef::from(r),
            full_body: r.body.clone(),
        })
        .collect();
    LogSearch {
        total: resp.count.value,
        by_severity: resp.summary.facets.statuses,
        by_service: top(resp.summary.facets.services, 10),
        groups: top(resp.summary.groups, 20),
        over_time: compress(
            resp.summary
                .histogram
                .into_iter()
                .map(|b| Point {
                    t: b.bucket,
                    count: b.count,
                    errors: None,
                })
                .collect(),
            24,
        ),
        samples: rows,
        body_limit,
    }
}

// ── search_spans ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchSpansArgs {
    #[serde(flatten)]
    pub query: QueryArgs,
    /// Only spans with an error status or HTTP status ≥ 500.
    #[serde(default)]
    pub errors_only: bool,
    /// Only spans at least this slow, in milliseconds.
    #[serde(default)]
    pub min_duration_ms: Option<f64>,
    /// Number of sample spans to return, newest first (default 10, max 50).
    #[serde(default)]
    pub samples: Option<u64>,
    /// Also count spans per value of this field.
    #[serde(default)]
    pub group_by: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SpanSearch {
    pub total: u64,
    pub errors: u64,
    pub error_rate_pct: f64,
    /// Latency from time buckets: count-weighted means of each bucket's
    /// percentiles, and the worst bucket's p99. Close to, not exactly, the
    /// window's percentiles.
    pub latency_ms_approx: Latency,
    pub by_service: Vec<KeyCount>,
    /// HTTP status classes ("500", "400", "200").
    pub by_status_class: Vec<KeyCount>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<KeyCount>,
    pub over_time: Vec<Point>,
    pub samples: Vec<SpanSample>,
}

#[derive(Debug, Default, Clone, Serialize, JsonSchema, PartialEq)]
pub struct Latency {
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
    pub worst_bucket_p99: f64,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SpanSample {
    pub time: String,
    pub service: String,
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub status_code: u16,
    pub status: String,
    pub duration_ms: f64,
    pub trace_id: String,
    pub span_id: String,
}

fn is_zero(n: &u16) -> bool {
    *n == 0
}

impl Trim for SpanSearch {
    fn trim(&mut self) -> bool {
        if self.samples.len() > 5 {
            return pop(&mut self.samples);
        }
        thin(&mut self.over_time)
            || keep(&mut self.groups, 5)
            || keep(&mut self.by_service, 5)
            || pop(&mut self.samples)
    }
}

/// Approximate window percentiles from per-bucket percentiles.
pub fn latency_from_buckets(buckets: &[TimeseriesBucket]) -> Latency {
    let total: u64 = buckets.iter().map(|b| b.count).sum();
    if total == 0 {
        return Latency::default();
    }
    let weighted = |f: fn(&TimeseriesBucket) -> f64| {
        round2(buckets.iter().map(|b| f(b) * b.count as f64).sum::<f64>() / total as f64)
    };
    Latency {
        p50: weighted(|b| b.p50_ms),
        p95: weighted(|b| b.p95_ms),
        p99: weighted(|b| b.p99_ms),
        worst_bucket_p99: round2(
            buckets
                .iter()
                .filter(|b| b.count > 0)
                .map(|b| b.p99_ms)
                .fold(0.0, f64::max),
        ),
    }
}

pub fn shape_span_search(
    resp: ExploreResponse<SpanRow>,
    ts: &[TimeseriesBucket],
    samples: usize,
) -> SpanSearch {
    let errors: u64 = resp.summary.histogram.iter().map(|b| b.error_count).sum();
    let total = resp.count.value;
    SpanSearch {
        total,
        errors,
        error_rate_pct: pct(errors, total),
        latency_ms_approx: latency_from_buckets(ts),
        by_service: top(resp.summary.facets.services, 10),
        by_status_class: resp.summary.facets.statuses,
        groups: top(resp.summary.groups, 20),
        over_time: compress(
            resp.summary
                .histogram
                .into_iter()
                .map(|b| Point {
                    t: b.bucket,
                    count: b.count,
                    errors: Some(b.error_count),
                })
                .collect(),
            24,
        ),
        samples: resp
            .rows
            .iter()
            .take(samples)
            .map(|r| SpanSample {
                time: ns_to_time(r.timestamp),
                service: r.service_name.clone(),
                name: r.span_name.clone(),
                method: r.http_method.clone(),
                path: r.http_path.clone(),
                status_code: r.http_status_code,
                status: r.status.clone(),
                duration_ms: ms(r.duration_ns),
                trace_id: r.trace_id.clone(),
                span_id: r.span_id.clone(),
            })
            .collect(),
    }
}

// ── aggregate ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AggregateArgs {
    /// "logs" or "spans".
    pub signal: SignalKind,
    /// Count records per value of this field.
    #[serde(default)]
    pub group_by: Option<String>,
    /// Return counts over time instead of (or, for spans, per group as well as) totals.
    #[serde(default)]
    pub over_time: bool,
    /// How many groups to return (default 10, max 50).
    #[serde(default)]
    pub limit: Option<u64>,
    #[serde(flatten)]
    pub query: QueryArgs,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct Aggregation {
    pub signal: Option<SignalKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_by: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<GroupRow>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub series: Vec<Point>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub group_series: Vec<GroupSeries>,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq)]
pub struct GroupRow {
    pub key: String,
    pub count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_rate_pct: Option<f64>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct GroupSeries {
    pub key: String,
    pub total: u64,
    pub points: Vec<Point>,
}

impl Trim for Aggregation {
    fn trim(&mut self) -> bool {
        if let Some(gs) = self.group_series.iter_mut().find(|g| g.points.len() > 6) {
            return thin(&mut gs.points);
        }
        thin(&mut self.series) || pop(&mut self.group_series) || {
            let n = self.groups.len();
            n > 3 && keep(&mut self.groups, n / 2)
        }
    }
}

pub fn join_error_groups(all: Vec<KeyCount>, errors: Vec<KeyCount>) -> Vec<GroupRow> {
    let errs: HashMap<String, u64> = errors.into_iter().map(|g| (g.key, g.count)).collect();
    all.into_iter()
        .map(|g| {
            let e = errs.get(&g.key).copied().unwrap_or(0);
            GroupRow {
                error_rate_pct: Some(pct(e, g.count)),
                errors: Some(e),
                count: g.count,
                key: g.key,
            }
        })
        .collect()
}

pub fn group_series_from(buckets: Vec<TimeseriesBucket>, limit: usize) -> Vec<GroupSeries> {
    let mut by_key: BTreeMap<String, Vec<Point>> = BTreeMap::new();
    for b in buckets {
        by_key.entry(b.group_key.clone()).or_default().push(Point {
            t: b.bucket,
            count: b.count,
            errors: Some(b.error_count),
        });
    }
    let mut series: Vec<GroupSeries> = by_key
        .into_iter()
        .map(|(key, mut points)| {
            points.sort_by(|a, b| a.t.cmp(&b.t));
            GroupSeries {
                total: points.iter().map(|p| p.count).sum(),
                key,
                points: compress(points, 24),
            }
        })
        .collect();
    series.sort_by(|a, b| b.total.cmp(&a.total));
    series.truncate(limit);
    series
}

// ── get_trace ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetTraceArgs {
    /// Trace ID (32 hex characters) or a Rush trace URL.
    pub trace: String,
    /// Show only this span and its descendants in the tree.
    #[serde(default)]
    pub focus_span_id: Option<String>,
    /// Maximum spans in the tree (default 40, max 200).
    #[serde(default)]
    pub max_spans: Option<u64>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct TraceSummary {
    pub trace_id: String,
    pub duration_ms: f64,
    pub span_count: usize,
    pub services: Vec<ServiceShare>,
    /// Spans with an error status or HTTP status ≥ 500.
    pub errors: Vec<SpanBrief>,
    /// From the root, following the slowest child at each level.
    pub critical_path: Vec<SpanBrief>,
    /// Depth-first span tree, cut at max_spans.
    pub tree: Vec<TreeLine>,
    pub tree_complete: bool,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq)]
pub struct ServiceShare {
    pub service: String,
    pub spans: usize,
    pub total_ms: f64,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
pub struct SpanBrief {
    pub span_id: String,
    pub service: String,
    pub name: String,
    pub duration_ms: f64,
    #[serde(skip_serializing_if = "is_zero")]
    pub status_code: u16,
    /// Exception message from the span's events, if any. Untrusted content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq)]
pub struct TreeLine {
    pub depth: usize,
    pub span_id: String,
    pub service: String,
    pub name: String,
    pub duration_ms: f64,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub error: bool,
}

impl Trim for TraceSummary {
    fn trim(&mut self) -> bool {
        if self.tree.len() > 10 {
            let n = self.tree.len();
            self.tree.truncate(n * 2 / 3);
            self.tree_complete = false;
            return true;
        }
        keep(&mut self.errors, 5) || keep(&mut self.critical_path, 8) || keep(&mut self.services, 8)
    }
}

fn is_error_span(s: &SpanNode) -> bool {
    s.status.contains("ERROR") || s.http_status_code >= 500
}

fn exception_of(s: &SpanNode) -> Option<String> {
    s.events
        .iter()
        .find(|e| e.name == "exception")
        .and_then(|e| {
            let msg = e
                .attributes
                .get("exception.message")
                .and_then(|v| v.as_str());
            let ty = e.attributes.get("exception.type").and_then(|v| v.as_str());
            match (ty, msg) {
                (Some(t), Some(m)) => Some(clip(&format!("{t}: {m}"), 300)),
                (None, Some(m)) => Some(clip(m, 300)),
                (Some(t), None) => Some(t.to_string()),
                _ => None,
            }
        })
}

fn brief(s: &SpanNode) -> SpanBrief {
    SpanBrief {
        span_id: s.span_id.clone(),
        service: s.service_name.clone(),
        name: s.span_name.clone(),
        duration_ms: ms(s.duration_ns),
        status_code: s.http_status_code,
        exception: exception_of(s),
    }
}

fn find_span<'a>(nodes: &'a [SpanNode], id: &str) -> Option<&'a SpanNode> {
    for n in nodes {
        if n.span_id == id {
            return Some(n);
        }
        if let Some(found) = find_span(&n.children, id) {
            return Some(found);
        }
    }
    None
}

pub fn shape_trace(
    trace: TraceResponse,
    focus: Option<&str>,
    max_spans: usize,
) -> Result<TraceSummary, String> {
    let mut services: BTreeMap<String, (usize, u64)> = BTreeMap::new();
    let mut errors = Vec::new();
    fn walk(
        nodes: &[SpanNode],
        services: &mut BTreeMap<String, (usize, u64)>,
        errors: &mut Vec<SpanBrief>,
    ) {
        for n in nodes {
            let e = services.entry(n.service_name.clone()).or_default();
            e.0 += 1;
            e.1 += n.duration_ns;
            if is_error_span(n) {
                errors.push(brief(n));
            }
            walk(&n.children, services, errors);
        }
    }
    walk(&trace.spans, &mut services, &mut errors);

    let roots: Vec<&SpanNode> = match focus {
        Some(id) => vec![
            find_span(&trace.spans, id)
                .ok_or_else(|| format!("span {id} is not in trace {}", trace.trace_id))?,
        ],
        None => {
            let mut r: Vec<&SpanNode> = trace.spans.iter().collect();
            r.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
            r
        }
    };

    let mut critical = Vec::new();
    if let Some(mut node) = roots.iter().copied().max_by_key(|n| n.duration_ns) {
        loop {
            critical.push(brief(node));
            match node.children.iter().max_by_key(|c| c.duration_ns) {
                Some(next) => node = next,
                None => break,
            }
        }
    }

    let mut tree = Vec::new();
    let mut complete = true;
    fn lines(
        nodes: &[&SpanNode],
        depth: usize,
        max: usize,
        out: &mut Vec<TreeLine>,
        complete: &mut bool,
    ) {
        for n in nodes {
            if out.len() >= max {
                *complete = false;
                return;
            }
            out.push(TreeLine {
                depth,
                span_id: n.span_id.clone(),
                service: n.service_name.clone(),
                name: n.span_name.clone(),
                duration_ms: ms(n.duration_ns),
                error: is_error_span(n),
            });
            let kids: Vec<&SpanNode> = n.children.iter().collect();
            lines(&kids, depth + 1, max, out, complete);
        }
    }
    lines(&roots, 0, max_spans, &mut tree, &mut complete);

    let mut shares: Vec<ServiceShare> = services
        .into_iter()
        .map(|(service, (spans, ns))| ServiceShare {
            service,
            spans,
            total_ms: ms(ns),
        })
        .collect();
    shares.sort_by(|a, b| b.total_ms.total_cmp(&a.total_ms));
    errors.truncate(20);
    Ok(TraceSummary {
        trace_id: trace.trace_id,
        duration_ms: ms(trace.duration_ns),
        span_count: trace.span_count,
        services: shares,
        errors,
        critical_path: critical,
        tree,
        tree_complete: complete,
    })
}

// ── services ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListServicesArgs {
    /// Only services whose name contains this text.
    #[serde(default)]
    pub contains: Option<String>,
    /// How many services to return, busiest first (default 25, max 200).
    #[serde(default)]
    pub limit: Option<u64>,
    #[serde(flatten)]
    pub time: TimeArgs,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ServiceList {
    pub services: Vec<ServiceRow>,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
pub struct ServiceRow {
    pub service: String,
    pub requests: u64,
    pub errors: u64,
    pub error_rate_pct: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
}

impl Trim for ServiceList {
    fn trim(&mut self) -> bool {
        let n = self.services.len();
        n > 5 && keep(&mut self.services, n * 2 / 3)
    }
}

fn service_row(n: &api::GraphNode) -> ServiceRow {
    ServiceRow {
        service: n.service_name.clone(),
        requests: n.request_count,
        errors: n.error_count,
        error_rate_pct: pct(n.error_count, n.request_count),
        p50_ms: round2(n.p50_ms),
        p95_ms: round2(n.p95_ms),
        p99_ms: round2(n.p99_ms),
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetServiceArgs {
    /// Service name.
    pub service: String,
    #[serde(flatten)]
    pub time: TimeArgs,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ServiceDetail {
    pub service: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totals: Option<ServiceRow>,
    pub endpoints: Vec<EndpointStat>,
    pub error_groups: Vec<ErrorStat>,
    /// Services this one calls.
    pub calls: Vec<EdgeStat>,
    /// Services that call this one.
    pub called_by: Vec<EdgeStat>,
    pub recent_deploys: Vec<api::Deploy>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct EndpointStat {
    pub endpoint: String,
    pub requests: u64,
    pub errors: u64,
    pub p95_ms: f64,
    pub p99_ms: f64,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ErrorStat {
    pub key: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub status_code: u16,
    pub count: u64,
    /// Example message. Untrusted content.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub example: String,
    pub last_seen: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct EdgeStat {
    pub service: String,
    pub requests: u64,
    pub errors: u64,
    pub avg_ms: f64,
}

impl Trim for ServiceDetail {
    fn trim(&mut self) -> bool {
        keep(&mut self.endpoints, 5)
            || keep(&mut self.error_groups, 5)
            || keep(&mut self.calls, 5)
            || keep(&mut self.called_by, 5)
            || keep(&mut self.recent_deploys, 2)
            || pop(&mut self.error_groups)
            || pop(&mut self.endpoints)
    }
}

// ── metrics ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct QueryMetricsArgs {
    /// PromQL expression, e.g. sum by (service_name) (rate(http_server_duration_count[5m])).
    pub query: String,
    /// Evaluate once at the window end instead of over the window.
    #[serde(default)]
    pub instant: bool,
    /// Range step, e.g. "30s", "5m". Default: about 120 points across the window.
    #[serde(default)]
    pub step: Option<String>,
    /// Include the data points for each series (otherwise only min/avg/max/last).
    #[serde(default)]
    pub include_points: bool,
    /// Maximum series to return (default 20, max 100).
    #[serde(default)]
    pub max_series: Option<u64>,
    #[serde(flatten)]
    pub time: TimeArgs,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct MetricsResult {
    pub query: String,
    /// vector, matrix, scalar or string.
    pub result_type: String,
    pub series_total: usize,
    pub series: Vec<SeriesSummary>,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq)]
pub struct SeriesSummary {
    pub labels: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg: Option<f64>,
    pub point_count: usize,
    /// [unix_seconds, value] pairs, thinned to at most 60.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub points: Vec<(f64, f64)>,
}

impl Trim for MetricsResult {
    fn trim(&mut self) -> bool {
        if let Some(s) = self.series.iter_mut().find(|s| s.points.len() > 10) {
            let step = 2;
            s.points = s.points.iter().step_by(step).copied().collect();
            return true;
        }
        let n = self.series.len();
        n > 3 && keep(&mut self.series, n * 2 / 3)
    }
}

fn prom_value(v: &serde_json::Value) -> Option<(f64, f64)> {
    let arr = v.as_array()?;
    let t = arr.first()?.as_f64()?;
    let raw = arr.get(1)?.as_str()?;
    let value = raw.parse::<f64>().ok()?;
    value.is_finite().then_some((t, value))
}

pub fn shape_prom(
    query: &str,
    data: PromData,
    include_points: bool,
    max_series: usize,
) -> MetricsResult {
    let mut series = Vec::new();
    let items = data.result.as_array().cloned().unwrap_or_default();
    let total = items.len();
    for item in items.iter().take(max_series) {
        let labels: BTreeMap<String, String> = item
            .get("metric")
            .and_then(|m| m.as_object())
            .map(|m| {
                m.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let points: Vec<(f64, f64)> = match (item.get("values"), item.get("value")) {
            (Some(vs), _) => vs
                .as_array()
                .map(|a| a.iter().filter_map(prom_value).collect())
                .unwrap_or_default(),
            (None, Some(v)) => prom_value(v).into_iter().collect(),
            _ => Vec::new(),
        };
        let vals: Vec<f64> = points.iter().map(|p| p.1).collect();
        let summary = |f: fn(&[f64]) -> f64| (!vals.is_empty()).then(|| round_sig(f(&vals)));
        let thinned = if include_points && points.len() > 60 {
            let step = points.len().div_ceil(60);
            points.iter().step_by(step).copied().collect()
        } else if include_points {
            points.clone()
        } else {
            Vec::new()
        };
        series.push(SeriesSummary {
            labels,
            last: vals.last().copied().map(round_sig),
            min: summary(|v| v.iter().copied().fold(f64::INFINITY, f64::min)),
            max: summary(|v| v.iter().copied().fold(f64::NEG_INFINITY, f64::max)),
            avg: summary(|v| v.iter().sum::<f64>() / v.len() as f64),
            point_count: points.len(),
            points: thinned,
        });
    }
    if data.result_type == "scalar" || data.result_type == "string" {
        if let Some((t, v)) = prom_value(&data.result) {
            series.push(SeriesSummary {
                labels: BTreeMap::new(),
                last: Some(round_sig(v)),
                min: None,
                max: None,
                avg: None,
                point_count: 1,
                points: if include_points {
                    vec![(t, v)]
                } else {
                    Vec::new()
                },
            });
        }
    }
    MetricsResult {
        query: query.to_string(),
        result_type: data.result_type,
        series_total: total.max(series.len()),
        series,
    }
}

/// Round to 4 significant digits for readability.
fn round_sig(v: f64) -> f64 {
    if v == 0.0 || !v.is_finite() {
        return v;
    }
    let mag = v.abs().log10().floor() as i32;
    let factor = 10f64.powi(3 - mag);
    (v * factor).round() / factor
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListMetricsArgs {
    /// Only metric names containing this text (case-insensitive).
    #[serde(default)]
    pub contains: Option<String>,
    /// How many names to return (default 100, max 500).
    #[serde(default)]
    pub limit: Option<u64>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct MetricNames {
    pub names: Vec<String>,
    pub matched: usize,
}

impl Trim for MetricNames {
    fn trim(&mut self) -> bool {
        let n = self.names.len();
        n > 10 && keep(&mut self.names, n / 2)
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MetricLabelsArgs {
    /// Limit to series of this metric name.
    #[serde(default)]
    pub metric: Option<String>,
    /// List values of this label. Without it, list label names.
    #[serde(default)]
    pub label: Option<String>,
    /// Only names or values containing this text.
    #[serde(default)]
    pub contains: Option<String>,
    /// How many to return (default 100, max 500).
    #[serde(default)]
    pub limit: Option<u64>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct MetricLabels {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metric: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Label names, or the values of `label`.
    pub items: Vec<String>,
    pub matched: usize,
}

impl Trim for MetricLabels {
    fn trim(&mut self) -> bool {
        let n = self.items.len();
        n > 10 && keep(&mut self.items, n / 2)
    }
}

fn filter_names(names: Vec<String>, contains: Option<&str>, limit: usize) -> (Vec<String>, usize) {
    let needle = contains
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty());
    let mut matched: Vec<String> = names
        .into_iter()
        .filter(|n| needle.as_ref().is_none_or(|c| n.to_lowercase().contains(c)))
        .collect();
    matched.sort();
    let count = matched.len();
    matched.truncate(limit);
    (matched, count)
}

fn metric_selector(metric: &str) -> Result<String, ToolError> {
    let ok = !metric.is_empty()
        && metric
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':' || c == '.')
        && !metric.starts_with(|c: char| c.is_ascii_digit());
    if !ok {
        return Err(ToolError::Input(format!(
            "`{metric}` is not a valid metric name"
        )));
    }
    Ok(format!("{{__name__=\"{metric}\"}}"))
}

// ── get_link ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    Explore,
    Trace,
    Service,
    Metrics,
    SavedQuery,
    Deploys,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetLinkArgs {
    pub kind: LinkKind,
    /// explore: "logs" or "spans" (default spans).
    #[serde(default)]
    pub signal: Option<SignalKind>,
    /// explore: field to group by.
    #[serde(default)]
    pub group_by: Option<String>,
    /// trace: trace ID; optional span_id.
    #[serde(default)]
    pub trace_id: Option<String>,
    #[serde(default)]
    pub span_id: Option<String>,
    /// metrics: PromQL.
    #[serde(default)]
    pub promql: Option<String>,
    /// saved_query: saved query ID.
    #[serde(default)]
    pub saved_query_id: Option<String>,
    /// explore filters/search/time, and `service` for kind=service.
    #[serde(flatten)]
    pub query: QueryArgs,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct LinkOut {
    pub url: String,
}

impl Trim for LinkOut {
    fn trim(&mut self) -> bool {
        false
    }
}

// ── Tools ─────────────────────────────────────────────────────────────────

fn clamp(v: Option<u64>, default: u64, max: u64) -> u64 {
    v.unwrap_or(default).clamp(1, max)
}

impl RushMcp {
    async fn explore_logs(
        &self,
        key: Option<&ClientKey>,
        tool: &str,
        q: &Query,
        rows: u64,
        group_by: Option<&str>,
    ) -> Result<ExploreResponse<LogRow>, ToolError> {
        let interval = bucket_for(&q.window, 24);
        let req = ExploreRequest {
            signal: SignalKind::Logs,
            time_range: TimeRange::from(&q.window),
            filters: &q.filters,
            search: q.search.as_deref(),
            limit: rows.max(1),
            interval,
            group_by,
            include_rows: rows > 0,
            include_summary: true,
        };
        Ok(self.state.client.explore(key, tool, &req).await?)
    }

    pub(crate) async fn do_search_logs(
        &self,
        key: Option<&ClientKey>,
        tool: &'static str,
        q: Query,
        samples: u64,
        group_by: Option<String>,
    ) -> Result<Envelope<LogSearch>, ToolError> {
        let resp = self
            .explore_logs(key, tool, &q, samples, group_by.as_deref())
            .await?;
        let partial = !resp.errors.is_empty();
        let result = shape_log_search(resp, samples as usize);
        let errors = result
            .by_severity
            .iter()
            .find(|k| k.key == "error")
            .map(|k| k.count)
            .unwrap_or(0);
        let top_service = result
            .by_service
            .first()
            .map(|k| format!("; top service {} ({})", k.key, thousands(k.count)))
            .unwrap_or_default();
        let links = self.links(key).await;
        let mut env = Envelope::new(
            format!(
                "{} logs, {} at error level{top_service}.",
                thousands(result.total),
                thousands(errors)
            ),
            result,
        )
        .window(&q.window)
        .link(
            "explore",
            links.explore(
                Signal::Logs,
                &query_text(&q.filters, q.search.as_deref()),
                &q.window,
                group_by.as_deref(),
            ),
        );
        if env.result.total == 0 {
            env = env.hint(empty_hint(SignalKind::Logs));
        }
        if partial {
            env = env.hint(Hint::new(
                "Rush couldn't compute the summary in time; counts and breakdowns may be missing.",
            ));
        }
        Ok(env)
    }

    pub(crate) async fn do_search_spans(
        &self,
        key: Option<&ClientKey>,
        tool: &'static str,
        q: Query,
        samples: u64,
        group_by: Option<String>,
    ) -> Result<Envelope<SpanSearch>, ToolError> {
        let interval = bucket_for(&q.window, 24);
        let explore = ExploreRequest {
            signal: SignalKind::Spans,
            time_range: TimeRange::from(&q.window),
            filters: &q.filters,
            search: q.search.as_deref(),
            limit: samples.max(1),
            interval,
            group_by: group_by.as_deref(),
            include_rows: samples > 0,
            include_summary: true,
        };
        let latency = TimeseriesRequest {
            time_range: TimeRange::from(&q.window),
            filters: &q.filters,
            interval: bucket_for(&q.window, 12),
            group_by: None,
            search: q.search.as_deref(),
        };
        let client = &self.state.client;
        let (resp, ts) = tokio::join!(
            client.explore::<SpanRow>(key, tool, &explore),
            client.post::<_, TimeseriesResponse>(key, tool, "/api/v1/query/timeseries", &latency),
        );
        let resp = resp?;
        let partial = !resp.errors.is_empty();
        let ts = ts.map(|t| t.buckets).unwrap_or_default();
        let result = shape_span_search(resp, &ts, samples as usize);
        let links = self.links(key).await;
        let mut env = Envelope::new(
            format!(
                "{} spans, {} errors ({}%), p95 ≈ {} ms.",
                thousands(result.total),
                thousands(result.errors),
                result.error_rate_pct,
                result.latency_ms_approx.p95
            ),
            result,
        )
        .window(&q.window)
        .link(
            "explore",
            links.explore(
                Signal::Spans,
                &query_text(&q.filters, q.search.as_deref()),
                &q.window,
                group_by.as_deref(),
            ),
        );
        if env.result.total == 0 {
            env = env.hint(empty_hint(SignalKind::Spans));
        }
        if partial {
            env = env.hint(Hint::new(
                "Rush couldn't compute the summary in time; counts and breakdowns may be missing.",
            ));
        }
        Ok(env)
    }
}

#[tool_router(router = core_router, vis = "pub(crate)")]
impl RushMcp {
    #[tool(
        description = "Start here. Returns the tenant and identity behind the API key, server time (UTC), enabled Rush features and toolsets, and how many logs and spans arrived in the last hour.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    pub(crate) async fn get_context(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<Context>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("get_context", async {
            let key = key.as_ref();
            let c = &self.state.client;
            let hour = TimeArgs::default().resolve()?;
            let count_req = |signal| ExploreRequest {
                signal,
                time_range: TimeRange::from(&hour),
                filters: &[],
                search: None,
                limit: 1,
                interval: "5m",
                group_by: None,
                include_rows: false,
                include_summary: true,
            };
            let (logs_req, spans_req) = (count_req(SignalKind::Logs), count_req(SignalKind::Spans));
            let (me, features, logs, spans) = tokio::join!(
                c.get::<WhoAmI>(key, "get_context", "/api/v1/whoami", &[]),
                c.get::<serde_json::Value>(key, "get_context", "/api/v1/features", &[]),
                c.explore::<LogRow>(key, "get_context", &logs_req),
                c.explore::<SpanRow>(key, "get_context", &spans_req),
            );
            let mut hints = Vec::new();
            let identity = match me {
                Ok(me) => Some(me),
                Err(e) if e.is_not_found() => {
                    hints.push(Hint::new("This Rush version has no /api/v1/whoami; tenant and role are unknown. Upgrade Rush for full context."));
                    None
                }
                Err(e) => return Err(e.into()),
            };
            let tenant = identity.as_ref().map(|m| m.tenant_id.clone()).filter(|t| !t.is_empty());
            let result = Context {
                server_time: crate::time::rfc3339(chrono::Utc::now()),
                tenant: tenant.clone(),
                identity,
                web_url: self.state.links.with_tenant(None).deploys().trim_end_matches("/deploys").to_string(),
                toolsets: self.state.toolsets.iter().map(|t| t.name().to_string()).collect(),
                features: features.unwrap_or(serde_json::Value::Null),
                last_hour: SignalCounts { logs: logs.ok().map(|r| r.count.value), spans: spans.ok().map(|r| r.count.value) },
            };
            let summary = format!(
                "Tenant {}; last hour: {} logs, {} spans.",
                tenant.as_deref().unwrap_or("unknown"),
                result.last_hour.logs.map(thousands).unwrap_or_else(|| "?".into()),
                result.last_hour.spans.map(thousands).unwrap_or_else(|| "?".into()),
            );
            let mut env = Envelope::new(summary, result);
            for h in hints {
                env = env.hint(h);
            }
            Ok(env)
        })
        .await
    }

    #[tool(
        description = "Resolve a time expression to an exact UTC window. Accepts `last` (\"15m\", \"24h\", \"7d\") or `from`/`to` as RFC3339, \"YYYY-MM-DD HH:MM\" (UTC), Unix seconds, \"now-2h\", \"today\" or \"yesterday\".",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn resolve_time(
        &self,
        Parameters(args): Parameters<TimeArgs>,
    ) -> Result<Json<Envelope<ResolvedTime>>, CallToolResult> {
        self.run("resolve_time", async {
            let w = args.resolve()?;
            let result = ResolvedTime {
                from: w.from_rfc3339(),
                to: w.to_rfc3339(),
                duration_minutes: w.duration().num_minutes(),
                relative: w.relative_minutes.is_some(),
                suggested_interval: bucket_for(&w, 60).to_string(),
            };
            Ok(Envelope::new(format!("{} to {}", result.from, result.to), result).window(&w))
        })
        .await
    }

    #[tool(
        description = "List field names for logs or spans: the built-in fields plus attribute keys found in a sample of recent records. Use before filtering so field names are exact.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn list_fields(
        &self,
        Parameters(args): Parameters<ListFieldsArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<FieldList>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("list_fields", async {
            let key = key.as_ref();
            let window = args.time.resolve()?;
            let mut filters = Vec::new();
            if let Some(s) = args
                .service
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                filters.push(Filter::eq("service_name", s));
            }
            let mut counts: HashMap<String, u64> = HashMap::new();
            let sampled = match args.signal {
                SignalKind::Spans => {
                    let req = WideQueryRequest {
                        time_range: TimeRange::from(&window),
                        filters: &filters,
                        limit: 100,
                        search: None,
                    };
                    let resp: WideQueryResponse = self
                        .state
                        .client
                        .post(key, "list_fields", "/api/v1/query", &req)
                        .await?;
                    for row in &resp.rows {
                        if let Ok(serde_json::Value::Object(map)) =
                            serde_json::from_str::<serde_json::Value>(&row.attributes)
                        {
                            for k in map.keys() {
                                *counts.entry(format!("attributes.{k}")).or_default() += 1;
                            }
                        }
                    }
                    resp.rows.len()
                }
                SignalKind::Logs => {
                    let req = LogsRequest {
                        time_range: TimeRange::from(&window),
                        filters: &filters,
                        limit: 100,
                        slim: false,
                    };
                    let resp: LogsResponse = self
                        .state
                        .client
                        .post(key, "list_fields", "/api/v1/logs", &req)
                        .await?;
                    for row in &resp.rows {
                        let LogRecord {
                            resource_attributes,
                            log_attributes,
                            ..
                        } = row;
                        for k in resource_attributes.keys() {
                            *counts.entry(format!("resource.{k}")).or_default() += 1;
                        }
                        for k in log_attributes.keys() {
                            *counts.entry(format!("log.{k}")).or_default() += 1;
                        }
                    }
                    resp.rows.len()
                }
            };
            let needle = args
                .contains
                .as_deref()
                .map(|c| c.trim().to_lowercase())
                .filter(|c| !c.is_empty());
            let matches = |name: &str| {
                needle
                    .as_ref()
                    .is_none_or(|c| name.to_lowercase().contains(c))
            };
            let standard: Vec<FieldDoc> = match args.signal {
                SignalKind::Spans => SPAN_FIELDS,
                SignalKind::Logs => LOG_FIELDS,
            }
            .iter()
            .filter(|f| matches(f.name))
            .cloned()
            .collect();
            let mut attributes: Vec<KeyCount> = counts
                .into_iter()
                .filter(|(k, _)| matches(k))
                .map(|(key, count)| KeyCount { key, count })
                .collect();
            attributes.sort_by(|a, b| b.count.cmp(&a.count).then(a.key.cmp(&b.key)));
            attributes.truncate(150);
            let result = FieldList {
                signal: args.signal,
                standard,
                attributes,
                sampled_records: sampled,
            };
            let mut env = Envelope::new(
                format!(
                    "{} built-in and {} attribute fields (from {} sampled {}).",
                    result.standard.len(),
                    result.attributes.len(),
                    sampled,
                    kind_name(args.signal)
                ),
                result,
            )
            .window(&window);
            if sampled == 0 {
                env = env.hint(empty_hint(args.signal));
            }
            Ok(env)
        })
        .await
    }

    #[tool(
        description = "Most common values of one log or span field in a window, with counts. Supports the same filters as search_logs/search_spans.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn list_field_values(
        &self,
        Parameters(args): Parameters<FieldValuesArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<FieldValues>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("list_field_values", async {
            let key = key.as_ref();
            let field = args.field.trim().to_string();
            if field.is_empty() || field.len() > 128 {
                return Err(ToolError::Input("field must be 1 to 128 characters".into()));
            }
            let mut q = args.query.resolve()?;
            if let Some(c) = args
                .contains
                .as_deref()
                .map(str::trim)
                .filter(|c| !c.is_empty())
            {
                q.filters.push(Filter {
                    field: field.clone(),
                    op: Op::Like,
                    value: serde_json::Value::String(format!("%{c}%")),
                });
            }
            let limit = clamp(args.limit, 20, 100);
            let req = GroupRequest {
                time_range: TimeRange::from(&q.window),
                filters: &q.filters,
                group_by: [&field],
                limit,
                search: q.search.as_deref(),
            };
            let path = match args.signal {
                SignalKind::Spans => "/api/v1/query/group",
                SignalKind::Logs => "/api/v1/logs/group",
            };
            let resp: GroupResponse = self
                .state
                .client
                .post(key, "list_field_values", path, &req)
                .await?;
            let values = resp.pairs(&field);
            let links = self.links(key).await;
            let mut env = Envelope::new(
                format!(
                    "{} values of {field}{}.",
                    values.len(),
                    values
                        .first()
                        .map(|v| format!("; most common {} ({})", v.key, thousands(v.count)))
                        .unwrap_or_default()
                ),
                FieldValues {
                    field: field.clone(),
                    values,
                },
            )
            .window(&q.window)
            .link(
                "explore",
                links.explore(
                    signal_link(args.signal),
                    &query_text(&q.filters, q.search.as_deref()),
                    &q.window,
                    Some(&field),
                ),
            );
            if env.result.values.is_empty() {
                env = env.hint(
                    Hint::new(format!("No values for `{field}`."))
                        .action("Check the field name with list_fields")
                        .action("Widen the window or remove filters"),
                );
            }
            Ok(env)
        })
        .await
    }

    #[tool(
        description = "Search logs. Returns the total, counts by severity and service, a count series, optional group counts, and newest sample lines (with a `ref` for get_log_record/get_log_context).",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn search_logs(
        &self,
        Parameters(args): Parameters<SearchLogsArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<LogSearch>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("search_logs", async {
            let q = args.query.resolve()?;
            let samples = args.samples.unwrap_or(10).min(50);
            self.do_search_logs(
                key.as_ref(),
                "search_logs",
                q,
                samples,
                args.group_by.clone(),
            )
            .await
        })
        .await
    }

    #[tool(
        description = "Search APM spans. Returns the total, error count and rate, approximate latency percentiles, counts by service and HTTP status class, a count series, optional group counts, and newest sample spans with trace IDs.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn search_spans(
        &self,
        Parameters(args): Parameters<SearchSpansArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<SpanSearch>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("search_spans", async {
            let mut q = args.query.resolve()?;
            if args.errors_only {
                q.filters.push(Filter {
                    field: "error".into(),
                    op: Op::Eq,
                    value: serde_json::json!(1),
                });
            }
            if let Some(min) = args.min_duration_ms.filter(|m| *m > 0.0) {
                q.filters.push(Filter {
                    field: "duration_ns".into(),
                    op: Op::Gte,
                    value: serde_json::json!((min * 1_000_000.0) as u64),
                });
            }
            let samples = args.samples.unwrap_or(10).min(50);
            self.do_search_spans(
                key.as_ref(),
                "search_spans",
                q,
                samples,
                args.group_by.clone(),
            )
            .await
        })
        .await
    }

    #[tool(
        description = "Count logs or spans grouped by a field (spans include error counts and rates), over time, or both (spans only). Set group_by, over_time, or both.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn aggregate(
        &self,
        Parameters(args): Parameters<AggregateArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<Aggregation>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("aggregate", async {
            let key = key.as_ref();
            let q = args.query.resolve()?;
            let group_by = args.group_by.as_deref().map(str::trim).filter(|g| !g.is_empty()).map(str::to_string);
            let limit = clamp(args.limit, 10, 50);
            let c = &self.state.client;
            let tr = || TimeRange::from(&q.window);
            let mut result = Aggregation { signal: Some(args.signal), group_by: group_by.clone(), ..Default::default() };
            match (args.signal, group_by.as_deref(), args.over_time) {
                (_, None, false) => return Err(ToolError::Input("set group_by, over_time, or both".into())),
                (SignalKind::Logs, Some(_), true) => {
                    return Err(ToolError::Input(
                        "grouped time series aren't available for logs; use group_by without over_time, or over_time without group_by".into(),
                    ));
                }
                (SignalKind::Spans, Some(field), false) => {
                    let mut err_filters = q.filters.clone();
                    err_filters.push(Filter { field: "error".into(), op: Op::Eq, value: serde_json::json!(1) });
                    let all = GroupRequest { time_range: tr(), filters: &q.filters, group_by: [field], limit, search: q.search.as_deref() };
                    let errs = GroupRequest { time_range: tr(), filters: &err_filters, group_by: [field], limit: 1000, search: q.search.as_deref() };
                    let (a, e) = tokio::join!(
                        c.post::<_, GroupResponse>(key, "aggregate", "/api/v1/query/group", &all),
                        c.post::<_, GroupResponse>(key, "aggregate", "/api/v1/query/group", &errs),
                    );
                    result.groups = join_error_groups(a?.pairs(field), e.map(|r| r.pairs(field)).unwrap_or_default());
                }
                (SignalKind::Logs, Some(field), false) => {
                    let req = GroupRequest { time_range: tr(), filters: &q.filters, group_by: [field], limit, search: q.search.as_deref() };
                    let resp: GroupResponse = c.post(key, "aggregate", "/api/v1/logs/group", &req).await?;
                    result.groups = resp.pairs(field).into_iter().map(|g| GroupRow { key: g.key, count: g.count, errors: None, error_rate_pct: None }).collect();
                }
                (SignalKind::Spans, field, true) => {
                    let req = TimeseriesRequest { time_range: tr(), filters: &q.filters, interval: bucket_for(&q.window, 48), group_by: field, search: q.search.as_deref() };
                    let resp: TimeseriesResponse = c.post(key, "aggregate", "/api/v1/query/timeseries", &req).await?;
                    if field.is_some() {
                        result.group_series = group_series_from(resp.buckets, limit as usize);
                    } else {
                        result.series = compress(
                            resp.buckets.into_iter().map(|b| Point { t: b.bucket, count: b.count, errors: Some(b.error_count) }).collect(),
                            48,
                        );
                    }
                }
                (SignalKind::Logs, None, true) => {
                    // The Explore summary histogram is the one the UI uses; it is
                    // more reliable than the standalone logs histogram endpoint.
                    let req = ExploreRequest {
                        signal: SignalKind::Logs,
                        time_range: tr(),
                        filters: &q.filters,
                        search: q.search.as_deref(),
                        limit: 1,
                        interval: bucket_for(&q.window, 48),
                        group_by: None,
                        include_rows: false,
                        include_summary: true,
                    };
                    let resp = c.explore::<LogRow>(key, "aggregate", &req).await?;
                    result.series = compress(
                        resp.summary.histogram.into_iter().map(|b| Point { t: b.bucket, count: b.count, errors: None }).collect(),
                        48,
                    );
                }
            }
            let total: u64 = result.groups.iter().map(|g| g.count).sum::<u64>()
                + result.series.iter().map(|p| p.count).sum::<u64>()
                + result.group_series.iter().map(|g| g.total).sum::<u64>();
            let links = self.links(key).await;
            let summary = match (&group_by, result.groups.first(), result.group_series.first()) {
                (Some(g), Some(first), _) => format!("{} groups by {g}; largest {} ({}).", result.groups.len(), first.key, thousands(first.count)),
                (Some(g), None, Some(first)) => format!("{} series by {g}; largest {} ({}).", result.group_series.len(), first.key, thousands(first.total)),
                _ => format!("{} {} over {} points.", thousands(total), kind_name(args.signal), result.series.len()),
            };
            let mut env = Envelope::new(summary, result)
                .window(&q.window)
                .link("explore", links.explore(signal_link(args.signal), &query_text(&q.filters, q.search.as_deref()), &q.window, group_by.as_deref()));
            if total == 0 {
                env = env.hint(empty_hint(args.signal));
            }
            Ok(env)
        })
        .await
    }

    #[tool(
        description = "Summarize one trace by ID or Rush trace URL: duration, span count, time per service, error spans with exception messages, the critical path, and a depth-limited span tree.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn get_trace(
        &self,
        Parameters(args): Parameters<GetTraceArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<TraceSummary>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("get_trace", async {
            let key = key.as_ref();
            let id = trace_id_from(&args.trace).filter(|id| id.len() == 32).ok_or_else(|| {
                ToolError::Input(format!("`{}` is not a 32-hex trace ID or a Rush trace URL", args.trace))
            })?;
            let trace: TraceResponse = self.state.client.get(key, "get_trace", &format!("/api/v1/traces/{id}"), &[]).await?;
            let max = clamp(args.max_spans, 40, 200) as usize;
            let counted: usize = {
                fn count(n: &[SpanNode]) -> usize {
                    n.iter().map(|s| 1 + count(&s.children)).sum()
                }
                count(&trace.spans)
            };
            let missing = trace.span_count.saturating_sub(counted);
            let result = shape_trace(trace, args.focus_span_id.as_deref().map(str::trim).filter(|s| !s.is_empty()), max)?;
            let links = self.links(key).await;
            let mut env = Envelope::new(
                format!(
                    "Trace {} took {} ms across {} spans in {} services; {} error spans.",
                    result.trace_id, result.duration_ms, result.span_count, result.services.len(), result.errors.len()
                ),
                result,
            )
            .link("trace", links.trace(&id, args.focus_span_id.as_deref()));
            if missing > 0 {
                env = env.hint(Hint::new(format!("{missing} spans have parents that aren't in this trace, so they are not in the tree or totals.")));
            }
            Ok(env)
        })
        .await
    }

    #[tool(
        description = "List services with request count, errors, error rate and p50/p95/p99 latency, busiest first.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    pub(crate) async fn list_services(
        &self,
        Parameters(args): Parameters<ListServicesArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<ServiceList>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("list_services", async {
            let key = key.as_ref();
            let window = args.time.resolve()?;
            let (minutes, note) = minutes_ending_now(&window);
            let graph: ServiceGraph = self
                .state
                .client
                .get(
                    key,
                    "list_services",
                    "/api/v1/services/graph",
                    &[("minutes", minutes.to_string())],
                )
                .await?;
            let needle = args
                .contains
                .as_deref()
                .map(|c| c.trim().to_lowercase())
                .filter(|c| !c.is_empty());
            let mut rows: Vec<ServiceRow> = graph
                .nodes
                .iter()
                .filter(|n| {
                    needle
                        .as_ref()
                        .is_none_or(|c| n.service_name.to_lowercase().contains(c))
                })
                .map(service_row)
                .collect();
            rows.sort_by(|a, b| b.requests.cmp(&a.requests));
            let total = rows.len();
            rows.truncate(clamp(args.limit, 25, 200) as usize);
            let worst = rows
                .iter()
                .filter(|r| r.requests > 0)
                .max_by(|a, b| a.error_rate_pct.total_cmp(&b.error_rate_pct));
            let summary = format!(
                "{total} services{}.",
                worst
                    .filter(|w| w.errors > 0)
                    .map(|w| format!("; highest error rate {} ({}%)", w.service, w.error_rate_pct))
                    .unwrap_or_default()
            );
            let mut env = Envelope::new(
                summary,
                ServiceList {
                    services: rows,
                    total,
                },
            )
            .window(&window);
            if let Some(n) = note {
                env = env.hint(Hint::new(n));
            }
            if total == 0 {
                env = env.hint(
                    Hint::new("No services had spans in this window.").action("Widen the window"),
                );
            }
            Ok(env)
        })
        .await
    }

    #[tool(
        description = "Health of one service: totals and latency, top endpoints, top error groups, services it calls and is called by, and recent deploys.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn get_service(
        &self,
        Parameters(args): Parameters<GetServiceArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<ServiceDetail>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("get_service", async {
            let key = key.as_ref();
            let service = args.service.trim().to_string();
            if service.is_empty() {
                return Err(ToolError::Input("service is required".into()));
            }
            let window = args.time.resolve()?;
            let (minutes, note) = minutes_ending_now(&window);
            let m = minutes.to_string();
            let c = &self.state.client;
            let svc = [("service", service.clone()), ("minutes", m.clone())];
            let errs = [
                ("service", service.clone()),
                ("minutes", m.clone()),
                ("mode", "endpoint".to_string()),
            ];
            let deploy_q = [
                ("service_name", service.clone()),
                ("from", window.from_rfc3339()),
                ("to", window.to_rfc3339()),
            ];
            let graph_q = [("minutes", m.clone())];
            let (endpoints, errors, graph, deploys) = tokio::join!(
                c.get::<EndpointsResponse>(key, "get_service", "/api/v1/services/endpoints", &svc),
                c.get::<ErrorsResponse>(key, "get_service", "/api/v1/services/errors", &errs),
                c.get::<ServiceGraph>(key, "get_service", "/api/v1/services/graph", &graph_q),
                c.get::<api::DeploysResponse>(key, "get_service", "/api/v1/deploys", &deploy_q),
            );
            let graph = graph?;
            let totals = graph
                .nodes
                .iter()
                .find(|n| n.service_name == service)
                .map(service_row);
            let edge = |e: &api::GraphEdge, other: &str| EdgeStat {
                service: other.to_string(),
                requests: e.request_count,
                errors: e.error_count,
                avg_ms: round2(e.avg_duration_ms),
            };
            let mut calls: Vec<EdgeStat> = graph
                .edges
                .iter()
                .filter(|e| e.source == service && e.target != service)
                .map(|e| edge(e, &e.target))
                .collect();
            let mut called_by: Vec<EdgeStat> = graph
                .edges
                .iter()
                .filter(|e| e.target == service && e.source != service)
                .map(|e| edge(e, &e.source))
                .collect();
            calls.sort_by(|a, b| b.requests.cmp(&a.requests));
            called_by.sort_by(|a, b| b.requests.cmp(&a.requests));
            let result = ServiceDetail {
                service: service.clone(),
                totals,
                endpoints: endpoints?
                    .endpoints
                    .into_iter()
                    .take(10)
                    .map(|e| EndpointStat {
                        endpoint: if e.endpoint.is_empty() {
                            format!("{} {}", e.method, e.path).trim().to_string()
                        } else {
                            e.endpoint
                        },
                        requests: e.req,
                        errors: e.errors,
                        p95_ms: round2(e.p95_ms),
                        p99_ms: round2(e.p99_ms),
                    })
                    .collect(),
                error_groups: errors?
                    .groups
                    .into_iter()
                    .take(10)
                    .map(|g| ErrorStat {
                        key: g.key,
                        status_code: g.status_code,
                        count: g.count,
                        example: clip(&g.example, 200),
                        last_seen: g.last_seen,
                    })
                    .collect(),
                calls,
                called_by,
                recent_deploys: deploys
                    .map(|d| d.deploys.into_iter().take(5).collect())
                    .unwrap_or_default(),
            };
            let links = self.links(key).await;
            let summary = match &result.totals {
                Some(t) => format!(
                    "{service}: {} requests, {}% errors, p95 {} ms.",
                    thousands(t.requests),
                    t.error_rate_pct,
                    t.p95_ms
                ),
                None => format!("{service}: no spans in this window."),
            };
            let no_data = result.totals.is_none();
            let mut env = Envelope::new(summary, result)
                .window(&window)
                .link("service", links.service(&service, &window));
            if let Some(n) = note {
                env = env.hint(Hint::new(n));
            }
            if no_data {
                env = env.hint(
                    Hint::new(format!("No spans for `{service}`."))
                        .action("Check the exact name with list_services")
                        .action("Widen the window"),
                );
            }
            Ok(env)
        })
        .await
    }

    #[tool(
        description = "Run a PromQL query over a window (or instantly at its end). Each series is summarized as min/avg/max/last; set include_points for the data points.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn query_metrics(
        &self,
        Parameters(args): Parameters<QueryMetricsArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<MetricsResult>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("query_metrics", async {
            let key = key.as_ref();
            let query = args.query.trim().to_string();
            if query.is_empty() || query.len() > 4_096 {
                return Err(ToolError::Input("query must be 1 to 4096 characters".into()));
            }
            let window = args.time.resolve()?;
            let max_series = clamp(args.max_series, 20, 100) as usize;
            let c = &self.state.client;
            let env: PromEnvelope<PromData> = if args.instant {
                c.get(key, "query_metrics", "/prom/api/v1/query", &[("query", query.clone()), ("time", window.to.timestamp().to_string())]).await?
            } else {
                let window_secs = window.duration().num_seconds().max(1);
                let step = match args.step.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    Some(s) => parse_duration(s).map_err(ToolError::Input)?.num_seconds(),
                    None => (window_secs / 120).max(15),
                };
                if step < 1 {
                    return Err(ToolError::Input("step must be at least 1s".into()));
                }
                if window_secs / step > 11_000 {
                    return Err(ToolError::Input("that step gives more than 11,000 points; use a larger step".into()));
                }
                c.get(
                    key,
                    "query_metrics",
                    "/prom/api/v1/query_range",
                    &[
                        ("query", query.clone()),
                        ("start", window.from.timestamp().to_string()),
                        ("end", window.to.timestamp().to_string()),
                        ("step", step.to_string()),
                    ],
                )
                .await?
            };
            let result = shape_prom(&query, env.data, args.include_points, max_series);
            let links = self.links(key).await;
            let summary = match result.series.first() {
                Some(s) if result.series_total == 1 => format!("1 series; last {}.", s.last.map(|v| v.to_string()).unwrap_or_else(|| "n/a".into())),
                _ => format!("{} series ({} shown).", result.series_total, result.series.len()),
            };
            let empty = result.series.is_empty();
            let mut env = Envelope::new(summary, result).window(&window).link("metrics", links.metrics(&query, &window));
            if empty {
                env = env.hint(
                    Hint::new("The query returned no series.")
                        .action("Check metric names with list_metrics and labels with list_metric_labels")
                        .action("Widen the window"),
                );
            }
            Ok(env)
        })
        .await
    }

    #[tool(
        description = "List metric names seen in the last hour, optionally filtered by a substring.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn list_metrics(
        &self,
        Parameters(args): Parameters<ListMetricsArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<MetricNames>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("list_metrics", async {
            let resp: PromEnvelope<Vec<String>> = self
                .state
                .client
                .get(
                    key.as_ref(),
                    "list_metrics",
                    "/prom/api/v1/label/__name__/values",
                    &[],
                )
                .await?;
            let (names, matched) = filter_names(
                resp.data,
                args.contains.as_deref(),
                clamp(args.limit, 100, 500) as usize,
            );
            let mut env = Envelope::new(
                format!("{matched} metric names match ({} shown).", names.len()),
                MetricNames { names, matched },
            );
            if matched == 0 {
                env = env.hint(Hint::new(
                    "No metric names matched. Rush lists names seen in the last hour.",
                ));
            }
            Ok(env)
        })
        .await
    }

    #[tool(
        description = "List metric label names, or the values of one label, optionally for one metric. Use before writing PromQL selectors.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn list_metric_labels(
        &self,
        Parameters(args): Parameters<MetricLabelsArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<MetricLabels>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("list_metric_labels", async {
            let metric = args
                .metric
                .as_deref()
                .map(str::trim)
                .filter(|m| !m.is_empty())
                .map(str::to_string);
            let label = args
                .label
                .as_deref()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string);
            let mut query = Vec::new();
            if let Some(m) = &metric {
                query.push(("match[]", metric_selector(m)?));
            }
            let path = match &label {
                Some(l) => {
                    if !l
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
                    {
                        return Err(ToolError::Input(format!("`{l}` is not a valid label name")));
                    }
                    format!("/prom/api/v1/label/{l}/values")
                }
                None => "/prom/api/v1/labels".to_string(),
            };
            let resp: PromEnvelope<Vec<String>> = self
                .state
                .client
                .get(key.as_ref(), "list_metric_labels", &path, &query)
                .await?;
            let (items, matched) = filter_names(
                resp.data,
                args.contains.as_deref(),
                clamp(args.limit, 100, 500) as usize,
            );
            let what = match &label {
                Some(l) => format!("values of {l}"),
                None => "label names".into(),
            };
            Ok(Envelope::new(
                format!("{matched} {what} ({} shown).", items.len()),
                MetricLabels {
                    metric,
                    label,
                    items,
                    matched,
                },
            ))
        })
        .await
    }

    #[tool(
        description = "Build a Rush UI link for an Explore query, trace, service, metrics query, saved query or the deploys page, to share with the user.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn get_link(
        &self,
        Parameters(args): Parameters<GetLinkArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<LinkOut>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("get_link", async {
            let links: Links = self.links(key.as_ref()).await;
            let q = args.query.resolve()?;
            let required = |v: &Option<String>, name: &str| {
                v.as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .ok_or_else(|| ToolError::Input(format!("{name} is required for this kind")))
            };
            let url = match args.kind {
                LinkKind::Explore => links.explore(
                    signal_link(args.signal.unwrap_or(SignalKind::Spans)),
                    &query_text(&q.filters, q.search.as_deref()),
                    &q.window,
                    args.group_by.as_deref(),
                ),
                LinkKind::Trace => {
                    let id = trace_id_from(&required(&args.trace_id, "trace_id")?)
                        .ok_or_else(|| ToolError::Input("trace_id is not a trace ID".into()))?;
                    links.trace(&id, args.span_id.as_deref())
                }
                LinkKind::Service => {
                    links.service(&required(&args.query.service, "service")?, &q.window)
                }
                LinkKind::Metrics => links.metrics(&required(&args.promql, "promql")?, &q.window),
                LinkKind::SavedQuery => {
                    links.saved_query(&required(&args.saved_query_id, "saved_query_id")?)
                }
                LinkKind::Deploys => links.deploys(),
            };
            Ok(Envelope::new(url.clone(), LinkOut { url }))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{CountBucket, ExploreCount, ExploreSummary, Facets};

    fn node(id: &str, service: &str, ns: u64, children: Vec<SpanNode>) -> SpanNode {
        SpanNode {
            span_id: id.into(),
            service_name: service.into(),
            span_name: format!("op-{id}"),
            duration_ns: ns,
            children,
            ..Default::default()
        }
    }

    #[test]
    fn trace_shape_finds_errors_critical_path_and_cuts_the_tree() {
        let mut failing = node("c", "db", 70_000_000, vec![]);
        failing.status = "STATUS_CODE_ERROR".into();
        failing.events = vec![api::SpanEvent {
            name: "exception".into(),
            attributes: serde_json::json!({"exception.type": "Timeout", "exception.message": "read timed out"}),
            ..Default::default()
        }];
        let trace = TraceResponse {
            trace_id: "t".into(),
            span_count: 4,
            duration_ns: 100_000_000,
            spans: vec![node(
                "a",
                "api",
                100_000_000,
                vec![node("b", "auth", 10_000_000, vec![]), failing],
            )],
            ..Default::default()
        };
        let s = shape_trace(trace, None, 2).unwrap();
        assert_eq!(
            s.critical_path
                .iter()
                .map(|b| b.span_id.as_str())
                .collect::<Vec<_>>(),
            ["a", "c"]
        );
        assert_eq!(s.errors.len(), 1);
        assert_eq!(
            s.errors[0].exception.as_deref(),
            Some("Timeout: read timed out")
        );
        assert_eq!(s.tree.len(), 2);
        assert!(!s.tree_complete);
        assert_eq!(s.services[0].service, "api");
    }

    #[test]
    fn trace_focus_must_exist() {
        let trace = TraceResponse {
            trace_id: "t".into(),
            spans: vec![node("a", "api", 1, vec![])],
            ..Default::default()
        };
        assert!(
            shape_trace(trace, Some("zzz"), 10)
                .unwrap_err()
                .contains("zzz")
        );
    }

    #[test]
    fn latency_is_weighted_by_bucket_counts() {
        let b = |count, p95| TimeseriesBucket {
            count,
            p50_ms: p95 / 2.0,
            p95_ms: p95,
            p99_ms: p95 * 2.0,
            ..Default::default()
        };
        let l = latency_from_buckets(&[b(90, 100.0), b(10, 1000.0)]);
        assert_eq!(l.p95, 190.0);
        assert_eq!(l.worst_bucket_p99, 2000.0);
        assert_eq!(latency_from_buckets(&[]), Latency::default());
    }

    #[test]
    fn span_search_counts_errors_from_the_histogram() {
        let resp = ExploreResponse::<SpanRow> {
            rows: vec![SpanRow {
                duration_ns: 2_500_000,
                trace_id: "t1".into(),
                ..Default::default()
            }],
            count: ExploreCount {
                value: 200,
                kind: "exact".into(),
            },
            summary: ExploreSummary {
                histogram: vec![
                    CountBucket {
                        bucket: "2026-10-18 14:00:00".into(),
                        count: 120,
                        error_count: 6,
                    },
                    CountBucket {
                        bucket: "2026-10-18 14:01:00".into(),
                        count: 80,
                        error_count: 4,
                    },
                ],
                facets: Facets::default(),
                ..Default::default()
            },
            ..Default::default()
        };
        let s = shape_span_search(resp, &[], 5);
        assert_eq!((s.total, s.errors, s.error_rate_pct), (200, 10, 5.0));
        assert_eq!(s.samples[0].duration_ms, 2.5);
    }

    #[test]
    fn log_search_trims_samples_then_bodies() {
        let rows = (0..20)
            .map(|i| LogRow {
                body: "x".repeat(2_000),
                service_name: format!("s{i}"),
                ..Default::default()
            })
            .collect();
        let resp = ExploreResponse::<LogRow> {
            rows,
            count: ExploreCount {
                value: 20,
                kind: "exact".into(),
            },
            ..Default::default()
        };
        let env = Envelope::new("t", shape_log_search(resp, 20)).fit(4_096);
        assert!(env.truncated);
        assert!(env.size() <= 4_096);
        assert!(
            env.result
                .samples
                .iter()
                .all(|s| s.body.chars().count() <= 500)
        );
    }

    #[test]
    fn error_groups_join_by_key() {
        let rows = join_error_groups(
            vec![
                KeyCount {
                    key: "a".into(),
                    count: 10,
                },
                KeyCount {
                    key: "b".into(),
                    count: 5,
                },
            ],
            vec![KeyCount {
                key: "a".into(),
                count: 2,
            }],
        );
        assert_eq!(
            rows[0],
            GroupRow {
                key: "a".into(),
                count: 10,
                errors: Some(2),
                error_rate_pct: Some(20.0)
            }
        );
        assert_eq!(rows[1].errors, Some(0));
    }

    #[test]
    fn grouped_series_keep_the_largest_groups() {
        let b = |k: &str, t: &str, c| TimeseriesBucket {
            group_key: k.into(),
            bucket: t.into(),
            count: c,
            ..Default::default()
        };
        let s = group_series_from(
            vec![
                b("x", "2", 1),
                b("y", "1", 9),
                b("x", "1", 1),
                b("z", "1", 5),
            ],
            2,
        );
        assert_eq!(
            s.iter().map(|g| g.key.as_str()).collect::<Vec<_>>(),
            ["y", "z"]
        );
    }

    #[test]
    fn prom_series_are_summarized_and_non_finite_values_skipped() {
        let data = PromData {
            result_type: "matrix".into(),
            result: serde_json::json!([
                {"metric": {"service_name": "api"}, "values": [[1.0, "1"], [2.0, "3"], [3.0, "NaN"], [4.0, "2"]]}
            ]),
        };
        let r = shape_prom("q", data, false, 10);
        let s = &r.series[0];
        assert_eq!(
            (s.min, s.max, s.last, s.avg, s.point_count),
            (Some(1.0), Some(3.0), Some(2.0), Some(2.0), 3)
        );
        assert!(s.points.is_empty());
        let vector = PromData {
            result_type: "vector".into(),
            result: serde_json::json!([{"metric": {}, "value": [5.0, "0.123456"]}]),
        };
        assert_eq!(
            shape_prom("q", vector, true, 10).series[0].last,
            Some(0.1235)
        );
    }

    #[test]
    fn metric_selectors_reject_injection() {
        assert_eq!(
            metric_selector("http_requests_total").unwrap(),
            "{__name__=\"http_requests_total\"}"
        );
        assert!(metric_selector("x\"}or{").is_err());
        assert!(metric_selector("9abc").is_err());
    }

    #[test]
    fn name_filtering_is_case_insensitive_and_counted() {
        let (names, matched) = filter_names(
            vec!["HTTP_a".into(), "http_b".into(), "cpu".into()],
            Some("http"),
            1,
        );
        assert_eq!((names, matched), (vec!["HTTP_a".to_string()], 2));
    }
}
