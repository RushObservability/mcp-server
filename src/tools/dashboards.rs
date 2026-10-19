//! `dashboards` toolset: find dashboards, read their widgets, and run a
//! widget's query the way the Rush UI does.

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
    CountBucket, Dashboard, DashboardsResponse, Filter, GroupRequest, GroupResponse, Op, PromData,
    PromEnvelope, TimeRange, TimeseriesBucket, TimeseriesRequest, TimeseriesResponse, Widget,
    query_text,
};
use crate::client::ClientKey;
use crate::envelope::{Envelope, Hint, Trim, clip};
use crate::links::id_from;
use crate::server::{RushMcp, ToolError};
use crate::time::{TimeArgs, Window, bucket_for};
use crate::tools::core::{MetricsResult, shape_prom};
use crate::tools::{keep, pop, round2};

fn strings(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

// ── Widget queries ────────────────────────────────────────────────────────

/// One query of a widget, from `query_config.queries[]` or the legacy top-level fields.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WidgetQuery {
    pub ref_id: String,
    pub source: String,
    pub filters: Vec<Filter>,
    pub group_by: Option<String>,
    pub aggregation: Option<String>,
    pub limit: Option<u64>,
    pub promql: Option<String>,
    pub hidden: bool,
}

fn parse_filters(v: Option<&serde_json::Value>) -> Vec<Filter> {
    v.and_then(|f| f.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|f| {
                    let field = f.get("field").and_then(|x| x.as_str())?.trim().to_string();
                    if field.is_empty() {
                        return None;
                    }
                    let op = Op::parse(f.get("op").and_then(|x| x.as_str()).unwrap_or("="))
                        .unwrap_or(Op::Eq);
                    Some(Filter {
                        field,
                        op,
                        value: f
                            .get("value")
                            .cloned()
                            .unwrap_or(serde_json::Value::String(String::new())),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_query(v: &serde_json::Value, default_ref: &str) -> WidgetQuery {
    let s = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(str::to_string)
    };
    let group_by = match v.get("group_by") {
        Some(serde_json::Value::Array(a)) => a.first().and_then(|x| x.as_str()).map(str::to_string),
        Some(serde_json::Value::String(g)) if !g.is_empty() => Some(g.clone()),
        _ => None,
    };
    WidgetQuery {
        ref_id: s("ref_id").unwrap_or_else(|| default_ref.to_string()),
        source: s("source").unwrap_or_else(|| "spans".into()),
        filters: parse_filters(v.get("filters")),
        group_by,
        aggregation: s("aggregation"),
        limit: v.get("limit").and_then(|x| x.as_u64()),
        promql: s("promql"),
        hidden: v.get("hidden").and_then(|x| x.as_bool()).unwrap_or(false),
    }
}

/// The queries the UI would run for this widget.
pub fn widget_queries(w: &Widget) -> Vec<WidgetQuery> {
    let qc = &w.query_config;
    let all: Vec<WidgetQuery> = match qc
        .get("queries")
        .and_then(|q| q.as_array())
        .filter(|q| !q.is_empty())
    {
        Some(qs) => qs
            .iter()
            .enumerate()
            .map(|(i, q)| parse_query(q, &((b'A' + i as u8) as char).to_string()))
            .collect(),
        None => vec![parse_query(qc, "A")],
    };
    let visible: Vec<WidgetQuery> = all.into_iter().filter(|q| !q.hidden).collect();
    // Time series kinds plot every query; the rest show only the first.
    if matches!(
        w.widget_type.as_str(),
        "timeseries" | "heatmap" | "histogram"
    ) {
        visible.into_iter().take(5).collect()
    } else {
        visible.into_iter().take(1).collect()
    }
}

/// Dashboard variable values: explicit values win, then each variable's default.
fn variable_values(
    dashboard: &Dashboard,
    given: &BTreeMap<String, String>,
) -> BTreeMap<String, Option<String>> {
    let mut out = BTreeMap::new();
    if let Some(vars) = dashboard.variables.as_array() {
        for v in vars {
            if let Some(name) = v.get("name").and_then(|n| n.as_str()) {
                let default = v
                    .get("default")
                    .and_then(|d| d.as_str())
                    .map(str::to_string);
                out.insert(name.to_string(), default);
            }
        }
    }
    for (k, v) in given {
        out.insert(k.clone(), Some(v.clone()));
    }
    // "All" (or no value) means "don't filter on this variable".
    for v in out.values_mut() {
        if v.as_deref()
            .is_some_and(|s| s.is_empty() || s == "$__all" || s.eq_ignore_ascii_case("all"))
        {
            *v = None;
        }
    }
    out
}

fn mentions(text: &str, name: &str) -> bool {
    text.contains(&format!("${{{name}}}"))
        || text.match_indices(&format!("${name}")).any(|(i, _)| {
            let after = text[i + name.len() + 1..].chars().next();
            !after.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        })
}

fn substitute(text: &str, name: &str, value: &str) -> String {
    let braced = text.replace(&format!("${{{name}}}"), value);
    let mut out = String::new();
    let token = format!("${name}");
    let mut rest = braced.as_str();
    while let Some(i) = rest.find(&token) {
        let after = rest[i + token.len()..].chars().next();
        out.push_str(&rest[..i]);
        if after.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
            out.push_str(&token);
        } else {
            out.push_str(value);
        }
        rest = &rest[i + token.len()..];
    }
    out.push_str(rest);
    out
}

/// Apply dashboard variables like the UI: substitute values, drop filters on
/// "All" variables, and widen PromQL matchers to `.*`.
pub fn apply_variables(q: &WidgetQuery, vars: &BTreeMap<String, Option<String>>) -> WidgetQuery {
    let mut out = q.clone();
    out.filters = q
        .filters
        .iter()
        .filter_map(|f| {
            let mut value = match &f.value {
                serde_json::Value::String(s) => s.clone(),
                other => {
                    return Some(Filter {
                        field: f.field.clone(),
                        op: f.op,
                        value: other.clone(),
                    });
                }
            };
            for (name, v) in vars {
                if mentions(&value, name) {
                    match v {
                        Some(v) => value = substitute(&value, name, v),
                        None => return None,
                    }
                }
            }
            Some(Filter {
                field: f.field.clone(),
                op: f.op,
                value: serde_json::Value::String(value),
            })
        })
        .collect();
    out.promql = q.promql.as_ref().map(|p| {
        let mut p = p.clone();
        for (name, v) in vars {
            p = substitute(&p, name, v.as_deref().unwrap_or(".*"));
        }
        p
    });
    out
}

// ── Results ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchDashboardsArgs {
    /// Only dashboards whose name or description contains this text.
    #[serde(default)]
    pub contains: Option<String>,
    /// Only dashboards with this tag.
    #[serde(default)]
    pub tag: Option<String>,
    /// How many to return, most recently updated first (default 25, max 200).
    #[serde(default)]
    pub limit: Option<u64>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DashboardList {
    pub dashboards: Vec<DashboardBrief>,
    pub matched: usize,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq)]
pub struct DashboardBrief {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// private, tenant or global.
    pub visibility: String,
    pub updated_at: String,
}

impl Trim for DashboardList {
    fn trim(&mut self) -> bool {
        let n = self.dashboards.len();
        n > 5 && keep(&mut self.dashboards, n * 2 / 3)
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DashboardArgs {
    /// Dashboard ID or a Rush dashboard link (/dashboards/<id>).
    pub dashboard: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DashboardSummary {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// Default time range in minutes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_range_minutes: Option<u64>,
    pub variables: Vec<VariableBrief>,
    pub widgets: Vec<WidgetBrief>,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq)]
pub struct VariableBrief {
    pub name: String,
    /// query, static or textbox.
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq)]
pub struct WidgetBrief {
    /// Pass to get_widget_data.
    pub id: String,
    pub title: String,
    /// timeseries, heatmap, histogram, pie, bar, table or counter.
    #[serde(rename = "type")]
    pub widget_type: String,
    pub queries: Vec<QueryBrief>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
pub struct QueryBrief {
    pub ref_id: String,
    /// spans, logs or metrics.
    pub source: String,
    /// PromQL, or filters as Explore search-bar text.
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_by: Option<String>,
}

impl Trim for DashboardSummary {
    fn trim(&mut self) -> bool {
        let n = self.widgets.len();
        n > 4 && keep(&mut self.widgets, n * 2 / 3)
    }
}

fn query_brief(q: &WidgetQuery) -> QueryBrief {
    QueryBrief {
        ref_id: q.ref_id.clone(),
        source: q.source.clone(),
        query: if q.source == "metrics" {
            q.promql.clone().unwrap_or_default()
        } else {
            query_text(&q.filters, None)
        },
        aggregation: q.aggregation.clone(),
        group_by: q.group_by.clone(),
    }
}

pub fn shape_summary(d: &Dashboard) -> DashboardSummary {
    DashboardSummary {
        id: d.id.clone(),
        name: d.name.clone(),
        description: clip(&d.description, 300),
        time_range_minutes: d
            .defaults
            .get("time_range_minutes")
            .and_then(|v| v.as_u64()),
        variables: d
            .variables
            .as_array()
            .map(|vs| {
                vs.iter()
                    .filter_map(|v| {
                        Some(VariableBrief {
                            name: v.get("name")?.as_str()?.to_string(),
                            kind: v
                                .get("type")
                                .and_then(|t| t.as_str())
                                .unwrap_or("static")
                                .to_string(),
                            default: v
                                .get("default")
                                .and_then(|d| d.as_str())
                                .map(str::to_string),
                            options: v
                                .get("options")
                                .map(strings)
                                .unwrap_or_default()
                                .into_iter()
                                .take(20)
                                .collect(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default(),
        widgets: d
            .widgets
            .iter()
            .map(|w| WidgetBrief {
                id: w.id.clone(),
                title: w.title.clone(),
                widget_type: w.widget_type.clone(),
                queries: widget_queries(w).iter().map(query_brief).collect(),
            })
            .collect(),
    }
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DashboardDefinition {
    /// The dashboard export: settings, variables and every widget with its full configuration.
    pub definition: serde_json::Value,
}

impl Trim for DashboardDefinition {
    fn trim(&mut self) -> bool {
        self.definition
            .get_mut("widgets")
            .and_then(|w| w.as_array_mut())
            .is_some_and(|w| w.len() > 1 && w.pop().is_some())
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WidgetDataArgs {
    /// Dashboard ID or Rush dashboard link.
    pub dashboard: String,
    /// Widget ID (from get_dashboard_summary) or its exact title.
    pub widget: String,
    /// Dashboard variable values, e.g. {"service": "checkout"}. Unset variables use their defaults; "All" removes the filter.
    #[serde(default)]
    pub variables: BTreeMap<String, String>,
    /// Window; defaults to the dashboard's default range or the last hour.
    #[serde(flatten)]
    pub time: TimeArgs,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct WidgetData {
    pub title: String,
    #[serde(rename = "type")]
    pub widget_type: String,
    pub queries: Vec<QueryData>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct QueryData {
    #[serde(flatten)]
    pub query: QueryBrief,
    /// Single number (counters, totals).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<f64>,
    /// Values over time.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub series: Vec<ValuePoint>,
    /// Values per group (pie, bar, grouped series).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<GroupValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<MetricsResult>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
pub struct ValuePoint {
    pub t: String,
    pub value: f64,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
pub struct GroupValue {
    pub key: String,
    pub value: f64,
}

impl Trim for WidgetData {
    fn trim(&mut self) -> bool {
        for q in &mut self.queries {
            if q.series.len() > 12 {
                q.series = q.series.iter().step_by(2).cloned().collect();
                return true;
            }
            if keep(&mut q.groups, 10) {
                return true;
            }
            if let Some(m) = &mut q.metrics {
                if m.trim() {
                    return true;
                }
            }
        }
        pop(&mut self.queries)
    }
}

/// Value of one span time-series bucket for an aggregation, as the UI picks it.
pub fn bucket_value(b: &TimeseriesBucket, aggregation: &str) -> f64 {
    match aggregation {
        "error_count" => b.error_count as f64,
        "error_rate" => {
            if b.count == 0 {
                0.0
            } else {
                b.error_count as f64 * 100.0 / b.count as f64
            }
        }
        "avg" | "avg_duration_ms" => b.avg_duration_ms,
        "p50" | "p50_ms" => b.p50_ms,
        "p95" | "p95_ms" => b.p95_ms,
        "p99" | "p99_ms" => b.p99_ms,
        _ => b.count as f64,
    }
}

/// Combine bucket values into one number: sums for counts, count-weighted means otherwise.
pub fn combine(buckets: &[&TimeseriesBucket], aggregation: &str) -> f64 {
    match aggregation {
        "count" | "" | "error_count" => buckets.iter().map(|b| bucket_value(b, aggregation)).sum(),
        "error_rate" => {
            let total: u64 = buckets.iter().map(|b| b.count).sum();
            let errors: u64 = buckets.iter().map(|b| b.error_count).sum();
            if total == 0 {
                0.0
            } else {
                errors as f64 * 100.0 / total as f64
            }
        }
        _ => {
            let total: u64 = buckets.iter().map(|b| b.count).sum();
            if total == 0 {
                0.0
            } else {
                buckets
                    .iter()
                    .map(|b| bucket_value(b, aggregation) * b.count as f64)
                    .sum::<f64>()
                    / total as f64
            }
        }
    }
}

#[derive(Debug, Serialize)]
struct CountRequest<'a> {
    time_range: TimeRange,
    filters: &'a [Filter],
    interval: &'a str,
}

impl RushMcp {
    async fn load_dashboard(
        &self,
        key: Option<&ClientKey>,
        tool: &str,
        raw: &str,
    ) -> Result<Dashboard, ToolError> {
        let id = id_from(raw, "dashboards").ok_or_else(|| {
            ToolError::Input(format!(
                "`{raw}` is not a dashboard ID or a Rush dashboard link"
            ))
        })?;
        Ok(self
            .state
            .client
            .get(key, tool, &format!("/api/v1/dashboards/{id}"), &[])
            .await?)
    }

    async fn run_widget_query(
        &self,
        key: Option<&ClientKey>,
        widget_type: &str,
        q: &WidgetQuery,
        window: &Window,
    ) -> Result<QueryData, ToolError> {
        let c = &self.state.client;
        let tool = "get_widget_data";
        let tr = || TimeRange::from(window);
        let mut data = QueryData {
            query: query_brief(q),
            total: None,
            series: Vec::new(),
            groups: Vec::new(),
            metrics: None,
        };
        let over_time = matches!(widget_type, "timeseries" | "heatmap" | "histogram");
        match (q.source.as_str(), widget_type) {
            ("metrics", _) => {
                let promql = q
                    .promql
                    .clone()
                    .filter(|p| !p.trim().is_empty())
                    .ok_or_else(|| ToolError::Input(format!("query {} has no PromQL", q.ref_id)))?;
                let step = (window.duration().num_seconds() / 120).max(15);
                let env: PromEnvelope<PromData> = c
                    .get(
                        key,
                        tool,
                        "/prom/api/v1/query_range",
                        &[
                            ("query", promql.clone()),
                            ("start", window.from.timestamp().to_string()),
                            ("end", window.to.timestamp().to_string()),
                            ("step", step.to_string()),
                        ],
                    )
                    .await?;
                let m = shape_prom(&promql, env.data, false, 10);
                if widget_type == "counter" {
                    data.total = m.series.first().and_then(|s| s.last);
                }
                data.metrics = Some(m);
            }
            ("logs", "pie" | "bar") => {
                let field = q.group_by.clone().unwrap_or_else(|| "severity_text".into());
                let req = GroupRequest {
                    time_range: tr(),
                    filters: &q.filters,
                    group_by: [&field],
                    limit: q.limit.unwrap_or(10).clamp(1, 50),
                    search: None,
                };
                let resp: GroupResponse = c.post(key, tool, "/api/v1/logs/group", &req).await?;
                data.groups = resp
                    .pairs(&field)
                    .into_iter()
                    .map(|g| GroupValue {
                        key: g.key,
                        value: g.count as f64,
                    })
                    .collect();
            }
            ("logs", _) => {
                let interval = if over_time {
                    bucket_for(window, 48)
                } else {
                    "1h"
                };
                let buckets: Vec<CountBucket> = c
                    .post(
                        key,
                        tool,
                        "/api/v1/logs/count",
                        &CountRequest {
                            time_range: tr(),
                            filters: &q.filters,
                            interval,
                        },
                    )
                    .await?;
                data.total = Some(buckets.iter().map(|b| b.count as f64).sum());
                if over_time {
                    data.series = buckets
                        .into_iter()
                        .map(|b| ValuePoint {
                            t: b.bucket,
                            value: b.count as f64,
                        })
                        .collect();
                }
            }
            (_, "pie" | "bar") => {
                let field = q.group_by.clone().unwrap_or_else(|| "service_name".into());
                let req = GroupRequest {
                    time_range: tr(),
                    filters: &q.filters,
                    group_by: [&field],
                    limit: q.limit.unwrap_or(10).clamp(1, 50),
                    search: None,
                };
                let resp: GroupResponse = c.post(key, tool, "/api/v1/query/group", &req).await?;
                data.groups = resp
                    .pairs(&field)
                    .into_iter()
                    .map(|g| GroupValue {
                        key: g.key,
                        value: g.count as f64,
                    })
                    .collect();
            }
            _ if over_time => {
                let agg = q.aggregation.clone().unwrap_or_else(|| "count".into());
                let req = TimeseriesRequest {
                    time_range: tr(),
                    filters: &q.filters,
                    interval: bucket_for(window, 48),
                    group_by: q.group_by.as_deref(),
                    search: None,
                };
                let resp: TimeseriesResponse =
                    c.post(key, tool, "/api/v1/query/timeseries", &req).await?;
                let all: Vec<&TimeseriesBucket> = resp.buckets.iter().collect();
                data.total = Some(round2(combine(&all, &agg)));
                if resp.grouped {
                    let mut by_group: BTreeMap<&str, Vec<&TimeseriesBucket>> = BTreeMap::new();
                    for b in &resp.buckets {
                        by_group.entry(b.group_key.as_str()).or_default().push(b);
                    }
                    let mut groups: Vec<GroupValue> = by_group
                        .into_iter()
                        .map(|(k, bs)| GroupValue {
                            key: k.to_string(),
                            value: round2(combine(&bs, &agg)),
                        })
                        .collect();
                    groups.sort_by(|a, b| b.value.total_cmp(&a.value));
                    groups.truncate(20);
                    data.groups = groups;
                } else {
                    data.series = resp
                        .buckets
                        .iter()
                        .map(|b| ValuePoint {
                            t: b.bucket.clone(),
                            value: round2(bucket_value(b, &agg)),
                        })
                        .collect();
                }
            }
            _ => {
                let buckets: Vec<CountBucket> = c
                    .post(
                        key,
                        tool,
                        "/api/v1/query/count",
                        &CountRequest {
                            time_range: tr(),
                            filters: &q.filters,
                            interval: "1h",
                        },
                    )
                    .await?;
                data.total = Some(buckets.iter().map(|b| b.count as f64).sum());
            }
        }
        if data.series.len() > 48 {
            let step = data.series.len().div_ceil(48);
            data.series = data.series.iter().step_by(step).cloned().collect();
        }
        Ok(data)
    }
}

#[tool_router(router = dashboards_router, vis = "pub(crate)")]
impl RushMcp {
    #[tool(
        description = "Find dashboards by name, description or tag, most recently updated first.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn search_dashboards(
        &self,
        Parameters(args): Parameters<SearchDashboardsArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<DashboardList>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("search_dashboards", async {
            let key = key.as_ref();
            let resp: DashboardsResponse = self
                .state
                .client
                .get(key, "search_dashboards", "/api/v1/dashboards", &[])
                .await?;
            let needle = args
                .contains
                .as_deref()
                .map(|c| c.trim().to_lowercase())
                .filter(|c| !c.is_empty());
            let tag = args
                .tag
                .as_deref()
                .map(|t| t.trim().to_lowercase())
                .filter(|t| !t.is_empty());
            let mut matched: Vec<DashboardBrief> = resp
                .dashboards
                .iter()
                .filter(|d| {
                    needle.as_ref().is_none_or(|n| {
                        d.name.to_lowercase().contains(n)
                            || d.description.to_lowercase().contains(n)
                    })
                })
                .filter(|d| {
                    tag.as_ref()
                        .is_none_or(|t| strings(&d.tags).iter().any(|x| x.to_lowercase() == *t))
                })
                .map(|d| DashboardBrief {
                    id: d.id.clone(),
                    name: d.name.clone(),
                    description: clip(&d.description, 200),
                    tags: strings(&d.tags),
                    visibility: d.visibility.clone(),
                    updated_at: d.updated_at.clone(),
                })
                .collect();
            let total = matched.len();
            matched.truncate(args.limit.unwrap_or(25).clamp(1, 200) as usize);
            let links = self.links(key).await;
            Ok(Envelope::new(
                format!("{total} dashboards match ({} shown).", matched.len()),
                DashboardList {
                    dashboards: matched,
                    matched: total,
                },
            )
            .link("dashboards", links.dashboards()))
        })
        .await
    }

    #[tool(
        description = "A dashboard's widgets (ID, title, type and each query as PromQL or filter text), variables and default time range, without layout. Use before get_widget_data.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn get_dashboard_summary(
        &self,
        Parameters(args): Parameters<DashboardArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<DashboardSummary>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("get_dashboard_summary", async {
            let key = key.as_ref();
            let d = self
                .load_dashboard(key, "get_dashboard_summary", &args.dashboard)
                .await?;
            let result = shape_summary(&d);
            let links = self.links(key).await;
            Ok(Envelope::new(
                format!(
                    "{}: {} widgets, {} variables.",
                    result.name,
                    result.widgets.len(),
                    result.variables.len()
                ),
                result,
            )
            .link("dashboard", links.dashboard(&d.id, None)))
        })
        .await
    }

    #[tool(
        description = "A dashboard's full definition (settings, variables and complete widget configurations, as exported by Rush). Large; prefer get_dashboard_summary unless the raw configuration is needed.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn get_dashboard(
        &self,
        Parameters(args): Parameters<DashboardArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<DashboardDefinition>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("get_dashboard", async {
            let key = key.as_ref();
            let id = id_from(&args.dashboard, "dashboards").ok_or_else(|| {
                ToolError::Input(format!(
                    "`{}` is not a dashboard ID or a Rush dashboard link",
                    args.dashboard
                ))
            })?;
            let def: serde_json::Value = self
                .state
                .client
                .get(
                    key,
                    "get_dashboard",
                    &format!("/api/v1/dashboards/{id}/export"),
                    &[],
                )
                .await?;
            let name = def
                .pointer("/dashboard/name")
                .and_then(|n| n.as_str())
                .unwrap_or("dashboard")
                .to_string();
            let widgets = def
                .get("widgets")
                .and_then(|w| w.as_array())
                .map(Vec::len)
                .unwrap_or(0);
            let links = self.links(key).await;
            Ok(Envelope::new(
                format!("{name}: full definition with {widgets} widgets."),
                DashboardDefinition { definition: def },
            )
            .link("dashboard", links.dashboard(&id, None)))
        })
        .await
    }

    #[tool(
        description = "Run one dashboard widget's queries the way the Rush UI does and return the numbers: totals, values over time, or values per group (PromQL widgets are summarized per series). Applies dashboard variables.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn get_widget_data(
        &self,
        Parameters(args): Parameters<WidgetDataArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<WidgetData>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("get_widget_data", async {
            let key = key.as_ref();
            let d = self.load_dashboard(key, "get_widget_data", &args.dashboard).await?;
            let wanted = args.widget.trim();
            let widget = d
                .widgets
                .iter()
                .find(|w| w.id == wanted)
                .or_else(|| d.widgets.iter().find(|w| w.title.eq_ignore_ascii_case(wanted)))
                .ok_or_else(|| ToolError::Input(format!("no widget `{wanted}` on {}; list widgets with get_dashboard_summary", d.name)))?;
            let mut time = args.time.clone();
            if time.last.is_none() && time.from.is_none() {
                let minutes = widget
                    .query_config
                    .get("time_range_minutes")
                    .and_then(|v| v.as_u64())
                    .or_else(|| d.defaults.get("time_range_minutes").and_then(|v| v.as_u64()))
                    .unwrap_or(60);
                time.last = Some(format!("{minutes}m"));
            }
            let window = time.resolve()?;
            let vars = variable_values(&d, &args.variables);
            let queries: Vec<WidgetQuery> = widget_queries(widget).iter().map(|q| apply_variables(q, &vars)).collect();
            if queries.is_empty() {
                return Err(ToolError::Input("this widget has no visible queries".into()));
            }
            let mut results = Vec::new();
            for q in &queries {
                results.push(self.run_widget_query(key, &widget.widget_type, q, &window).await?);
            }
            let detail = results.first().map(|r| match (&r.metrics, r.total, r.groups.first()) {
                (Some(m), _, _) => format!(
                    "; {} series{}",
                    m.series_total,
                    m.series.first().and_then(|s| s.last).map(|v| format!(", first ends at {v}")).unwrap_or_default()
                ),
                (None, Some(total), _) => format!("; total {total}"),
                (None, None, Some(g)) => format!("; largest group {} ({})", g.key, g.value),
                _ => String::new(),
            });
            let summary = format!(
                "{} ({}): {} quer{}{}.",
                widget.title,
                widget.widget_type,
                results.len(),
                if results.len() == 1 { "y" } else { "ies" },
                detail.unwrap_or_default()
            );
            let table_hint = widget.widget_type == "table";
            let links = self.links(key).await;
            let mut env = Envelope::new(summary, WidgetData { title: widget.title.clone(), widget_type: widget.widget_type.clone(), queries: results })
                .window(&window)
                .link("dashboard", links.dashboard(&d.id, Some(&window)));
            if table_hint {
                env = env.hint(Hint::new("Table widgets list raw records; this returns the total. Use search_logs or search_spans with the same filters for rows."));
            }
            Ok(env)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn widget(kind: &str, qc: serde_json::Value) -> Widget {
        Widget {
            id: "w".into(),
            title: "Errors".into(),
            widget_type: kind.into(),
            query_config: qc,
            ..Default::default()
        }
    }

    #[test]
    fn legacy_and_multi_query_widgets_parse_like_the_ui() {
        let legacy = widget(
            "bar",
            serde_json::json!({"source": "logs", "filters": [{"field": "service_name", "op": "=", "value": "api"}], "group_by": ["severity_text"]}),
        );
        let q = widget_queries(&legacy);
        assert_eq!(q.len(), 1);
        assert_eq!(
            (
                q[0].ref_id.as_str(),
                q[0].source.as_str(),
                q[0].group_by.as_deref()
            ),
            ("A", "logs", Some("severity_text"))
        );

        let multi = widget(
            "timeseries",
            serde_json::json!({"queries": [
                {"ref_id": "A", "source": "spans", "aggregation": "p95"},
                {"ref_id": "B", "source": "metrics", "promql": "up", "hidden": true},
                {"source": "metrics", "promql": "rate(x[5m])"}
            ]}),
        );
        let q = widget_queries(&multi);
        assert_eq!(
            q.iter().map(|x| x.ref_id.as_str()).collect::<Vec<_>>(),
            ["A", "C"],
            "hidden queries are skipped"
        );
        let pie = widget("pie", multi.query_config.clone());
        assert_eq!(
            widget_queries(&pie).len(),
            1,
            "non-time-series widgets use the first query"
        );
    }

    #[test]
    fn variables_substitute_drop_and_widen() {
        let q = WidgetQuery {
            filters: vec![
                Filter::eq("service_name", "$service"),
                Filter::eq("env", "${env}"),
                Filter::eq("path", "/x"),
            ],
            promql: Some("sum(rate(req{service=\"$service\",env=\"$env\"}[5m]))".into()),
            ..Default::default()
        };
        let d = Dashboard {
            variables: serde_json::json!([{"name": "service", "default": "api"}, {"name": "env", "default": "All"}]),
            ..Default::default()
        };
        let vars = variable_values(&d, &BTreeMap::new());
        let out = apply_variables(&q, &vars);
        assert_eq!(
            out.filters,
            vec![Filter::eq("service_name", "api"), Filter::eq("path", "/x")],
            "All drops the env filter"
        );
        assert_eq!(
            out.promql.as_deref(),
            Some("sum(rate(req{service=\"api\",env=\".*\"}[5m]))")
        );
        let given = BTreeMap::from([("service".to_string(), "checkout".to_string())]);
        assert_eq!(
            apply_variables(&q, &variable_values(&d, &given)).filters[0],
            Filter::eq("service_name", "checkout")
        );
    }

    #[test]
    fn substitution_respects_token_boundaries() {
        assert_eq!(
            substitute("$svc and $service", "svc", "a"),
            "a and $service"
        );
        assert!(!mentions("$services", "service"));
        assert!(mentions("x-${service}", "service"));
    }

    #[test]
    fn bucket_aggregations_match_the_ui() {
        let b = |count, errors, p95| TimeseriesBucket {
            count,
            error_count: errors,
            p95_ms: p95,
            ..Default::default()
        };
        let (x, y) = (b(100, 5, 200.0), b(300, 3, 100.0));
        assert_eq!(bucket_value(&x, "error_rate"), 5.0);
        assert_eq!(combine(&[&x, &y], "count"), 400.0);
        assert_eq!(combine(&[&x, &y], "error_rate"), 2.0);
        assert_eq!(combine(&[&x, &y], "p95"), 125.0);
    }

    #[test]
    fn summaries_list_widgets_without_layout() {
        let d = Dashboard {
            id: "d1".into(),
            name: "Checkout".into(),
            defaults: serde_json::json!({"time_range_minutes": 60}),
            variables: serde_json::json!([{"name": "service", "type": "query", "default": "api"}]),
            widgets: vec![widget(
                "timeseries",
                serde_json::json!({"source": "metrics", "promql": "up"}),
            )],
            ..Default::default()
        };
        let s = shape_summary(&d);
        assert_eq!(s.time_range_minutes, Some(60));
        assert_eq!(s.variables[0].kind, "query");
        assert_eq!(s.widgets[0].queries[0].query, "up");
    }
}
