//! `saved_queries` toolset: list and run queries people saved in Explore.

use rmcp::{
    RoleServer,
    handler::server::wrapper::{Json, Parameters},
    model::CallToolResult,
    service::RequestContext,
    tool, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::api::{Filter, Op, SavedQueriesResponse, SavedQuery, SignalKind, query_text};
use crate::envelope::{Envelope, Hint, Trim, clip};
use crate::links::saved_query_id_from;
use crate::server::{RushMcp, ToolError};
use crate::time::TimeArgs;
use crate::tools::core::{LogSearch, SpanSearch};
use crate::tools::{Query, keep};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListSavedQueriesArgs {
    /// Only queries whose name or description contains this text.
    #[serde(default)]
    pub contains: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SavedQueryList {
    pub queries: Vec<SavedQueryOut>,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq)]
pub struct SavedQueryOut {
    pub id: String,
    pub name: String,
    /// Why the query is useful, written by whoever saved it.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// "logs", "spans" or "" (either).
    pub signal: String,
    /// The query as Explore search-bar text.
    pub query: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub group_by: String,
    /// Saved time range in minutes; 0 means the viewer's current range.
    pub time_minutes: u32,
    /// "tenant", "group: <name>" or "private".
    pub shared_with: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub owner: String,
}

impl Trim for SavedQueryList {
    fn trim(&mut self) -> bool {
        if let Some(q) = self
            .queries
            .iter_mut()
            .find(|q| q.description.chars().count() > 120)
        {
            q.description = clip(&q.description, 120);
            return true;
        }
        let n = self.queries.len();
        n > 5 && keep(&mut self.queries, n * 2 / 3)
    }
}

fn filters_of(q: &SavedQuery) -> Vec<Filter> {
    q.query
        .filters
        .iter()
        .filter(|f| !f.field.trim().is_empty())
        .map(|f| Filter {
            field: f.field.trim().to_string(),
            op: Op::parse(&f.op).unwrap_or(Op::Eq),
            value: serde_json::Value::String(f.value.clone()),
        })
        .collect()
}

pub fn saved_out(q: &SavedQuery, groups: &[crate::api::NamedGroup]) -> SavedQueryOut {
    let search = (!q.query.search.trim().is_empty()).then_some(q.query.search.as_str());
    SavedQueryOut {
        id: q.id.clone(),
        name: q.name.clone(),
        description: clip(&q.description, 500),
        signal: q.query.view_mode.clone(),
        query: query_text(&filters_of(q), search),
        group_by: q.query.group_by.clone(),
        time_minutes: q.query.time_preset,
        shared_with: match q.visibility.as_str() {
            "group" => format!(
                "group: {}",
                groups
                    .iter()
                    .find(|g| g.id == q.group_id)
                    .map(|g| g.name.as_str())
                    .unwrap_or("a group")
            ),
            other => other.to_string(),
        },
        owner: q.owner_name.clone(),
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RunSavedQueryArgs {
    /// Saved query ID, or a Rush link containing ?saved=<id>.
    pub saved_query: String,
    /// Override the saved time range. Without this, the saved range is used (or the last hour).
    #[serde(flatten)]
    pub time: TimeArgs,
    /// Sample rows to return (default 10, max 50).
    #[serde(default)]
    pub samples: Option<u64>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SavedRun {
    pub saved_query: SavedQueryOut,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logs: Option<LogSearch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spans: Option<SpanSearch>,
}

impl Trim for SavedRun {
    fn trim(&mut self) -> bool {
        if let Some(l) = &mut self.logs {
            if l.trim() {
                return true;
            }
        }
        if let Some(s) = &mut self.spans {
            if s.trim() {
                return true;
            }
        }
        if self.saved_query.description.chars().count() > 120 {
            self.saved_query.description = clip(&self.saved_query.description, 120);
            return true;
        }
        false
    }
}

#[tool_router(router = saved_queries_router, vis = "pub(crate)")]
impl RushMcp {
    #[tool(
        description = "List saved Explore queries visible to this key: shared with the tenant, with its groups, or its own. Each has a description of why it is useful.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn list_saved_queries(
        &self,
        Parameters(args): Parameters<ListSavedQueriesArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<SavedQueryList>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("list_saved_queries", async {
            let resp: SavedQueriesResponse = self
                .state
                .client
                .get(
                    key.as_ref(),
                    "list_saved_queries",
                    "/api/v1/saved-queries",
                    &[],
                )
                .await?;
            let needle = args
                .contains
                .as_deref()
                .map(|c| c.trim().to_lowercase())
                .filter(|c| !c.is_empty());
            let queries: Vec<SavedQueryOut> = resp
                .saved_queries
                .iter()
                .filter(|q| {
                    needle.as_ref().is_none_or(|n| {
                        q.name.to_lowercase().contains(n)
                            || q.description.to_lowercase().contains(n)
                    })
                })
                .map(|q| saved_out(q, &resp.groups))
                .collect();
            let mut env = Envelope::new(
                format!("{} saved queries.", queries.len()),
                SavedQueryList { queries },
            );
            if env.result.queries.is_empty() {
                env = env.hint(Hint::new("No saved queries are visible to this key."));
            }
            Ok(env)
        })
        .await
    }

    #[tool(
        description = "Run a saved Explore query by ID or Rush link and return the same summary as search_logs or search_spans, plus the saved query's name and description.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn run_saved_query(
        &self,
        Parameters(args): Parameters<RunSavedQueryArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<SavedRun>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("run_saved_query", async {
            let key = key.as_ref();
            let id = saved_query_id_from(&args.saved_query).ok_or_else(|| {
                ToolError::Input(format!(
                    "`{}` is not a saved query ID or a link with ?saved=<id>",
                    args.saved_query
                ))
            })?;
            let saved: SavedQuery = self
                .state
                .client
                .get(
                    key,
                    "run_saved_query",
                    &format!("/api/v1/saved-queries/{id}"),
                    &[],
                )
                .await?;
            let mut time = args.time.clone();
            if time.last.is_none() && time.from.is_none() && saved.query.time_preset > 0 {
                time.last = Some(format!("{}m", saved.query.time_preset));
            }
            let window = time.resolve()?;
            let search = (!saved.query.search.trim().is_empty())
                .then(|| saved.query.search.trim().to_string());
            let q = Query {
                filters: filters_of(&saved),
                search,
                window,
            };
            let group_by = (!saved.query.group_by.trim().is_empty())
                .then(|| saved.query.group_by.trim().to_string());
            let samples = args.samples.unwrap_or(10).min(50);
            let out = saved_out(&saved, &[]);
            let links = self.links(key).await;
            let signal = if saved.query.view_mode == "logs" {
                SignalKind::Logs
            } else {
                SignalKind::Spans
            };
            let env = match signal {
                SignalKind::Logs => self
                    .do_search_logs(key, "run_saved_query", q, samples, group_by)
                    .await?
                    .map(|logs| SavedRun {
                        saved_query: out,
                        logs: Some(logs),
                        spans: None,
                    }),
                SignalKind::Spans => self
                    .do_search_spans(key, "run_saved_query", q, samples, group_by)
                    .await?
                    .map(|spans| SavedRun {
                        saved_query: out,
                        logs: None,
                        spans: Some(spans),
                    }),
            };
            let name = env.result.saved_query.name.clone();
            let summary = format!("{name}: {}", env.summary);
            let mut env = env.link("saved_query", links.saved_query(&id));
            env.summary = summary;
            Ok(env)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{NamedGroup, SavedFilter, SavedQueryBody};

    fn saved() -> SavedQuery {
        SavedQuery {
            id: "q1".into(),
            name: "Checkout errors".into(),
            description: "First stop when checkout alerts fire".into(),
            visibility: "group".into(),
            group_id: "sre".into(),
            owner_name: "Priya".into(),
            query: SavedQueryBody {
                filters: vec![
                    SavedFilter {
                        field: "service_name".into(),
                        op: "=".into(),
                        value: "checkout".into(),
                    },
                    SavedFilter {
                        field: "http_status_code".into(),
                        op: ">=".into(),
                        value: "500".into(),
                    },
                    SavedFilter {
                        field: " ".into(),
                        op: "=".into(),
                        value: "ignored".into(),
                    },
                ],
                search: "timeout".into(),
                group_by: "http_path".into(),
                time_preset: 60,
                view_mode: "spans".into(),
            },
            ..Default::default()
        }
    }

    #[test]
    fn saved_queries_render_as_search_text_with_their_audience() {
        let out = saved_out(
            &saved(),
            &[NamedGroup {
                id: "sre".into(),
                name: "SRE".into(),
            }],
        );
        assert_eq!(
            out.query,
            "service_name=checkout http_status_code>=500 timeout"
        );
        assert_eq!(out.shared_with, "group: SRE");
        assert_eq!(out.signal, "spans");
        assert_eq!(out.time_minutes, 60);
    }

    #[test]
    fn saved_filters_convert_to_api_filters() {
        let f = filters_of(&saved());
        assert_eq!(f.len(), 2, "blank fields are dropped");
        assert_eq!(f[1].op, Op::Gte);
    }
}
