//! `changes` toolset: deploy markers.

use rmcp::{
    RoleServer,
    handler::server::wrapper::{Json, Parameters},
    model::CallToolResult,
    service::RequestContext,
    tool, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::api::{Deploy, DeploysResponse};
use crate::envelope::{Envelope, Hint, Trim, clip};
use crate::server::RushMcp;
use crate::time::TimeArgs;
use crate::tools::pop;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListDeploysArgs {
    /// Only deploys of this service.
    #[serde(default)]
    pub service: Option<String>,
    /// Window to search. Defaults to the last 7 days.
    #[serde(flatten)]
    pub time: TimeArgs,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DeployList {
    /// Newest first (at most 100).
    pub deploys: Vec<Deploy>,
}

impl Trim for DeployList {
    fn trim(&mut self) -> bool {
        pop(&mut self.deploys)
    }
}

#[tool_router(router = changes_router, vis = "pub(crate)")]
impl RushMcp {
    #[tool(
        description = "List deploy markers (service, version, commit, environment, who and when), newest first. Defaults to the last 7 days. Use to line up changes with errors or latency.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn list_deploys(
        &self,
        Parameters(args): Parameters<ListDeploysArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<Json<Envelope<DeployList>>, CallToolResult> {
        let key = Self::client_key(&ctx);
        self.run("list_deploys", async {
            let key = key.as_ref();
            let mut time = args.time.clone();
            if time.last.is_none() && time.from.is_none() {
                time.last = Some("7d".into());
            }
            let window = time.resolve()?;
            let mut query = vec![("from", window.from_rfc3339()), ("to", window.to_rfc3339())];
            if let Some(s) = args
                .service
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                query.push(("service_name", s.to_string()));
            }
            let resp: DeploysResponse = self
                .state
                .client
                .get(key, "list_deploys", "/api/v1/deploys", &query)
                .await?;
            let deploys: Vec<Deploy> = resp
                .deploys
                .into_iter()
                .map(|mut d| {
                    d.description = clip(&d.description, 300);
                    d
                })
                .collect();
            let summary = match deploys.first() {
                Some(d) => format!(
                    "{} deploys; latest {} {} at {}.",
                    deploys.len(),
                    d.service_name,
                    if d.version.is_empty() {
                        &d.commit_sha
                    } else {
                        &d.version
                    },
                    d.deployed_at
                ),
                None => "No deploys in this window.".into(),
            };
            let links = self.links(key).await;
            let mut env = Envelope::new(summary, DeployList { deploys })
                .window(&window)
                .link("deploys", links.deploys());
            if env.result.deploys.is_empty() {
                env = env.hint(
                    Hint::new("No deploy markers recorded.")
                        .action("Widen the window, or check that your CI records deploys in Rush"),
                );
            }
            Ok(env)
        })
        .await
    }
}
