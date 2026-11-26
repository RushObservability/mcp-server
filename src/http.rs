//! Streamable HTTP transport plus `/healthz`, `/readyz` and `/metrics`.

use std::sync::Arc;

use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::api::WhoAmI;
use crate::client::{ApiError, ClientKey, RushClient};
use crate::config::Config;
use crate::server::{AppState, RushMcp};

mod sessions;

const MAX_PENDING_AUTHENTICATIONS: usize = 32;

struct AuthState {
    policy: AuthPolicy,
    client: RushClient,
    pending: Semaphore,
}

/// Who may use the MCP endpoint.
#[derive(Clone)]
struct AuthPolicy {
    /// The server has its own API key that requests may fall back to.
    server_key: bool,
    /// Token required to use that key. `None` only on loopback (see Config::validate).
    server_token: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum Decision {
    /// Use the client's own Rush key.
    ClientKey(String),
    /// Use the server's configured key.
    ServerKey,
    Reject(&'static str),
}

fn decide(policy: &AuthPolicy, headers: &HeaderMap) -> Decision {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|t| !t.is_empty());
    match bearer {
        // A Rush key authenticates itself against Rush; no server token needed.
        Some(token) if token.starts_with("rush_") => Decision::ClientKey(token.to_string()),
        Some(token) if policy.server_key => match &policy.server_token {
            Some(expected) if constant_time_eq(token.as_bytes(), expected.as_bytes()) => {
                Decision::ServerKey
            }
            Some(_) => Decision::Reject("invalid server token"),
            None => Decision::ServerKey,
        },
        None if policy.server_key && policy.server_token.is_none() => Decision::ServerKey,
        _ if policy.server_key => {
            Decision::Reject("send the server token as Authorization: Bearer <token>")
        }
        _ => Decision::Reject("send your Rush API key as Authorization: Bearer rush_qry_…"),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn authenticate(
    State(state): State<Arc<AuthState>>,
    mut req: Request,
    next: Next,
) -> Response {
    match decide(&state.policy, req.headers()) {
        Decision::ClientKey(key) => {
            let key = ClientKey(key);
            if let Err(status) = verify_client_key(&state, &key).await {
                return if status == StatusCode::UNAUTHORIZED {
                    unauthorized("Rush rejected the API key")
                } else {
                    status.into_response()
                };
            }
            req.extensions_mut().insert(key);
            next.run(req).await
        }
        Decision::ServerKey => next.run(req).await,
        Decision::Reject(message) => unauthorized(message),
    }
}

fn unauthorized(message: &'static str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        message,
    )
        .into_response()
}

async fn verify_client_key(state: &AuthState, key: &ClientKey) -> Result<(), StatusCode> {
    let _permit = state
        .pending
        .try_acquire()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    match state
        .client
        .get::<WhoAmI>(Some(key), "http_auth", "/api/v1/whoami", &[])
        .await
    {
        Ok(identity) if identity.principal.kind == "api_key" => Ok(()),
        Ok(_) | Err(ApiError::Unauthorized(_) | ApiError::Forbidden(_)) => {
            Err(StatusCode::UNAUTHORIZED)
        }
        Err(ApiError::RateLimited(_)) => Err(StatusCode::TOO_MANY_REQUESTS),
        Err(_) => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

pub async fn serve(state: Arc<AppState>, config: &Config) -> anyhow::Result<()> {
    let shutdown = CancellationToken::new();
    let mut http_config = StreamableHttpServerConfig::default();
    http_config.json_response = true;
    http_config.cancellation_token = shutdown.child_token();
    if !config.allowed_hosts.is_empty() {
        http_config.allowed_hosts = config.allowed_hosts.clone();
    }
    http_config.allowed_origins = config.allowed_origins.clone();

    let factory_state = state.clone();
    let mcp = StreamableHttpService::new(
        move || Ok(RushMcp::new(factory_state.clone())),
        Arc::new(sessions::BoundedSessions::new(config.max_http_sessions)),
        http_config,
    );
    let policy = AuthPolicy {
        server_key: config.api_key.is_some() || config.api_key_file.is_some(),
        server_token: config.server_token.clone(),
    };
    let auth_state = Arc::new(AuthState {
        policy,
        client: state.client.clone(),
        pending: Semaphore::new(MAX_PENDING_AUTHENTICATIONS),
    });
    let mcp_routes = Router::new()
        .nest_service(&config.base_path, mcp)
        .layer(middleware::from_fn_with_state(auth_state, authenticate));
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .with_state(state)
        .merge(mcp_routes);

    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!(address = %config.listen, path = %config.base_path, "serving MCP over streamable HTTP");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            shutdown.cancel();
        })
        .await?;
    Ok(())
}

/// Ready when the Rush API answers.
async fn readyz(State(state): State<Arc<AppState>>) -> Response {
    match state.client.ping().await {
        Ok(()) => (StatusCode::OK, "ready").into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}

async fn metrics(State(state): State<Arc<AppState>>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.metrics.render(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(auth: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(a) = auth {
            h.insert(header::AUTHORIZATION, a.parse().unwrap());
        }
        h
    }

    #[test]
    fn rush_keys_pass_through_without_a_server_token() {
        let policy = AuthPolicy {
            server_key: true,
            server_token: Some("t0ken".into()),
        };
        assert_eq!(
            decide(&policy, &headers(Some("Bearer rush_qry_abc"))),
            Decision::ClientKey("rush_qry_abc".into())
        );
    }

    #[test]
    fn the_server_key_needs_the_server_token() {
        let policy = AuthPolicy {
            server_key: true,
            server_token: Some("t0ken".into()),
        };
        assert_eq!(
            decide(&policy, &headers(Some("Bearer t0ken"))),
            Decision::ServerKey
        );
        assert!(matches!(
            decide(&policy, &headers(Some("Bearer nope"))),
            Decision::Reject(_)
        ));
        assert!(matches!(
            decide(&policy, &headers(None)),
            Decision::Reject(_)
        ));
    }

    #[test]
    fn loopback_without_a_token_may_use_the_server_key() {
        let policy = AuthPolicy {
            server_key: true,
            server_token: None,
        };
        assert_eq!(decide(&policy, &headers(None)), Decision::ServerKey);
    }

    #[test]
    fn without_a_server_key_clients_must_bring_their_own() {
        let policy = AuthPolicy {
            server_key: false,
            server_token: None,
        };
        assert!(
            matches!(decide(&policy, &headers(None)), Decision::Reject(m) if m.contains("rush_qry"))
        );
        assert!(matches!(
            decide(&policy, &headers(Some("Bearer whatever"))),
            Decision::Reject(_)
        ));
    }

    #[tokio::test]
    async fn byok_admission_requires_a_query_api_key_identity() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{header, method, path},
        };

        let api = MockServer::start().await;
        for (key, response) in [
            (
                "local-test-key",
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"principal":{"type":"api_key"}})),
            ),
            (
                "local-test-anonymous",
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"principal":{"type":"anonymous"}})),
            ),
            ("local-test-rejected", ResponseTemplate::new(403)),
        ] {
            Mock::given(method("GET"))
                .and(path("/api/v1/whoami"))
                .and(header("authorization", format!("Bearer {key}")))
                .respond_with(response)
                .expect(1)
                .mount(&api)
                .await;
        }
        let state = AuthState {
            policy: AuthPolicy {
                server_key: false,
                server_token: None,
            },
            client: RushClient::new(
                api.uri().parse().unwrap(),
                crate::client::KeySource::None,
                std::time::Duration::from_secs(2),
            )
            .unwrap(),
            pending: Semaphore::new(1),
        };
        assert_eq!(
            verify_client_key(&state, &ClientKey("local-test-key".into())).await,
            Ok(())
        );
        for key in ["local-test-anonymous", "local-test-rejected"] {
            assert_eq!(
                verify_client_key(&state, &ClientKey(key.into())).await,
                Err(StatusCode::UNAUTHORIZED)
            );
        }
    }

    #[test]
    fn token_comparison_is_length_and_content_exact() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
