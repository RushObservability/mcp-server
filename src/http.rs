//! Streamable HTTP transport plus `/healthz`, `/readyz` and `/metrics`.

use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header, uri::Authority},
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
/// How long a request waits for a free verification slot before getting 429.
const AUTH_QUEUE_WAIT: Duration = Duration::from_secs(5);
/// How long Rush's answer for a key is reused.
const ACCEPTED_TTL: Duration = Duration::from_secs(60);
const REJECTED_TTL: Duration = Duration::from_secs(15);
const MAX_CACHED_KEYS: usize = 1_000;

/// Rush's answer per hashed key, until it expires.
type Verdicts = HashMap<u64, (Result<(), StatusCode>, Instant)>;

struct AuthState {
    policy: AuthPolicy,
    client: RushClient,
    pending: Semaphore,
    /// rmcp checks Host too, but only after this middleware has run.
    allowed_hosts: Vec<String>,
    /// Keys are cached by keyed hash, never stored.
    hasher: RandomState,
    verified: Mutex<Verdicts>,
}

impl AuthState {
    fn new(policy: AuthPolicy, client: RushClient, allowed_hosts: Vec<String>) -> Self {
        Self {
            policy,
            client,
            pending: Semaphore::new(MAX_PENDING_AUTHENTICATIONS),
            allowed_hosts,
            hasher: RandomState::new(),
            verified: Mutex::new(HashMap::new()),
        }
    }

    fn verified(&self) -> std::sync::MutexGuard<'_, Verdicts> {
        self.verified.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn cached(&self, id: u64) -> Option<Result<(), StatusCode>> {
        self.verified()
            .get(&id)
            .filter(|(_, until)| Instant::now() < *until)
            .map(|(result, _)| *result)
    }

    /// Remember accepted and rejected keys; upstream errors are retried.
    fn remember(&self, id: u64, result: Result<(), StatusCode>) {
        let ttl = match result {
            Ok(()) => ACCEPTED_TTL,
            Err(StatusCode::UNAUTHORIZED) => REJECTED_TTL,
            Err(_) => return,
        };
        let now = Instant::now();
        let mut cache = self.verified();
        if cache.len() >= MAX_CACHED_KEYS {
            cache.retain(|_, (_, until)| now < *until);
            if cache.len() >= MAX_CACHED_KEYS {
                // shortcut: a flood of distinct keys empties the cache, so
                // real keys are checked again; move to LRU if that shows up.
                cache.clear();
            }
        }
        cache.insert(id, (result, now + ttl));
    }
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
    if !host_allowed(&req, &state.allowed_hosts) {
        return (
            StatusCode::FORBIDDEN,
            "Forbidden: Host header is not allowed",
        )
            .into_response();
    }
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

/// The same Host allowlist rmcp applies (empty allows any host).
fn host_allowed(req: &Request, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return true;
    }
    let host = match req.headers().get(header::HOST) {
        Some(h) => h.to_str().ok().and_then(|h| h.parse::<Authority>().ok()),
        None => req.uri().authority().cloned(),
    };
    let Some(host) = host else {
        return false;
    };
    let norm = |h: &str| h.trim_matches(['[', ']']).to_ascii_lowercase();
    allowed
        .iter()
        .map(|a| a.trim())
        .filter(|a| !a.is_empty())
        .any(|a| match a.parse::<Authority>() {
            Ok(a) => {
                norm(a.host()) == norm(host.host())
                    && a.port_u16().is_none_or(|p| host.port_u16() == Some(p))
            }
            Err(_) => norm(a) == norm(host.host()),
        })
}

async fn verify_client_key(state: &AuthState, key: &ClientKey) -> Result<(), StatusCode> {
    let id = state.hasher.hash_one(&key.0);
    if let Some(result) = state.cached(id) {
        return result;
    }
    let Ok(Ok(_permit)) = tokio::time::timeout(AUTH_QUEUE_WAIT, state.pending.acquire()).await
    else {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    };
    // A request that queued behind the same key may find its answer now.
    if let Some(result) = state.cached(id) {
        return result;
    }
    let result = match state
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
    };
    state.remember(id, result);
    result
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

    let allowed_hosts = http_config.allowed_hosts.clone();
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
    let auth_state = Arc::new(AuthState::new(policy, state.client.clone(), allowed_hosts));
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

    fn auth_state(api: &wiremock::MockServer, permits: usize) -> AuthState {
        let mut state = AuthState::new(
            AuthPolicy {
                server_key: false,
                server_token: None,
            },
            RushClient::new(
                api.uri().parse().unwrap(),
                crate::client::KeySource::None,
                Duration::from_secs(2),
            )
            .unwrap(),
            vec!["localhost".into(), "127.0.0.1".into()],
        );
        state.pending = Semaphore::new(permits);
        state
    }

    #[tokio::test]
    async fn byok_admission_requires_a_query_api_key_identity_and_is_cached() {
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
        let state = auth_state(&api, 1);
        // Each key is asked about once; the repeat is answered from the cache.
        for _ in 0..2 {
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
    }

    #[tokio::test]
    async fn a_burst_beyond_the_verification_slots_waits_its_turn() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::path};

        let api = MockServer::start().await;
        Mock::given(path("/api/v1/whoami"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(200))
                    .set_body_json(serde_json::json!({"principal":{"type":"api_key"}})),
            )
            .expect(3)
            .mount(&api)
            .await;
        let state = auth_state(&api, 1);
        let (a, b, c) = (
            ClientKey("rush_qry_a".into()),
            ClientKey("rush_qry_b".into()),
            ClientKey("rush_qry_c".into()),
        );
        let results = tokio::join!(
            verify_client_key(&state, &a),
            verify_client_key(&state, &b),
            verify_client_key(&state, &c),
        );
        assert_eq!(results, (Ok(()), Ok(()), Ok(())));
    }

    #[tokio::test]
    async fn a_disallowed_host_is_refused_before_asking_rush() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::path};

        let api = MockServer::start().await;
        Mock::given(path("/api/v1/whoami"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"principal":{"type":"api_key"}})),
            )
            .expect(1)
            .mount(&api)
            .await;
        let app = Router::new().route("/mcp", get(|| async { "ok" })).layer(
            middleware::from_fn_with_state(Arc::new(auth_state(&api, 1)), authenticate),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });

        let http = reqwest::Client::new();
        let call = |host: &'static str| {
            http.get(format!("http://{addr}/mcp"))
                .header(header::HOST, host)
                .bearer_auth("rush_qry_abc")
                .send()
        };
        assert_eq!(call("evil.example").await.unwrap().status(), 403);
        assert_eq!(call("evil.example:80").await.unwrap().status(), 403);
        assert_eq!(call("localhost").await.unwrap().status(), 200);
    }

    #[test]
    fn token_comparison_is_length_and_content_exact() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
