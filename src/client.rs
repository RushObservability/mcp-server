//! HTTP client for the Rush query API.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reqwest::{Method, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use url::Url;

use crate::envelope::clip;

const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_ERROR_BODY_BYTES: usize = 2048;
/// How long a key read from RUSH_API_KEY_FILE is reused before the file is read again.
const KEY_FILE_TTL: Duration = Duration::from_secs(1);

/// Where the server's own API key comes from.
#[derive(Debug, Clone)]
pub enum KeySource {
    Static(String),
    /// Re-read at most once a second so a rotated key takes effect without a restart.
    File(PathBuf),
    None,
}

impl KeySource {
    pub fn read(&self) -> Result<Option<String>, ApiError> {
        match self {
            KeySource::Static(k) => Ok(Some(k.trim().to_string())),
            KeySource::File(path) => std::fs::read_to_string(path)
                .map(|k| Some(k.trim().to_string()))
                .map_err(|e| {
                    ApiError::Config(format!(
                        "can't read RUSH_API_KEY_FILE {}: {e}",
                        path.display()
                    ))
                }),
            KeySource::None => Ok(None),
        }
    }
}

/// A Rush API key supplied by the HTTP client for its own requests.
#[derive(Debug, Clone)]
pub struct ClientKey(pub String);

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    Config(String),
    #[error("Rush rejected the request: {0}")]
    BadRequest(String),
    #[error(
        "The Rush API key was rejected (missing, invalid or revoked{prefix}). Check RUSH_API_KEY.",
        prefix = .0.as_deref().map(|p| format!("; key {p}…")).unwrap_or_default()
    )]
    Unauthorized(Option<String>),
    #[error("The Rush API key isn't allowed to do this: {0}")]
    Forbidden(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Rush is rate limiting this key{}; wait before retrying.", .0.map(|s| format!(" (retry after {s}s)")).unwrap_or_default())]
    RateLimited(Option<u64>),
    #[error("Rush is temporarily unavailable ({0}); try again shortly.")]
    Unavailable(String),
    #[error("Rush returned HTTP {0}: {1}")]
    Upstream(u16, String),
    #[error("Couldn't reach Rush at {0}: {1}")]
    Network(String, String),
    #[error("Rush returned more than {0} bytes. Narrow the query or lower the result limit.")]
    ResponseTooLarge(usize),
    #[error(
        "Rush returned a response this server couldn't read ({0}). The Rush API may be a different version."
    )]
    Decode(String),
}

impl ApiError {
    pub fn is_not_found(&self) -> bool {
        matches!(self, ApiError::NotFound(_))
    }
}

#[derive(Debug, Clone)]
pub struct RushClient {
    http: reqwest::Client,
    base: Url,
    key: KeySource,
    /// The last key read from a key file, and when it was read.
    file_key: Arc<Mutex<Option<(Instant, String)>>>,
}

impl RushClient {
    pub fn new(base: Url, key: KeySource, timeout: Duration) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(concat!("rush-mcp/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            http,
            base,
            key,
            file_key: Arc::default(),
        })
    }

    pub fn base(&self) -> &Url {
        &self.base
    }

    /// The key for one request: the HTTP client's own key if it sent one,
    /// otherwise the server's configured key.
    async fn resolve_key(&self, client_key: Option<&ClientKey>) -> Result<String, ApiError> {
        if let Some(ClientKey(k)) = client_key {
            return Ok(k.clone());
        }
        let key = match &self.key {
            KeySource::File(_) => self.read_key_file().await?,
            other => other.read()?,
        };
        key.filter(|k| !k.is_empty())
            .ok_or(ApiError::Unauthorized(None))
    }

    /// The key file's contents, reused for `KEY_FILE_TTL` and read off the
    /// async runtime so requests don't block on the filesystem.
    async fn read_key_file(&self) -> Result<Option<String>, ApiError> {
        if let Some((read_at, key)) = &*self.file_key.lock().unwrap_or_else(|e| e.into_inner())
            && read_at.elapsed() < KEY_FILE_TTL
        {
            return Ok(Some(key.clone()));
        }
        let source = self.key.clone();
        let key = tokio::task::spawn_blocking(move || source.read())
            .await
            .map_err(|e| ApiError::Config(format!("can't read RUSH_API_KEY_FILE: {e}")))??;
        if let Some(k) = &key {
            *self.file_key.lock().unwrap_or_else(|e| e.into_inner()) =
                Some((Instant::now(), k.clone()));
        }
        Ok(key)
    }

    pub async fn get<T: DeserializeOwned>(
        &self,
        client_key: Option<&ClientKey>,
        tool: &str,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<T, ApiError> {
        self.send::<(), T>(Method::GET, client_key, tool, path, query, None)
            .await
    }

    pub async fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        client_key: Option<&ClientKey>,
        tool: &str,
        path: &str,
        body: &B,
    ) -> Result<T, ApiError> {
        self.send(Method::POST, client_key, tool, path, &[], Some(body))
            .await
    }

    /// POST and return the response once its status is a success, so the
    /// caller can read a long-lived body (the SRE agent's event stream).
    /// `timeout` replaces the client's request timeout for this call.
    pub async fn post_stream<B: Serialize>(
        &self,
        client_key: Option<&ClientKey>,
        tool: &str,
        path: &str,
        body: &B,
        timeout: Duration,
    ) -> Result<reqwest::Response, ApiError> {
        let key = self.resolve_key(client_key).await?;
        let req = self
            .request(Method::POST, &key, tool, path)?
            .timeout(timeout)
            .json(body);
        let resp = req
            .send()
            .await
            .map_err(|e| ApiError::Network(self.base.to_string(), network_message(&e)))?;
        if resp.status().is_success() {
            return Ok(resp);
        }
        Err(error_from(resp, &key, path).await)
    }

    fn request(
        &self,
        method: Method,
        key: &str,
        tool: &str,
        path: &str,
    ) -> Result<reqwest::RequestBuilder, ApiError> {
        let url = self
            .base
            .join(path.trim_start_matches('/'))
            .map_err(|e| ApiError::Config(format!("bad API path {path}: {e}")))?;
        Ok(self
            .http
            .request(method, url)
            .bearer_auth(key)
            .header("X-Rush-Client", concat!("mcp/", env!("CARGO_PKG_VERSION")))
            .header("X-Rush-MCP-Tool", tool))
    }

    async fn send<B: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        client_key: Option<&ClientKey>,
        tool: &str,
        path: &str,
        query: &[(&str, String)],
        body: Option<&B>,
    ) -> Result<T, ApiError> {
        let key = self.resolve_key(client_key).await?;
        let value = body
            .map(serde_json::to_value)
            .transpose()
            .map_err(|e| ApiError::Decode(e.to_string()))?;
        let unified = if method == Method::POST {
            value
                .as_ref()
                .and_then(|v| crate::query_contract::adapt(path, v))
        } else if method == Method::GET {
            crate::query_contract::prom_request(path, query)
        } else {
            None
        };
        let mut req = self.request(
            if unified.is_some() {
                Method::POST
            } else {
                method
            },
            &key,
            tool,
            if unified.is_some() {
                crate::query_contract::ENDPOINT
            } else {
                path
            },
        )?;
        if !query.is_empty() && unified.is_none() {
            req = req.query(query);
        }
        if let Some(body) = unified.as_ref() {
            req = req.json(body);
        } else if let Some(body) = body {
            req = req.json(body);
        }
        let started = std::time::Instant::now();
        let resp = req
            .send()
            .await
            .map_err(|e| ApiError::Network(self.base.to_string(), network_message(&e)))?;
        let status = resp.status();
        tracing::debug!(
            tool,
            path,
            status = status.as_u16(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            "rush api call"
        );
        if status.is_success() {
            if resp
                .content_length()
                .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
            {
                return Err(ApiError::ResponseTooLarge(MAX_RESPONSE_BYTES));
            }
            let (bytes, truncated) = body_prefix(resp, MAX_RESPONSE_BYTES)
                .await
                .map_err(|e| ApiError::Network(self.base.to_string(), network_message(&e)))?;
            if truncated {
                return Err(ApiError::ResponseTooLarge(MAX_RESPONSE_BYTES));
            }
            return (if let Some(request) = unified {
                crate::query_contract::decode(&bytes, &request)
            } else {
                serde_json::from_slice(&bytes)
            })
            .map_err(|e| ApiError::Decode(format!("{path}: {e}")));
        }
        Err(error_from(resp, &key, path).await)
    }
}

/// Retain at most `limit` bytes, even when the response has no Content-Length.
async fn body_prefix(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<(Vec<u8>, bool), reqwest::Error> {
    let reserve = response
        .content_length()
        .map_or(0, |n| n.min(limit as u64) as usize);
    let mut bytes = Vec::with_capacity(reserve);
    while let Some(chunk) = response.chunk().await? {
        let remaining = limit - bytes.len();
        bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        if chunk.len() > remaining {
            return Ok((bytes, true));
        }
    }
    Ok((bytes, false))
}

/// Map a failed response to an error the model can act on.
async fn error_from(resp: reqwest::Response, key: &str, path: &str) -> ApiError {
    let status = resp.status();
    let retry_after = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok());
    let (bytes, _) = body_prefix(resp, MAX_ERROR_BODY_BYTES)
        .await
        .unwrap_or_default();
    let text = clip(String::from_utf8_lossy(&bytes).trim(), 500);
    match status {
        StatusCode::BAD_REQUEST
        | StatusCode::UNPROCESSABLE_ENTITY
        | StatusCode::PAYLOAD_TOO_LARGE => ApiError::BadRequest(text),
        StatusCode::UNAUTHORIZED => ApiError::Unauthorized(Some(key.chars().take(12).collect())),
        StatusCode::FORBIDDEN => ApiError::Forbidden(text),
        StatusCode::NOT_FOUND => ApiError::NotFound(if text.is_empty() {
            path.to_string()
        } else {
            text
        }),
        StatusCode::TOO_MANY_REQUESTS => ApiError::RateLimited(retry_after),
        StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT | StatusCode::BAD_GATEWAY => {
            ApiError::Unavailable(if text.is_empty() {
                status.to_string()
            } else {
                text
            })
        }
        other => ApiError::Upstream(other.as_u16(), text),
    }
}

fn network_message(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "the request timed out; narrow the time window or filters".into()
    } else if e.is_connect() {
        "connection failed".into()
    } else {
        e.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn body_reader_retains_only_the_requested_prefix() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/example"))
            .respond_with(ResponseTemplate::new(200).set_body_string("example body"))
            .mount(&server)
            .await;
        for (limit, want, truncated) in [(7, "example", true), (12, "example body", false)] {
            let response = reqwest::get(format!("{}/example", server.uri()))
                .await
                .unwrap();
            let (bytes, over_limit) = body_prefix(response, limit).await.unwrap();
            assert_eq!(bytes, want.as_bytes());
            assert_eq!(over_limit, truncated);
        }
    }

    async fn client(server: &MockServer) -> RushClient {
        RushClient::new(
            Url::parse(&server.uri()).unwrap(),
            KeySource::Static("rush_qry_serverkey0000".into()),
            Duration::from_secs(5),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn sends_the_key_and_client_identity() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/whoami"))
            .and(header("authorization", "Bearer rush_qry_serverkey0000"))
            .and(header("x-rush-mcp-tool", "get_context"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&server)
            .await;
        let v: serde_json::Value = client(&server)
            .await
            .get(None, "get_context", "/api/v1/whoami", &[])
            .await
            .unwrap();
        assert_eq!(v["ok"], true);
    }

    #[tokio::test]
    async fn a_client_key_overrides_the_server_key() {
        let server = MockServer::start().await;
        Mock::given(header("authorization", "Bearer rush_qry_clientkey"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;
        let key = ClientKey("rush_qry_clientkey".into());
        let _: serde_json::Value = client(&server)
            .await
            .get(Some(&key), "t", "/x", &[])
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn maps_upstream_failures_to_actionable_errors() {
        let server = MockServer::start().await;
        for (code, p) in [
            (400, "/bad"),
            (401, "/unauth"),
            (403, "/forbid"),
            (404, "/missing"),
            (429, "/slow"),
            (503, "/down"),
            (500, "/boom"),
        ] {
            let mut resp = ResponseTemplate::new(code).set_body_string(format!("reason {code}"));
            if code == 429 {
                resp = resp.insert_header("retry-after", "7");
            }
            Mock::given(path(p)).respond_with(resp).mount(&server).await;
        }
        let c = client(&server).await;
        let err = |p: &'static str| {
            let c = c.clone();
            async move {
                c.get::<serde_json::Value>(None, "t", p, &[])
                    .await
                    .unwrap_err()
            }
        };
        assert!(matches!(err("/bad").await, ApiError::BadRequest(m) if m == "reason 400"));
        let unauth = err("/unauth").await.to_string();
        assert!(unauth.contains("rush_qry_ser"));
        assert!(
            !unauth.contains("serverkey0000"),
            "never leak more than the prefix"
        );
        assert!(matches!(err("/forbid").await, ApiError::Forbidden(_)));
        assert!(err("/missing").await.is_not_found());
        assert!(err("/slow").await.to_string().contains("retry after 7s"));
        assert!(matches!(err("/down").await, ApiError::Unavailable(_)));
        assert!(matches!(err("/boom").await, ApiError::Upstream(500, _)));
    }

    #[tokio::test]
    async fn body_reader_reserves_the_content_length() {
        let server = MockServer::start().await;
        let body = vec![b'x'; 1_000_000];
        Mock::given(path("/big"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .mount(&server)
            .await;
        let response = reqwest::get(format!("{}/big", server.uri())).await.unwrap();
        let (bytes, over_limit) = body_prefix(response, MAX_RESPONSE_BYTES).await.unwrap();
        assert_eq!((bytes.len(), over_limit), (body.len(), false));
        assert_eq!(bytes.capacity(), body.len(), "one allocation, no regrowth");
    }

    #[tokio::test]
    async fn a_key_file_is_reread_each_request() {
        let dir = std::env::temp_dir().join(format!("rush-mcp-key-{}", std::process::id()));
        std::fs::write(&dir, "rush_qry_one\n").unwrap();
        let source = KeySource::File(dir.clone());
        assert_eq!(source.read().unwrap().as_deref(), Some("rush_qry_one"));
        std::fs::write(&dir, "rush_qry_two").unwrap();
        assert_eq!(source.read().unwrap().as_deref(), Some("rush_qry_two"));
        std::fs::remove_file(dir).unwrap();
    }

    #[tokio::test]
    async fn a_key_file_is_cached_briefly_and_rotation_is_picked_up() {
        let file = std::env::temp_dir().join(format!("rush-mcp-key-ttl-{}", std::process::id()));
        std::fs::write(&file, "rush_qry_one\n").unwrap();
        let c = RushClient::new(
            Url::parse("http://127.0.0.1:1").unwrap(),
            KeySource::File(file.clone()),
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(c.resolve_key(None).await.unwrap(), "rush_qry_one");
        std::fs::write(&file, "rush_qry_two").unwrap();
        assert_eq!(
            c.clone().resolve_key(None).await.unwrap(),
            "rush_qry_one",
            "served from the cache, shared by clones"
        );
        tokio::time::sleep(KEY_FILE_TTL + Duration::from_millis(100)).await;
        assert_eq!(c.resolve_key(None).await.unwrap(), "rush_qry_two");
        std::fs::remove_file(&file).unwrap();
        assert!(matches!(
            c.resolve_key(None).await,
            Ok(k) if k == "rush_qry_two"
        ));
        tokio::time::sleep(KEY_FILE_TTL + Duration::from_millis(100)).await;
        assert!(matches!(
            c.resolve_key(None).await,
            Err(ApiError::Config(_))
        ));
    }
}
