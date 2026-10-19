use std::net::SocketAddr;

use clap::{Parser, ValueEnum};
use url::Url;

use crate::toolsets::Toolset;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Transport {
    /// One client over stdin/stdout (Claude Desktop, Claude Code, Cursor).
    Stdio,
    /// Streamable HTTP for shared deployments.
    Http,
}

/// Rush MCP server: lets AI assistants query Rush Observability.
#[derive(Debug, Clone, Parser)]
#[command(name = "rush-mcp", version, about)]
pub struct Config {
    /// Rush API base URL, e.g. https://rush.example.com
    #[arg(long = "url", env = "RUSH_URL")]
    pub url: Url,

    /// Rush web UI base URL used for links in results. Defaults to --url.
    #[arg(long = "web-url", env = "RUSH_WEB_URL")]
    pub web_url: Option<Url>,

    /// Query API key (`rush_qry_…`). Required for stdio. In HTTP mode it is
    /// used for clients that do not send their own key.
    #[arg(long = "api-key", env = "RUSH_API_KEY", hide_env_values = true)]
    pub api_key: Option<String>,

    /// File holding the API key, re-read on every request so rotation needs
    /// no restart. Takes precedence over --api-key.
    #[arg(long = "api-key-file", env = "RUSH_API_KEY_FILE")]
    pub api_key_file: Option<std::path::PathBuf>,

    /// Toolsets to enable (comma-separated), or `all`.
    #[arg(
        long,
        env = "RUSH_MCP_TOOLSETS",
        value_delimiter = ',',
        default_value = "core,analysis,alerting,changes,saved_queries"
    )]
    pub toolsets: Vec<String>,

    /// Only expose these tools (comma-separated), within the enabled toolsets.
    #[arg(long = "enable-tools", value_delimiter = ',')]
    pub enable_tools: Vec<String>,

    /// Hide these tools (comma-separated).
    #[arg(long = "disable-tools", value_delimiter = ',')]
    pub disable_tools: Vec<String>,

    /// Byte budget for one tool result before samples and long strings are cut.
    #[arg(
        long = "max-result-bytes",
        env = "RUSH_MCP_MAX_RESULT_BYTES",
        default_value_t = 16_384
    )]
    pub max_result_bytes: usize,

    #[arg(long, value_enum, default_value = "stdio")]
    pub transport: Transport,

    /// HTTP listen address.
    #[arg(long, env = "RUSH_MCP_LISTEN", default_value = "127.0.0.1:8090")]
    pub listen: SocketAddr,

    /// HTTP path for the MCP endpoint.
    #[arg(long = "base-path", env = "RUSH_MCP_BASE_PATH", default_value = "/mcp")]
    pub base_path: String,

    /// Bearer token clients must send to use the server's own API key in HTTP
    /// mode. Required when listening on a non-loopback address with --api-key.
    #[arg(
        long = "server-token",
        env = "RUSH_MCP_SERVER_TOKEN",
        hide_env_values = true
    )]
    pub server_token: Option<String>,

    /// Allowed Host header values in HTTP mode (DNS-rebinding protection).
    /// Defaults to loopback names.
    #[arg(
        long = "allowed-hosts",
        env = "RUSH_MCP_ALLOWED_HOSTS",
        value_delimiter = ','
    )]
    pub allowed_hosts: Vec<String>,

    /// Allowed browser Origins in HTTP mode, e.g. https://app.example.com:443
    #[arg(
        long = "allowed-origins",
        env = "RUSH_MCP_ALLOWED_ORIGINS",
        value_delimiter = ','
    )]
    pub allowed_origins: Vec<String>,

    /// Extra text appended to the server instructions sent to clients.
    #[arg(long = "instructions-append", env = "RUSH_MCP_INSTRUCTIONS_APPEND")]
    pub instructions_append: Option<String>,

    /// Upstream request timeout in seconds.
    #[arg(
        long = "timeout-secs",
        env = "RUSH_MCP_TIMEOUT_SECS",
        default_value_t = 30
    )]
    pub timeout_secs: u64,
}

impl Config {
    pub fn web_url(&self) -> &Url {
        self.web_url.as_ref().unwrap_or(&self.url)
    }

    /// Parse the `--toolsets` list into known toolsets.
    pub fn enabled_toolsets(&self) -> Result<Vec<Toolset>, String> {
        let mut out = Vec::new();
        for raw in &self.toolsets {
            let name = raw.trim();
            if name.is_empty() {
                continue;
            }
            if name.eq_ignore_ascii_case("all") {
                return Ok(Toolset::ALL.to_vec());
            }
            let toolset = Toolset::parse(name).ok_or_else(|| {
                format!(
                    "unknown toolset `{name}`; known toolsets: {}",
                    Toolset::ALL
                        .iter()
                        .map(|t| t.name())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;
            if !out.contains(&toolset) {
                out.push(toolset);
            }
        }
        if out.is_empty() {
            return Err("at least one toolset must be enabled".into());
        }
        Ok(out)
    }

    /// Startup checks that need more than clap's per-flag validation.
    pub fn validate(&self) -> Result<(), String> {
        self.enabled_toolsets()?;
        check_scheme(&self.url, "--url")?;
        check_scheme(self.web_url(), "--web-url")?;
        if self.max_result_bytes < 2_048 {
            return Err("--max-result-bytes must be at least 2048".into());
        }
        let has_key = self.api_key.is_some() || self.api_key_file.is_some();
        match self.transport {
            Transport::Stdio if !has_key => {
                Err("stdio mode needs an API key: set RUSH_API_KEY or RUSH_API_KEY_FILE".into())
            }
            Transport::Http
                if has_key && self.server_token.is_none() && !self.listen.ip().is_loopback() =>
            {
                Err(
                    "refusing to share the server's API key on a non-loopback address without \
                     RUSH_MCP_SERVER_TOKEN; set a token or have clients send their own key"
                        .into(),
                )
            }
            _ => Ok(()),
        }
    }
}

/// Keys must not travel over plain HTTP except to the local machine.
fn check_scheme(url: &Url, flag: &str) -> Result<(), String> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_host(url) => Ok(()),
        "http" => Err(format!(
            "{flag} uses plain http to a non-loopback host; use https so the API key is not sent in clear text"
        )),
        other => Err(format!("{flag} must be http or https, not `{other}`")),
    }
}

pub fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => {
            d.eq_ignore_ascii_case("localhost") || d.ends_with(".localhost")
        }
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Config {
        let mut full = vec!["rush-mcp"];
        full.extend_from_slice(args);
        Config::try_parse_from(full).unwrap()
    }

    #[test]
    fn stdio_requires_a_key() {
        let cfg = parse(&["--url", "https://rush.example.com"]);
        assert!(cfg.validate().unwrap_err().contains("API key"));
        let cfg = parse(&[
            "--url",
            "https://rush.example.com",
            "--api-key",
            "rush_qry_x",
        ]);
        cfg.validate().unwrap();
    }

    #[test]
    fn plain_http_is_only_allowed_to_loopback() {
        for ok in [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
        ] {
            parse(&["--url", ok, "--api-key", "k"]).validate().unwrap();
        }
        let err = parse(&["--url", "http://rush.example.com", "--api-key", "k"])
            .validate()
            .unwrap_err();
        assert!(err.contains("https"));
    }

    #[test]
    fn http_mode_refuses_to_share_a_key_publicly_without_a_token() {
        let base = [
            "--url",
            "https://r.example.com",
            "--transport",
            "http",
            "--api-key",
            "k",
        ];
        let mut public = base.to_vec();
        public.extend(["--listen", "0.0.0.0:8090"]);
        assert!(parse(&public).validate().is_err());
        public.extend(["--server-token", "t"]);
        parse(&public).validate().unwrap();
        // Loopback, or no shared key at all, is fine.
        parse(&base).validate().unwrap();
        parse(&[
            "--url",
            "https://r.example.com",
            "--transport",
            "http",
            "--listen",
            "0.0.0.0:8090",
        ])
        .validate()
        .unwrap();
    }

    #[test]
    fn toolsets_parse_and_reject_unknown_names() {
        let cfg = parse(&[
            "--url",
            "https://r.example.com",
            "--api-key",
            "k",
            "--toolsets",
            "core,all",
        ]);
        assert_eq!(cfg.enabled_toolsets().unwrap(), Toolset::ALL.to_vec());
        let cfg = parse(&[
            "--url",
            "https://r.example.com",
            "--api-key",
            "k",
            "--toolsets",
            "core,nope",
        ]);
        assert!(cfg.enabled_toolsets().unwrap_err().contains("nope"));
    }
}
