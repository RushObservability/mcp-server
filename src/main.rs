use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use rmcp::ServiceExt;
use tracing_subscriber::EnvFilter;

use rush_mcp::client::{KeySource, RushClient};
use rush_mcp::config::{Config, Transport};
use rush_mcp::server::{AppState, RushMcp};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Logs go to stderr: stdout carries the MCP protocol in stdio mode.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("RUSH_MCP_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let config = Config::parse();
    if let Err(message) = config.validate() {
        eprintln!("rush-mcp: {message}");
        std::process::exit(2);
    }

    let key = match (&config.api_key_file, &config.api_key) {
        (Some(path), _) => KeySource::File(path.clone()),
        (None, Some(key)) => KeySource::Static(key.clone()),
        (None, None) => KeySource::None,
    };
    let client = RushClient::new(
        config.url.clone(),
        key,
        Duration::from_secs(config.timeout_secs),
    )?;
    let state = Arc::new(AppState::from_config(&config, client).map_err(anyhow::Error::msg)?);
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        url = %config.url,
        toolsets = ?state.toolsets.iter().map(|t| t.name()).collect::<Vec<_>>(),
        "starting rush-mcp"
    );

    match config.transport {
        Transport::Stdio => {
            let service = RushMcp::new(state).serve(rmcp::transport::stdio()).await?;
            service.waiting().await?;
        }
        Transport::Http => rush_mcp::http::serve(state, &config).await?,
    }
    Ok(())
}
