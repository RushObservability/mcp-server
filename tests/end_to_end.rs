//! A real MCP client talking to the server in-process, with Rush mocked.

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use rmcp::model::CallToolRequestParams;
use rmcp::{RoleClient, ServiceExt, service::RunningService};
use serde_json::{Value, json};
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use rush_mcp::client::{KeySource, RushClient};
use rush_mcp::config::Config;
use rush_mcp::server::{AppState, RushMcp};

async fn connect(rush: &MockServer, extra: &[&str]) -> RunningService<RoleClient, ()> {
    let mut args = vec![
        "rush-mcp",
        "--url",
        "http://127.0.0.1:1",
        "--web-url",
        "https://rush.example.com",
        "--api-key",
        "rush_qry_test",
    ];
    if !extra.contains(&"--toolsets") {
        args.extend(["--toolsets", "all"]);
    }
    args.extend_from_slice(extra);
    let config = Config::try_parse_from(args).unwrap();
    let client = RushClient::new(
        url::Url::parse(&rush.uri()).unwrap(),
        KeySource::Static("rush_qry_test".into()),
        Duration::from_secs(5),
    )
    .unwrap();
    let state = Arc::new(AppState::from_config(&config, client).unwrap());
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let server = RushMcp::new(state).serve(server_io).await.unwrap();
        let _ = server.waiting().await;
    });
    ().serve(client_io).await.unwrap()
}

async fn call(
    client: &RunningService<RoleClient, ()>,
    tool: &'static str,
    args: Value,
) -> (bool, Value, String) {
    let res = client
        .call_tool(
            CallToolRequestParams::new(tool)
                .with_arguments(args.as_object().cloned().unwrap_or_default()),
        )
        .await
        .unwrap();
    let text = res
        .content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.clone()))
        .collect::<Vec<_>>()
        .join("\n");
    (
        res.is_error.unwrap_or(false),
        res.structured_content.unwrap_or(Value::Null),
        text,
    )
}

async fn mock_whoami(rush: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/api/v1/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tenant_id": "prod",
            "principal": {"type": "api_key", "id": "k1", "name": "MCP", "role": "viewer"},
            "capabilities": {"read": true, "write": false, "admin": false}
        })))
        .mount(rush)
        .await;
}

#[tokio::test]
async fn initialize_advertises_tools_and_instructions() {
    let rush = MockServer::start().await;
    let client = connect(&rush, &[]).await;
    let info = client.peer_info().unwrap();
    assert_eq!(info.server_info.as_ref().unwrap().name, "rush-mcp");
    assert!(
        info.instructions
            .as_deref()
            .unwrap()
            .contains("untrusted data")
    );
    let tools = client.list_all_tools().await.unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    for want in [
        "get_context",
        "search_logs",
        "get_trace",
        "query_metrics",
        "compare_cohorts",
        "list_deploys",
        "run_saved_query",
    ] {
        assert!(names.contains(&want), "missing {want}");
    }
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn toolset_flags_limit_what_clients_see() {
    let rush = MockServer::start().await;
    let client = connect(
        &rush,
        &["--toolsets", "changes", "--disable-tools", "nothing"],
    )
    .await;
    let tools = client.list_all_tools().await.unwrap();
    assert_eq!(
        tools.iter().map(|t| t.name.as_ref()).collect::<Vec<_>>(),
        ["list_deploys"]
    );
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn search_logs_returns_a_summary_with_tenant_links() {
    let rush = MockServer::start().await;
    mock_whoami(&rush).await;
    Mock::given(method("POST"))
        .and(path("/api/v1/explore/search"))
        .and(header("authorization", "Bearer rush_qry_test"))
        .and(header("x-rush-mcp-tool", "search_logs"))
        .and(body_partial_json(json!({"signal": "logs", "filters": [{"field": "service_name", "op": "=", "value": "checkout"}]})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "signal": "logs",
            "rows": [{"Timestamp": 1760796000000000000_i64, "ServiceName": "checkout", "SeverityText": "ERROR",
                      "Body": "payment provider timeout", "TimestampNs": "1760796000000000000", "BlockNumber": "1",
                      "BlockOffset": "2", "BodyHash": "3", "TraceId": "4bf92f3577b34da6a3ce929d0e0e4736"}],
            "count": {"value": 42, "kind": "exact"},
            "summary": {"histogram": [{"bucket": "2026-10-18 14:00:00", "count": 42, "error_count": 0}],
                        "facets": {"services": [{"key": "checkout", "count": 42}], "statuses": [{"key": "error", "count": 7}], "methods": []},
                        "groups": [], "interval_secs": 60},
            "errors": {}
        })))
        .expect(1)
        .mount(&rush)
        .await;
    let client = connect(&rush, &[]).await;
    let (is_error, out, _) = call(
        &client,
        "search_logs",
        json!({"service": "checkout", "last": "30m", "search": "timeout"}),
    )
    .await;
    assert!(!is_error, "{out}");
    assert_eq!(
        out["summary"],
        "42 logs, 7 at error level; top service checkout (42)."
    );
    assert_eq!(out["result"]["total"], 42);
    assert_eq!(out["result"]["samples"][0]["ref"]["body_hash"], "3");
    let link = out["links"]["explore"].as_str().unwrap();
    assert!(
        link.starts_with(
            "https://rush.example.com/?q=service_name%3Dcheckout+timeout&mode=logs&t=30"
        ),
        "{link}"
    );
    assert!(link.ends_with("&tenant=prod"), "{link}");
    assert_eq!(out["truncated"], false);
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn upstream_rejections_come_back_as_readable_tool_errors() {
    let rush = MockServer::start().await;
    Mock::given(path("/api/v1/traces/4bf92f3577b34da6a3ce929d0e0e4736"))
        .respond_with(ResponseTemplate::new(404).set_body_string("trace not found"))
        .mount(&rush)
        .await;
    Mock::given(path("/prom/api/v1/query_range"))
        .respond_with(ResponseTemplate::new(400).set_body_string("PromQL error: unexpected token"))
        .mount(&rush)
        .await;
    let client = connect(&rush, &[]).await;

    let (is_error, _, text) = call(
        &client,
        "get_trace",
        json!({"trace": "https://rush.example.com/trace/4bf92f3577b34da6a3ce929d0e0e4736"}),
    )
    .await;
    assert!(is_error);
    assert!(text.contains("trace not found"), "{text}");

    let (is_error, _, text) = call(&client, "get_trace", json!({"trace": "nope"})).await;
    assert!(is_error);
    assert!(text.contains("32-hex"), "{text}");

    let (is_error, _, text) = call(&client, "query_metrics", json!({"query": "rate(x[5m]"})).await;
    assert!(is_error);
    assert!(text.contains("PromQL error: unexpected token"), "{text}");

    let (is_error, _, text) = call(
        &client,
        "search_spans",
        json!({"from": "now", "to": "now-1h"}),
    )
    .await;
    assert!(is_error);
    assert!(text.contains("must be before"), "{text}");
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn get_trace_summarizes_and_links_the_trace() {
    let rush = MockServer::start().await;
    mock_whoami(&rush).await;
    Mock::given(path("/api/v1/traces/4bf92f3577b34da6a3ce929d0e0e4736"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736", "span_count": 2, "duration_ns": 120000000, "services": ["api", "db"],
            "spans": [{"span_id": "a", "service_name": "api", "span_name": "GET /pay", "duration_ns": 120000000, "status": "STATUS_CODE_OK",
                       "timestamp": "2026-10-18 14:00:00.000000000", "attributes": {}, "events": [],
                       "children": [{"span_id": "b", "service_name": "db", "span_name": "SELECT", "duration_ns": 100000000,
                                     "status": "STATUS_CODE_ERROR", "timestamp": "2026-10-18 14:00:00.010000000", "attributes": {}, "events": [], "children": []}]}]
        })))
        .mount(&rush)
        .await;
    let client = connect(&rush, &[]).await;
    let (is_error, out, _) = call(
        &client,
        "get_trace",
        json!({"trace": "4bf92f3577b34da6a3ce929d0e0e4736"}),
    )
    .await;
    assert!(!is_error, "{out}");
    assert_eq!(out["result"]["critical_path"].as_array().unwrap().len(), 2);
    assert_eq!(out["result"]["errors"][0]["service"], "db");
    assert_eq!(
        out["links"]["trace"],
        "https://rush.example.com/trace/4bf92f3577b34da6a3ce929d0e0e4736?tenant=prod"
    );
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn results_respect_the_byte_budget() {
    let rush = MockServer::start().await;
    let rows: Vec<Value> = (0..50)
        .map(|i| json!({"timestamp": 1760796000000000000_i64 + i, "service_name": "svc", "span_name": "x".repeat(300), "duration_ns": 1000, "trace_id": "t", "span_id": "s"}))
        .collect();
    Mock::given(path("/api/v1/explore/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"rows": rows, "count": {"value": 50, "kind": "exact"}, "summary": {"histogram": [], "facets": {}, "groups": []}})))
        .mount(&rush)
        .await;
    Mock::given(path("/api/v1/query/timeseries"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"buckets": [], "grouped": false})),
        )
        .mount(&rush)
        .await;
    let client = connect(&rush, &["--max-result-bytes", "4096"]).await;
    let (is_error, out, _) = call(&client, "search_spans", json!({"samples": 50})).await;
    assert!(!is_error, "{out}");
    assert_eq!(out["truncated"], true);
    assert!(serde_json::to_vec(&out).unwrap().len() <= 4096);
    client.cancel().await.unwrap();
}
