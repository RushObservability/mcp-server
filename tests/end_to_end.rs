//! A real MCP client talking to the server in-process, with Rush mocked.

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use rmcp::model::{
    CallToolRequestParams, GetPromptRequestParams, ReadResourceRequestParams, ResourceContents,
};
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

#[tokio::test]
async fn prompts_render_with_arguments() {
    let rush = MockServer::start().await;
    let client = connect(&rush, &[]).await;
    let prompts = client.list_all_prompts().await.unwrap();
    assert_eq!(prompts.len(), 5);
    let got = client
        .get_prompt(
            GetPromptRequestParams::new("triage_service").with_arguments(
                json!({"service": "checkout", "last": "24h"})
                    .as_object()
                    .cloned()
                    .unwrap(),
            ),
        )
        .await
        .unwrap();
    let text = serde_json::to_string(&got.messages).unwrap();
    assert!(text.contains("`checkout`"), "{text}");
    assert!(text.contains("last 24h"), "{text}");
    assert!(text.contains("get_service"));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn resources_return_tool_output_as_json() {
    let rush = MockServer::start().await;
    Mock::given(path("/api/v1/services/graph"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"nodes": [{"service_name": "api", "request_count": 10, "error_count": 1, "p95_ms": 12.5}], "edges": []})))
        .mount(&rush)
        .await;
    let client = connect(&rush, &[]).await;
    let uris: Vec<String> = client
        .list_all_resources()
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.uri.to_string())
        .collect();
    assert_eq!(uris, ["rush://context", "rush://services"]);
    let read = client
        .read_resource(ReadResourceRequestParams::new("rush://services"))
        .await
        .unwrap();
    let ResourceContents::TextResourceContents {
        text, mime_type, ..
    } = &read.contents[0]
    else {
        panic!("expected text")
    };
    assert_eq!(mime_type.as_deref(), Some("application/json"));
    let v: Value = serde_json::from_str(text).unwrap();
    assert_eq!(v["result"]["services"][0]["service"], "api");
    assert!(
        client
            .read_resource(ReadResourceRequestParams::new("rush://nope"))
            .await
            .is_err()
    );
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn monitors_are_listed_worst_first_and_previews_explain_missing_write_access() {
    let rush = MockServer::start().await;
    Mock::given(path("/api/v1/monitors"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"monitors": [
            {"id": "m1", "name": "latency", "type": "apm", "state": "ok", "enabled": true},
            {"id": "m2", "name": "errors", "type": "apm", "state": "alert", "enabled": true, "group_states": {"service=checkout": "alert"}},
            {"id": "m3", "name": "old", "type": "log", "state": "alert", "enabled": false}
        ]})))
        .mount(&rush)
        .await;
    Mock::given(path("/api/v1/monitors/preview"))
        .respond_with(ResponseTemplate::new(403).set_body_string("write role required"))
        .mount(&rush)
        .await;
    let client = connect(&rush, &[]).await;
    let (is_error, out, _) = call(&client, "list_monitors", json!({})).await;
    assert!(!is_error, "{out}");
    assert_eq!(
        out["summary"],
        "3 monitors: 1 alert, 0 warn, 0 no data, 1 muted."
    );
    assert_eq!(out["result"]["monitors"][0]["id"], "m2");
    assert_eq!(
        out["result"]["monitors"][0]["problem_groups"][0],
        "service=checkout (alert)"
    );
    assert_eq!(out["result"]["monitors"][2]["muted"], true);

    let (is_error, _, text) = call(&client, "preview_monitor", json!({"type": "apm", "query_config": {"service": "checkout", "metric": "error_rate"}, "critical": 5})).await;
    assert!(is_error);
    assert!(text.contains("write-role"), "{text}");
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn widget_data_runs_the_widget_query_with_variables() {
    let rush = MockServer::start().await;
    Mock::given(path("/api/v1/dashboards/d1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "d1", "name": "Checkout", "defaults": {"time_range_minutes": 30},
            "variables": [{"name": "service", "type": "static", "default": "api"}],
            "widgets": [{"id": "w1", "title": "Errors by path", "widget_type": "bar",
                         "query_config": {"source": "spans", "group_by": ["http_path"], "filters": [{"field": "service_name", "op": "=", "value": "$service"}]}}]
        })))
        .mount(&rush)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/query/group"))
        .and(body_partial_json(json!({"group_by": ["http_path"], "filters": [{"field": "service_name", "op": "=", "value": "checkout"}]})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"groups": [{"http_path": "/pay", "count": 7}]})))
        .expect(1)
        .mount(&rush)
        .await;
    let client = connect(&rush, &[]).await;
    let (is_error, out, _) = call(&client, "get_widget_data", json!({"dashboard": "https://rush.example.com/dashboards/d1", "widget": "errors by path", "variables": {"service": "checkout"}})).await;
    assert!(!is_error, "{out}");
    assert_eq!(
        out["result"]["queries"][0]["groups"][0],
        json!({"key": "/pay", "value": 7.0})
    );
    assert_eq!(
        out["result"]["queries"][0]["query"],
        "service_name=checkout"
    );
    client.cancel().await.unwrap();
}

fn sse(events: &[Value]) -> String {
    events
        .iter()
        .map(|e| format!("data: {e}\n\n"))
        .collect::<Vec<_>>()
        .join(": keep-alive\n\n")
}

#[tokio::test]
async fn start_investigation_streams_the_agent_report() {
    let rush = MockServer::start().await;
    mock_whoami(&rush).await;
    Mock::given(path("/api/v1/investigation-templates"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"templates": [
            {"id": "alert_investigation", "name": "Investigate Alert", "description": "d", "prompt_modifier": "secret prompt", "auto_tools": []}
        ]})))
        .mount(&rush)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/investigate"))
        .and(body_partial_json(json!({"question": "Why are checkout errors up?", "template_id": "alert_investigation"})))
        .respond_with(ResponseTemplate::new(200).insert_header("content-type", "text/event-stream").set_body_string(sse(&[
            json!({"type": "session_created", "session_id": "s-42"}),
            json!({"type": "tool_call", "name": "search_logs", "args": {"service": "checkout"}}),
            json!({"type": "tool_result", "name": "search_logs", "data": "31 errors: pool timeout"}),
            json!({"type": "summary", "text": "Connection pool exhausted after the 14:02 deploy.", "kind": "final"}),
            json!({"type": "done", "rounds": 2, "tool_calls": 1, "prompt_tokens": 800, "completion_tokens": 90, "session_id": "s-42", "model": "m"}),
        ])))
        .expect(1)
        .mount(&rush)
        .await;
    // Rush hasn't stored the report yet; the stream's report is used.
    Mock::given(path("/api/v1/sessions/s-42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "session": {"id": "s-42", "title": "Why are checkout errors up?", "status": "active", "working_memory": "{}"},
            "turns": [{"turn_index": 0, "role": "user", "content": "Why are checkout errors up?", "tool_calls": "[]", "report_kind": "", "created_at": "2026-10-18 14:00:00.000"}]
        })))
        .mount(&rush)
        .await;
    let client = connect(&rush, &[]).await;

    let (is_error, out, text) = call(
        &client,
        "start_investigation",
        json!({"question": "Why are checkout errors up?", "template": "alert_investigation", "last": "30m", "wait_seconds": 5}),
    )
    .await;
    assert!(!is_error, "{text}");
    let r = &out["result"];
    assert_eq!(r["session_id"], "s-42");
    assert_eq!(r["status"], "completed");
    assert_eq!(
        r["report"],
        "Connection pool exhausted after the 14:02 deploy."
    );
    assert_eq!(
        r["steps"][0],
        json!({"tool": "search_logs", "input": "service=checkout", "result": "31 errors: pool timeout"})
    );
    assert_eq!(
        out["links"]["investigation"],
        "https://rush.example.com/sre-agent/s-42?tenant=prod"
    );

    // Rush picks the tenant and tool scopes; the server never sends them.
    let requests = rush.received_requests().await.unwrap();
    let body: Value = requests
        .iter()
        .find(|r| r.url.path() == "/api/v1/investigate")
        .map(|r| serde_json::from_slice(&r.body).unwrap())
        .unwrap();
    assert!(
        body.get("tenant_id").is_none() && body.get("scopes").is_none(),
        "{body}"
    );
    assert_eq!(body["window"]["selection_reason"], "user_provided_range");

    let (is_error, _, text) = call(
        &client,
        "start_investigation",
        json!({"question": "x", "template": "nope"}),
    )
    .await;
    assert!(is_error);
    assert!(
        text.contains("known templates: alert_investigation"),
        "{text}"
    );

    let (is_error, out, _) = call(&client, "list_investigation_templates", json!({})).await;
    assert!(!is_error);
    assert!(
        out["result"]["templates"][0]
            .get("prompt_modifier")
            .is_none()
    );
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn get_investigation_reads_the_stored_session() {
    let rush = MockServer::start().await;
    mock_whoami(&rush).await;
    Mock::given(path("/api/v1/sessions/s-7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "session": {"id": "s-7", "title": "Latency on /pay", "status": "active", "template_id": "", "prompt_tokens": 1200, "completion_tokens": 300, "llm_model": "m"},
            "turns": [
                {"turn_index": 0, "role": "user", "content": "Why is /pay slow?", "tool_calls": "[]", "report_kind": "", "created_at": "2026-10-18 14:00:00"},
                {"turn_index": 1, "role": "assistant", "content": "Which region do you mean?", "report_kind": "question", "created_at": "2026-10-18 14:01:00",
                 "tool_calls": "[{\"type\":\"tool_call\",\"name\":\"get_service\",\"args\":{\"name\":\"pay\"}},{\"type\":\"tool_result\",\"name\":\"get_service\",\"data\":\"p95 2.1s\"}]"}
            ]
        })))
        .mount(&rush)
        .await;
    Mock::given(path("/api/v1/sessions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"sessions": [
            {"id": "s-7", "title": "Latency on /pay", "status": "active", "updated_at": "2026-10-18 14:01:00", "prompt_tokens": 1200, "completion_tokens": 300}
        ]})))
        .mount(&rush)
        .await;
    let client = connect(&rush, &[]).await;

    let (is_error, out, text) = call(
        &client,
        "get_investigation",
        json!({"session_id": "https://rush.example.com/sre-agent/s-7"}),
    )
    .await;
    assert!(!is_error, "{text}");
    assert_eq!(out["result"]["status"], "needs_answer");
    assert_eq!(out["result"]["report"], "Which region do you mean?");
    assert_eq!(out["result"]["steps"][0]["result"], "p95 2.1s");
    assert_eq!(out["result"]["usage"]["completion_tokens"], 300);
    assert!(
        out["summary"]
            .as_str()
            .unwrap()
            .contains("continue_investigation")
    );

    let (is_error, out, _) = call(&client, "list_investigations", json!({"limit": 5})).await;
    assert!(!is_error);
    assert_eq!(out["result"]["investigations"][0]["tokens"], 1500);
    assert_eq!(
        out["result"]["investigations"][0]["link"],
        "https://rush.example.com/sre-agent/s-7?tenant=prod"
    );
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn keys_without_agent_access_get_setup_help() {
    let rush = MockServer::start().await;
    Mock::given(path("/api/v1/investigate"))
        .respond_with(
            ResponseTemplate::new(403).set_body_string("API key does not have agent access"),
        )
        .mount(&rush)
        .await;
    Mock::given(path("/api/v1/parse-query"))
        .respond_with(ResponseTemplate::new(501).set_body_string("LLM disabled"))
        .mount(&rush)
        .await;
    let client = connect(&rush, &[]).await;
    let (is_error, _, text) =
        call(&client, "start_investigation", json!({"question": "why?"})).await;
    assert!(is_error);
    assert!(text.contains("does not have agent access"), "{text}");
    assert!(
        text.contains("Allow SRE agent and natural-language search"),
        "{text}"
    );

    let (is_error, _, text) = call(
        &client,
        "parse_query",
        json!({"query": "errors in checkout"}),
    )
    .await;
    assert!(is_error);
    assert!(text.contains("turned off"), "{text}");
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn parse_query_returns_filters_for_the_signal_and_a_link() {
    let rush = MockServer::start().await;
    mock_whoami(&rush).await;
    Mock::given(method("POST"))
        .and(path("/api/v1/parse-query"))
        .and(body_partial_json(
            json!({"query": "500 errors from checkout"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "filters": [
                {"field": "service_name", "op": "=", "value": "checkout"},
                {"field": "status_code", "op": ">=", "value": 500},
                {"field": "level", "op": "=", "value": "warn"}
            ],
            "search": "",
            "confidence": 0.92
        })))
        .mount(&rush)
        .await;
    let client = connect(&rush, &[]).await;
    let (is_error, out, text) = call(
        &client,
        "parse_query",
        json!({"query": "500 errors from checkout", "signal": "spans"}),
    )
    .await;
    assert!(!is_error, "{text}");
    assert_eq!(
        out["result"]["filters"],
        json!([
            {"field": "service_name", "op": "=", "value": "checkout"},
            {"field": "http_status_code", "op": ">=", "value": 500}
        ])
    );
    assert_eq!(out["result"]["dropped"].as_array().unwrap().len(), 1);
    let link = out["links"]["explore"].as_str().unwrap();
    assert!(
        link.contains("mode=spans") && link.contains("http_status_code%3E%3D500"),
        "{link}"
    );
    client.cancel().await.unwrap();
}
