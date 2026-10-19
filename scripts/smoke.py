#!/usr/bin/env python3
"""Drive every rush-mcp tool against a real Rush deployment over stdio.

Usage:
    RUSH_URL=https://rush.example.com RUSH_API_KEY=rush_qry_... \
        python3 scripts/smoke.py target/release/rush-mcp

Prints one line per tool call: status, latency, result size, truncation,
link names and the summary. Exits non-zero if any call fails unexpectedly.
"""
import json, os, subprocess, sys, time

if len(sys.argv) != 2 or not os.environ.get("RUSH_URL") or not os.environ.get("RUSH_API_KEY"):
    sys.exit(__doc__)
env = dict(os.environ, RUSH_MCP_TOOLSETS="all", RUSH_MCP_LOG=os.environ.get("RUSH_MCP_LOG", "warn"))
p = subprocess.Popen([sys.argv[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
failures = []
nid = 0
def send(method, params=None, notify=False):
    global nid
    msg = {"jsonrpc": "2.0", "method": method}
    if params is not None: msg["params"] = params
    if not notify:
        nid += 1; msg["id"] = nid
    p.stdin.write(json.dumps(msg) + "\n"); p.stdin.flush()
    if notify: return None
    while True:
        line = p.stdout.readline()
        if not line: raise SystemExit("server exited: " + p.stderr.read()[-2000:])
        resp = json.loads(line)
        if resp.get("id") == nid: return resp
init = send("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "drive", "version": "0"}})
print("server:", init["result"]["serverInfo"]["name"], init["result"]["serverInfo"]["version"])
send("notifications/initialized", notify=True)
tools = send("tools/list", {})["result"]["tools"]
print("tools:", len(tools))
def call(name, args, expect_error=False):
    t0 = time.time()
    r = send("tools/call", {"name": name, "arguments": args})
    ms = int((time.time() - t0) * 1000)
    res = r.get("result") or {}
    if "error" in r:
        print(f"  {name:22} PROTOCOL ERROR {r['error']}"); return None
    sc = res.get("structuredContent")
    size = len(json.dumps(sc)) if sc else 0
    if res.get("isError"):
        print(f"  {name:22} ERROR ({ms}ms): {res['content'][0]['text'][:220]}")
        if not expect_error:
            failures.append(name)
        return None
    hints = "; ".join(h["message"] for h in sc.get("hints", []))
    print(f"  {name:22} ok {ms:5}ms {size:6}B trunc={sc['truncated']!s:5} links={','.join(sc['links'])} | {sc['summary'][:150]}" + (f"  [hint: {hints[:120]}]" if hints else ""))
    return sc
ctx = call("get_context", {})
call("resolve_time", {"last": "6h"})
svc = call("list_services", {"last": "1h"})
service = svc["result"]["services"][0]["service"] if svc and svc["result"]["services"] else None
call("get_service", {"service": service or "x", "last": "1h"})
call("get_service_latency", {"service": service or "x", "last": "1h"})
call("list_fields", {"signal": "spans"})
call("list_fields", {"signal": "logs"})
call("list_field_values", {"signal": "spans", "field": "service_name"})
call("list_field_values", {"signal": "logs", "field": "severity"})
spans = call("search_spans", {"last": "1h", "errors_only": True, "samples": 5})
call("search_spans", {"last": "1h", "service": service, "group_by": "http_path"})
logs = call("search_logs", {"last": "1h", "samples": 5})
call("aggregate", {"signal": "spans", "group_by": "service_name", "last": "1h"})
call("aggregate", {"signal": "spans", "over_time": True, "last": "1h"})
call("aggregate", {"signal": "spans", "group_by": "service_name", "over_time": True, "last": "1h"})
call("aggregate", {"signal": "logs", "group_by": "service_name", "last": "1h"})
call("aggregate", {"signal": "logs", "over_time": True, "last": "1h"})
tid = None
if spans and spans["result"]["samples"]: tid = spans["result"]["samples"][0]["trace_id"]
if tid: call("get_trace", {"trace": tid})
if logs and logs["result"]["samples"]:
    ref = logs["result"]["samples"][0]["ref"]
    call("get_log_record", {"ref": ref})
    call("get_log_context", {"ref": ref, "before": 3, "after": 3})
call("compare_cohorts", {"signal": "spans", "errors_only": True, "last": "1h"})
call("compare_cohorts", {"signal": "logs", "last": "30m"})
call("compare_windows", {"last": "1h"})
m = call("list_metrics", {"limit": 20})
metric = m["result"]["names"][0] if m and m["result"]["names"] else None
if metric:
    call("list_metric_labels", {"metric": metric})
    call("query_metrics", {"query": metric, "last": "1h", "max_series": 5})
    call("query_metrics", {"query": f"count({metric})", "instant": True})
call("query_metrics", {"query": "sum(rate(", "last": "1h"}, expect_error=True)
call("list_deploys", {})
sq = call("list_saved_queries", {})
if sq and sq["result"]["queries"]:
    call("run_saved_query", {"saved_query": sq["result"]["queries"][0]["id"]})
call("get_link", {"kind": "explore", "signal": "logs", "service": service, "last": "15m"})
p.stdin.close(); p.terminate()
if failures:
    sys.exit(f"failed: {', '.join(failures)}")
print("all tool calls succeeded")
