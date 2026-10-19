# Rush MCP Server

`rush-mcp` is a [Model Context Protocol](https://modelcontextprotocol.io)
server for [Rush Observability](https://github.com/RushObservability). It lets
AI assistants such as Claude Code, Claude Desktop, Cursor and VS Code search
logs and APM spans, read traces, run PromQL, check service health, compare
time windows, read monitors, SLOs, anomalies and dashboards, run saved
queries, and hand deeper investigations to the Rush SRE agent, and link every
answer back to the Rush UI.

> **Status:** read-only, apart from starting SRE agent investigations (opt-in).
> Write tools (muting monitors, recording deploys) come in a later release.

## How it works

Each tool makes one or two bounded calls to the Rush query API and returns a
small summary rather than raw rows: totals, top groups, a count series, a few
samples, and `links` into the Rush UI for the same view. Results are capped at
16 KB by default. When detail is cut, the result says `truncated: true` and
explains how to narrow the query.

Every result has the same shape:

```json
{
  "summary": "1,284 logs, 31 at error level; top service checkout (912).",
  "window": { "from": "2026-10-18T13:00:00Z", "to": "2026-10-18T14:00:00Z" },
  "result": { "...": "tool-specific" },
  "truncated": false,
  "hints": [],
  "links": { "explore": "https://rush.example.com/?q=…&mode=logs&t=60&tenant=prod" }
}
```

Times are UTC. Tools take `last` (`"15m"`, `"24h"`, `"7d"`, default `"1h"`)
or `from`/`to` as RFC3339, `"YYYY-MM-DD HH:MM"`, Unix seconds, `"now-2h"`,
`"today"` or `"yesterday"`.

## Install

```bash
cargo install --git https://github.com/RushObservability/mcp-server.git
```

This installs the `rush-mcp` binary. Release archives for Linux, macOS and
Windows, and a container image (`ghcr.io/rushobservability/mcp-server`), are
published for each version tag.

## Get an API key

In Rush, go to **Settings → API Keys**, create a **Query** key, and choose a
role:

- **Viewer** (default) is enough for every tool except `preview_monitor`.
- **Write** is needed for `preview_monitor`, because Rush only lets
  writers simulate monitors, and for write tools in later releases.

For the `sre_agent` toolset, also turn on **Allow SRE agent and
natural-language search** when creating the key. It lets the key start and
read SRE agent investigations and use `parse_query`, all of which spend the
tenant's LLM budget. Investigations started with a key can use the agent's
telemetry tools only, never source code or cluster access.

A key is scoped to the tenant it was created in, so the server only ever sees
that tenant's data. Rush records the key, and the tool that used it, with each
request.

## Connect a client

Every client needs the Rush URL and the key. The key is sent only to Rush, and
only over HTTPS (plain HTTP is allowed to `localhost` for development).

### Claude Code

```bash
claude mcp add rush --env RUSH_URL=https://rush.example.com --env RUSH_API_KEY=rush_qry_… -- rush-mcp
```

### Claude Desktop, Cursor, Windsurf and other JSON-configured clients

```json
{
  "mcpServers": {
    "rush": {
      "command": "rush-mcp",
      "env": {
        "RUSH_URL": "https://rush.example.com",
        "RUSH_API_KEY": "rush_qry_…"
      }
    }
  }
}
```

Claude Desktop reads this from `claude_desktop_config.json`, and Cursor from
`.cursor/mcp.json`.

### VS Code

```json
{
  "servers": {
    "rush": {
      "type": "stdio",
      "command": "rush-mcp",
      "env": { "RUSH_URL": "https://rush.example.com", "RUSH_API_KEY": "rush_qry_…" }
    }
  }
}
```

### Docker

```bash
docker run --rm -i -e RUSH_URL=https://rush.example.com -e RUSH_API_KEY=rush_qry_… ghcr.io/rushobservability/mcp-server
```

## Tools

<!-- tools:start -->
| Tool | Toolset | What it does |
|---|---|---|
| `get_context` | core | Start here. Returns the tenant and identity behind the API key, server time (UTC), enabled Rush features and toolsets, and how many logs and spans arrived in the last hour. |
| `resolve_time` | core | Resolve a time expression to an exact UTC window. Accepts `last` ("15m", "24h", "7d") or `from`/`to` as RFC3339, "YYYY-MM-DD HH:MM" (UTC), Unix seconds, "now-2h", "today" or "yesterday". |
| `list_fields` | core | List field names for logs or spans: the built-in fields plus attribute keys found in a sample of recent records. Use before filtering so field names are exact. |
| `list_field_values` | core | Most common values of one log or span field in a window, with counts. Supports the same filters as search_logs/search_spans. |
| `search_logs` | core | Search logs. Returns the total, counts by severity and service, a count series, optional group counts, and newest sample lines (with a `ref` for get_log_record/get_log_context). |
| `search_spans` | core | Search APM spans. Returns the total, error count and rate, approximate latency percentiles, counts by service and HTTP status class, a count series, optional group counts, and newest sample spans with trace IDs. |
| `aggregate` | core | Count logs or spans grouped by a field (spans include error counts and rates), over time, or both (spans only). Set group_by, over_time, or both. |
| `get_trace` | core | Summarize one trace by ID or Rush trace URL: duration, span count, time per service, error spans with exception messages, the critical path, and a depth-limited span tree. |
| `list_services` | core | List services with request count, errors, error rate and p50/p95/p99 latency, busiest first. |
| `get_service` | core | Health of one service: totals and latency, top endpoints, top error groups, services it calls and is called by, and recent deploys. |
| `query_metrics` | core | Run a PromQL query over a window (or instantly at its end). Each series is summarized as min/avg/max/last; set include_points for the data points. |
| `list_metrics` | core | List metric names seen in the last hour, optionally filtered by a substring. |
| `list_metric_labels` | core | List metric label names, or the values of one label, optionally for one metric. Use before writing PromQL selectors. |
| `get_link` | core | Build a Rush UI link for an Explore query, trace, service, metrics query, saved query or the deploys page, to share with the user. |
| `compare_cohorts` | analysis | BubbleUp: find which attributes (service, operation, path, status, severity, namespace…) are over-represented in a selection compared with a baseline. Select by window (vs the previous window by default), or for spans by errors_only/min_duration_ms (vs the rest of the same window). |
| `compare_windows` | analysis | Compare a window with a baseline (the previous window of the same length by default): span volume, error rate, approximate p95, log volume and error-level logs, with percent changes. |
| `get_service_latency` | analysis | Latency distribution for one service (p50/p95/p99 and counts per latency band) and where request time goes: the service itself vs database calls, per database. |
| `get_log_context` | analysis | Log lines written just before and after one log line, oldest first, with the original line marked. Takes the `ref` from a search_logs sample. |
| `get_log_record` | analysis | Full detail of one log line (body plus resource and log attributes), from the `ref` in a search_logs sample. |
| `list_monitors` | alerting | List monitors with their state (alert, warn, no_data, ok) and whether they are muted, worst first, with counts per state. Filter by state or text. |
| `get_monitor` | alerting | One monitor in full: query, thresholds, evaluation settings, state per group, notification message and recent state changes. Takes a monitor ID or Rush link. |
| `preview_monitor` | alerting | Simulate a proposed monitor over recent data without saving it: current value per group, value ranges, and the alerts it would have raised. Rush requires a write-role API key for previews. |
| `list_slos` | alerting | List SLOs with state, target, measured success rate and error budget left, breaching and lowest-budget first. |
| `get_slo` | alerting | One SLO in full: target, measured success rate, error and total counts, error budget left, and recent state changes. Takes an SLO ID or Rush link. |
| `list_anomalies` | alerting | List anomaly detections. By default returns rules that are currently anomalous, with value, expected value and deviation in standard deviations; set include_resolved for recent history. |
| `get_anomaly` | alerting | One anomaly event with its detection rule and, for HTTP status anomalies, the services emitting that status and sample logs around the time. |
| `search_dashboards` | dashboards | Find dashboards by name, description or tag, most recently updated first. |
| `get_dashboard_summary` | dashboards | A dashboard's widgets (ID, title, type and each query as PromQL or filter text), variables and default time range, without layout. Use before get_widget_data. |
| `get_dashboard` | dashboards | A dashboard's full definition (settings, variables and complete widget configurations, as exported by Rush). Large; prefer get_dashboard_summary unless the raw configuration is needed. |
| `get_widget_data` | dashboards | Run one dashboard widget's queries the way the Rush UI does and return the numbers: totals, values over time, or values per group (PromQL widgets are summarized per series). Applies dashboard variables. |
| `list_deploys` | changes | List deploy markers (service, version, commit, environment, who and when), newest first. Defaults to the last 7 days. Use to line up changes with errors or latency. |
| `list_saved_queries` | saved_queries | List saved Explore queries visible to this key: shared with the tenant, with its groups, or its own. Each has a description of why it is useful. |
| `run_saved_query` | saved_queries | Run a saved Explore query by ID or Rush link and return the same summary as search_logs or search_spans, plus the saved query's name and description. |
| `start_investigation` | sre_agent | Hand an investigation to the Rush SRE agent, which queries logs, traces, metrics, deploys and alerts on its own and writes a report. Give a question, or an anomaly event ID, optionally a template and an incident window. Waits up to wait_seconds (default 30) and returns the report if it finished, otherwise the evidence so far and a session ID for get_investigation. Spends the tenant's LLM budget; needs a key with agent access. |
| `continue_investigation` | sre_agent | Ask the Rush SRE agent a follow-up in an existing investigation, or answer its question. The agent keeps the session's evidence and memory. Waits up to wait_seconds (default 30) like start_investigation. Spends the tenant's LLM budget. |
| `get_investigation` | sre_agent | Read an SRE agent investigation: status, the latest question and report, the evidence trail (each tool the agent called with a one-line result) and token use. Set wait_seconds (max 120) to wait for a running investigation to finish. |
| `list_investigations` | sre_agent | List recent SRE agent investigations in this tenant, most recently updated first, with title, status, template, token use and a Rush link. |
| `list_investigation_templates` | sre_agent | List the SRE agent's investigation templates (alert investigation, postmortem, capacity review, deploy review, security review) with what each does. Pass a template's id to start_investigation. |
| `parse_query` | sre_agent | Turn a plain-language request ("500 errors from checkout in production") into Rush filters and free-text search for logs or spans, with an Explore link. Pass the result to search_logs, search_spans or aggregate. Uses the Rush LLM gateway; needs a key with agent access. |
<!-- tools:end -->

Toolsets are enabled with `--toolsets` (default
`core,analysis,alerting,changes,saved_queries`; `dashboards` and `sre_agent`
are opt-in; or `all`). Narrow them further with `--enable-tools` and
`--disable-tools`.

### SRE agent investigations

`start_investigation` hands a question (or an anomaly event) to the Rush SRE
agent, which runs its own queries and writes a report. The tool waits up to
`wait_seconds` (default 30, max 45). If the agent hasn't finished by then, it
returns the evidence so far and a session ID, and the run carries on. Read it
with `get_investigation`, which can wait up to 120 seconds, and ask follow-ups
with `continue_investigation`. Every result links to the session in Rush.

The agent cancels a run when its event stream closes, so this server keeps
reading the stream in the background after the tool returns. Stopping the
server stops the runs it is following. Rush stores every session, so
`get_investigation` and `list_investigations` work from any server or client.

## Prompts and resources

Prompts are ready-made investigations you can start from your client's prompt
menu. Each appears only when the toolsets it uses are enabled.

| Prompt | Arguments | What it does |
|---|---|---|
| `triage_service` | `service`, `last` | Checks a service's health and, if something is wrong, narrows down where and why |
| `investigate_alert` | `alert` | Works through a firing monitor or anomaly: re-runs the signal, compares before and after, checks deploys |
| `deploy_review` | `service`, `version` | Compares errors and latency before and after a deploy |
| `slow_endpoint` | `service`, `endpoint`, `last` | Finds what slow requests to one endpoint have in common |
| `postmortem_draft` | `incident` | Drafts a postmortem with the SRE agent's postmortem template |

Two resources can be attached as context: `rush://context` (same as
`get_context`) and `rush://services` (same as `list_services` for the last
hour).

## Configuration

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `--url` | `RUSH_URL` | required | Rush API base URL |
| `--web-url` | `RUSH_WEB_URL` | `--url` | Rush UI base URL used in links |
| `--api-key` | `RUSH_API_KEY` | | Query API key (`rush_qry_…`) |
| `--api-key-file` | `RUSH_API_KEY_FILE` | | File with the key, re-read on every request so a rotated key needs no restart |
| `--toolsets` | `RUSH_MCP_TOOLSETS` | `core,analysis,alerting,changes,saved_queries` | Toolsets to enable, or `all` |
| `--enable-tools` | | | Only expose these tools |
| `--disable-tools` | | | Hide these tools |
| `--max-result-bytes` | `RUSH_MCP_MAX_RESULT_BYTES` | `16384` | Result size budget |
| `--transport` | | `stdio` | `stdio` or `http` |
| `--listen` | `RUSH_MCP_LISTEN` | `127.0.0.1:8090` | HTTP listen address |
| `--base-path` | `RUSH_MCP_BASE_PATH` | `/mcp` | HTTP path for the MCP endpoint |
| `--server-token` | `RUSH_MCP_SERVER_TOKEN` | | Token clients must send to use the server's own key in HTTP mode |
| `--allowed-hosts` | `RUSH_MCP_ALLOWED_HOSTS` | loopback | Accepted `Host` headers in HTTP mode |
| `--allowed-origins` | `RUSH_MCP_ALLOWED_ORIGINS` | | Accepted browser `Origin`s in HTTP mode |
| `--instructions-append` | `RUSH_MCP_INSTRUCTIONS_APPEND` | | Extra text for the server instructions |
| `--timeout-secs` | `RUSH_MCP_TIMEOUT_SECS` | `30` | Upstream request timeout |

Logs go to stderr. Set `RUSH_MCP_LOG=debug` to see each Rush API call.

## Shared HTTP deployments

`rush-mcp --transport http` serves streamable HTTP at `/mcp`, with
`/healthz`, `/readyz` (checks Rush is reachable) and `/metrics` (tool call
counts, errors, time and result bytes in Prometheus format).

There are two ways for clients to authenticate:

- **Bring their own key.** Clients send `Authorization: Bearer rush_qry_…`
  and the server uses that key for their calls. No server key is needed.
- **Share the server's key.** Start the server with `RUSH_API_KEY` and clients
  send `Authorization: Bearer <RUSH_MCP_SERVER_TOKEN>`. The server refuses to
  start this way on a non-loopback address without a server token.

Set `--allowed-hosts` to the hostnames clients use, so DNS-rebinding attempts
are rejected.

## Security

- Read-only: no tool changes anything in Rush. The exceptions are
  `start_investigation` and `continue_investigation` (opt-in `sre_agent`
  toolset), which record an investigation session and spend LLM budget.
- Log bodies, span names and attribute values come from monitored systems.
  The server tells clients to treat them as untrusted data, never as
  instructions.
- Keys are never logged. Errors show at most the 12-character key prefix.

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## Development

```bash
make ci     # formatting, Clippy, tests, build
```

`scripts/smoke.py` drives every tool, prompt and resource against a real Rush
deployment over stdio and prints each result's summary, size and timing. Set
`RUSH_KEY_ROLE=write` when the key can preview monitors, `RUSH_KEY_AGENT=1`
when it has agent access, and `RUSH_SMOKE_INVESTIGATE=1` to also start a
short SRE agent investigation (this spends LLM budget):

```bash
RUSH_URL=https://rush.example.com RUSH_API_KEY=rush_qry_… python3 scripts/smoke.py target/release/rush-mcp
```

The tool table above is generated from the code; a test fails if it drifts.

## License

MIT. See [LICENSE](LICENSE).
