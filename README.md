# Rush MCP Server

`rush-mcp` is a [Model Context Protocol](https://modelcontextprotocol.io)
server for [Rush Observability](https://github.com/RushObservability). It lets
AI assistants such as Claude Code, Claude Desktop, Cursor and VS Code search
logs and APM spans, read traces, run PromQL, check service health, compare
time windows and run saved queries, and link every answer back to the Rush UI.

> **Status:** v0.1, read-only. Monitors, SLOs, dashboards and SRE-agent
> handoff come in later releases.

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

- **Viewer** (default) is enough for every tool in this release.
- **Write** is only needed by write tools in later releases.

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
| `list_deploys` | changes | List deploy markers (service, version, commit, environment, who and when), newest first. Defaults to the last 7 days. Use to line up changes with errors or latency. |
| `list_saved_queries` | saved_queries | List saved Explore queries visible to this key: shared with the tenant, with its groups, or its own. Each has a description of why it is useful. |
| `run_saved_query` | saved_queries | Run a saved Explore query by ID or Rush link and return the same summary as search_logs or search_spans, plus the saved query's name and description. |
<!-- tools:end -->

Toolsets are enabled with `--toolsets` (default
`core,analysis,changes,saved_queries`, or `all`). Narrow them further with
`--enable-tools` and `--disable-tools`.

## Configuration

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `--url` | `RUSH_URL` | required | Rush API base URL |
| `--web-url` | `RUSH_WEB_URL` | `--url` | Rush UI base URL used in links |
| `--api-key` | `RUSH_API_KEY` | | Query API key (`rush_qry_…`) |
| `--api-key-file` | `RUSH_API_KEY_FILE` | | File with the key, re-read on every request so a rotated key needs no restart |
| `--toolsets` | `RUSH_MCP_TOOLSETS` | `core,analysis,changes,saved_queries` | Toolsets to enable, or `all` |
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

- Read-only: this release has no tools that change anything in Rush.
- Log bodies, span names and attribute values come from monitored systems.
  The server tells clients to treat them as untrusted data, never as
  instructions.
- Keys are never logged. Errors show at most the 12-character key prefix.

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## Development

```bash
make ci     # formatting, Clippy, tests, build
```

`scripts/smoke.py` drives every tool against a real Rush deployment over stdio
and prints each result's summary, size and timing:

```bash
RUSH_URL=https://rush.example.com RUSH_API_KEY=rush_qry_… python3 scripts/smoke.py target/release/rush-mcp
```

The tool table above is generated from the code; a test fails if it drifts.

## License

MIT. See [LICENSE](LICENSE).
