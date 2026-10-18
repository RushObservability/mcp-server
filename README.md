# Rush MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io) server for
[Rush Observability](https://github.com/RushObservability). It lets AI
assistants such as Claude Code, Claude Desktop, Cursor and VS Code search
logs and traces, run PromQL, look up services, dashboards, monitors and
SLOs, and hand a problem to the Rush SRE agent for a full investigation.

> **Status:** in design. There is no usable release yet. Watch this
> repository for the first version.

## Planned

- Logs, APM spans and traces: search, counts, grouping and trace lookup
- Metrics: PromQL queries plus metric, label and value discovery
- Services: catalog, dependencies, errors and latency
- Dashboards, monitors, SLOs, anomalies and deploy markers
- Saved queries and links back into the Rush web UI for every result
- SRE agent handoff: start an investigation and follow its findings
- Read-only by default, with write tools you opt into per category
- API-key auth with tenant scoping
- stdio for local use and streamable HTTP for shared deployments
- Single static binary and a Docker image, written in Rust

## License

MIT. See [LICENSE](LICENSE).
