# Security Policy

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
pull requests, or discussions.**

Report privately through GitHub Security Advisories:

1. Go to the [Security tab](https://github.com/RushObservability/mcp-server/security)
2. Click **Report a vulnerability**

This opens a private channel visible only to the maintainers.

### What to include

- The `rush-mcp` version (`rush-mcp --version`), the transport (stdio or HTTP) and the MCP client
- Your configuration and the tool call, with any API key or server token redacted
- Steps to reproduce, and what an attacker gains

### What to expect

- **Acknowledgement** within 5 business days.
- **Initial assessment**, including severity, within 10 business days.
- **Progress updates** at least every 10 business days until resolution.
- **Credit** in the advisory and release notes, unless you prefer anonymity.

We ask for a reasonable opportunity to ship a fix before public disclosure,
and aim to release fixes for confirmed high and critical issues within 90 days.

## Supported Versions

This project is pre-1.0. Security fixes land on `main` and in the next release;
there are no backports to earlier tags.

## Scope

`rush-mcp` holds a Rush API key and lets AI clients call the Rush query API
through MCP tools. Reports touching the following are especially valuable:

- **Credential exposure:** the API key or server token reaching logs, error
  messages, tool results, metrics, or another client's session.
- **Cross-client access in HTTP mode:** one client using another client's key,
  or using the server's key without the server token.
- **Transport:** any path that sends a key over plaintext HTTP, accepts a
  certificate it should not, or bypasses the Host/Origin checks.
- **Prompt injection through telemetry:** log bodies, span names and attribute
  values are attacker-influenced. Anything that lets that content escape its
  field in a tool result, or change server behaviour, is in scope.
- **Request forgery:** tool arguments that reach a Rush endpoint, or a host,
  other than the one the tool intends.

**Out of scope:** vulnerabilities in the query-api server itself (report those
against that project), issues that need an already-compromised local account,
and scanner output without a demonstrated impact.

## Our Automated Security Practices

- Formatting, Clippy (`-D warnings`), and the test suite gate every pull
  request, across every platform the release ships
- `cargo audit` for RustSec advisories and `cargo deny` for the dependency,
  license and source policy
- gitleaks scans the full repository history for secrets
- Dependabot version updates for Cargo and GitHub Actions, plus Dependabot
  alerts from the GitHub Advisory Database
- All GitHub Actions are pinned to full commit SHAs
- Workflow tokens are least-privilege (`contents: read`)
