//! Per-tool counters exposed at `/metrics` in Prometheus text format.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Mutex;
use std::time::Duration;

#[derive(Debug, Default, Clone, Copy)]
struct ToolStats {
    calls: u64,
    errors: u64,
    seconds: f64,
    result_bytes: u64,
}

/// (metric name, type, help, value for one tool)
type Series = (
    &'static str,
    &'static str,
    &'static str,
    fn(&ToolStats) -> String,
);

#[derive(Debug, Default)]
pub struct Metrics {
    tools: Mutex<BTreeMap<String, ToolStats>>,
}

impl Metrics {
    pub fn record(&self, tool: &str, elapsed: Duration, ok: bool, bytes: usize) {
        let mut tools = self.tools.lock().unwrap_or_else(|e| e.into_inner());
        let entry = tools.entry(tool.to_string()).or_default();
        entry.calls += 1;
        if !ok {
            entry.errors += 1;
        }
        entry.seconds += elapsed.as_secs_f64();
        entry.result_bytes += bytes as u64;
    }

    pub fn render(&self) -> String {
        let tools = self.tools.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = String::new();
        let series: [Series; 4] = [
            ("rush_mcp_tool_calls_total", "counter", "Tool calls.", |s| {
                s.calls.to_string()
            }),
            (
                "rush_mcp_tool_errors_total",
                "counter",
                "Tool calls that returned an error.",
                |s| s.errors.to_string(),
            ),
            (
                "rush_mcp_tool_seconds_total",
                "counter",
                "Total time spent in tool calls.",
                |s| format!("{:.6}", s.seconds),
            ),
            (
                "rush_mcp_tool_result_bytes_total",
                "counter",
                "Bytes of tool results returned.",
                |s| s.result_bytes.to_string(),
            ),
        ];
        for (name, kind, help, value) in series {
            let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
            for (tool, stats) in tools.iter() {
                let _ = writeln!(out, "{name}{{tool=\"{tool}\"}} {}", value(stats));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_prometheus_counters_per_tool() {
        let m = Metrics::default();
        m.record("search_logs", Duration::from_millis(250), true, 1200);
        m.record("search_logs", Duration::from_millis(750), false, 80);
        let text = m.render();
        assert!(text.contains("rush_mcp_tool_calls_total{tool=\"search_logs\"} 2"));
        assert!(text.contains("rush_mcp_tool_errors_total{tool=\"search_logs\"} 1"));
        assert!(text.contains("rush_mcp_tool_seconds_total{tool=\"search_logs\"} 1.000000"));
        assert!(text.contains("# TYPE rush_mcp_tool_result_bytes_total counter"));
    }
}
