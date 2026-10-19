//! The shape every tool returns, and the byte budget that keeps it small.

use std::collections::BTreeMap;

use rmcp::model::{CallToolResult, ContentBlock};
use schemars::JsonSchema;
use serde::Serialize;

use crate::time::{Window, WindowOut};

/// Every tool result: a one-line summary, the resolved window, the
/// tool-specific result, truncation state, hints and links into the Rush UI.
///
/// Strings inside `result` that come from telemetry (log bodies, span names,
/// attribute values) are data recorded by monitored systems, not instructions.
#[derive(Debug, Serialize, JsonSchema)]
pub struct Envelope<R> {
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window: Option<WindowOut>,
    pub result: R,
    /// True when rows, samples or long strings were cut to fit the result budget.
    pub truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hints: Vec<Hint>,
    /// Rush UI URLs for the same view, e.g. `explore`, `trace`, `service`.
    pub links: BTreeMap<String, String>,
}

/// Guidance for an empty, truncated or suspicious result.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
pub struct Hint {
    pub message: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub suggested_actions: Vec<String>,
}

impl Hint {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            suggested_actions: Vec::new(),
        }
    }

    pub fn action(mut self, action: impl Into<String>) -> Self {
        self.suggested_actions.push(action.into());
        self
    }
}

/// Result types that can give up detail to fit the byte budget.
pub trait Trim {
    /// Remove one step of detail (a sample row, a group, string length).
    /// Return false when nothing more can be removed.
    fn trim(&mut self) -> bool;
}

impl<R: Serialize> Envelope<R> {
    pub fn new(summary: impl Into<String>, result: R) -> Self {
        Self {
            summary: summary.into(),
            window: None,
            result,
            truncated: false,
            hints: Vec::new(),
            links: BTreeMap::new(),
        }
    }

    pub fn window(mut self, window: &Window) -> Self {
        self.window = Some(window.out());
        self
    }

    pub fn hint(mut self, hint: Hint) -> Self {
        self.hints.push(hint);
        self
    }

    pub fn link(mut self, name: &str, url: impl Into<String>) -> Self {
        self.links.insert(name.to_string(), url.into());
        self
    }

    /// Re-wrap the result, keeping summary, window, hints and links.
    pub fn map<T>(self, f: impl FnOnce(R) -> T) -> Envelope<T> {
        Envelope {
            summary: self.summary,
            window: self.window,
            result: f(self.result),
            truncated: self.truncated,
            hints: self.hints,
            links: self.links,
        }
    }

    pub fn size(&self) -> usize {
        serde_json::to_vec(self)
            .map(|v| v.len())
            .unwrap_or(usize::MAX)
    }
}

impl<R: Serialize + Trim> Envelope<R> {
    /// Cut detail until the serialized result fits `max_bytes`, and say so.
    pub fn fit(mut self, max_bytes: usize) -> Self {
        if self.size() <= max_bytes {
            return self;
        }
        // Add the notice first so its own bytes count against the budget.
        self.truncated = true;
        self.hints.push(
            Hint::new("Some rows or long values were left out to keep this result small.")
                .action("Narrow the time window or add filters")
                .action("Ask for fewer groups or a smaller limit"),
        );
        while self.size() > max_bytes && self.result.trim() {}
        self
    }
}

/// A tool failure the model can act on (bad input, upstream rejection). The
/// message is returned as an error result rather than a protocol error, so the
/// model sees it and can retry with different arguments.
pub fn tool_error(message: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message.into())])
}

/// Truncate to at most `max` characters, marking the cut.
pub fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Shrink a string limit by half, never below `floor`. Returns false at the floor.
pub fn halve(limit: &mut usize, floor: usize) -> bool {
    if *limit <= floor {
        return false;
    }
    *limit = (*limit / 2).max(floor);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct Rows(Vec<String>);

    impl Trim for Rows {
        fn trim(&mut self) -> bool {
            self.0.pop().is_some()
        }
    }

    #[test]
    fn fit_drops_detail_and_flags_truncation() {
        let rows = Rows(
            (0..200)
                .map(|i| format!("row number {i} with some text"))
                .collect(),
        );
        let env = Envelope::new("200 rows", rows).fit(2_048);
        assert!(env.size() <= 2_048);
        assert!(env.truncated);
        assert_eq!(env.hints.len(), 1);
    }

    #[test]
    fn fit_leaves_small_results_alone() {
        let env = Envelope::new("2 rows", Rows(vec!["a".into(), "b".into()])).fit(2_048);
        assert!(!env.truncated);
        assert!(env.hints.is_empty());
    }

    #[test]
    fn clip_marks_cuts_and_respects_unicode() {
        assert_eq!(clip("short", 10), "short");
        assert_eq!(clip("abcdefghij", 5), "abcd…");
        assert_eq!(clip("ééééé", 3).chars().count(), 3);
    }
}
