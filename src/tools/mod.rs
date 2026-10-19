//! MCP tools, one module per toolset.

pub mod analysis;
pub mod changes;
pub mod core;
pub mod saved_queries;

use chrono::{TimeZone, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::api::{Filter, KeyCount};
use crate::server::ToolError;
use crate::time::{TimeArgs, Window};

pub const MAX_SEARCH_CHARS: usize = 512;

/// Filters, free-text search and time window shared by query tools.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct QueryArgs {
    /// Conditions ANDed together, e.g. [{"field":"http_status_code","op":">=","value":500}].
    #[serde(default)]
    pub filters: Vec<Filter>,
    /// Free-text search. Terms are ANDed, "quoted phrases" match exactly, OR must be written out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,
    /// Shortcut for a service_name = <service> filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(flatten)]
    pub time: TimeArgs,
}

/// A query ready to send: validated filters, search and window.
#[derive(Debug, Clone)]
pub struct Query {
    pub filters: Vec<Filter>,
    pub search: Option<String>,
    pub window: Window,
}

impl QueryArgs {
    pub fn resolve(&self) -> Result<Query, ToolError> {
        let window = self.time.resolve()?;
        let mut filters = self.filters.clone();
        if filters.len() > 30 {
            return Err(ToolError::Input("at most 30 filters are allowed".into()));
        }
        for f in &filters {
            let field = f.field.trim();
            if field.is_empty() || field.len() > 128 || field.chars().any(char::is_control) {
                return Err(ToolError::Input(format!(
                    "filter field `{}` must be 1 to 128 characters",
                    f.field
                )));
            }
        }
        if let Some(service) = self
            .service
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            filters.push(Filter::eq("service_name", service));
        }
        let search = self
            .search
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        if search
            .as_ref()
            .is_some_and(|s| s.chars().count() > MAX_SEARCH_CHARS)
        {
            return Err(ToolError::Input(format!(
                "search must be at most {MAX_SEARCH_CHARS} characters"
            )));
        }
        Ok(Query {
            filters,
            search,
            window,
        })
    }
}

/// One point of a count series.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
pub struct Point {
    /// Bucket start (UTC).
    pub t: String,
    pub count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<u64>,
}

/// Merge adjacent points until at most `max` remain, summing counts.
pub fn compress(points: Vec<Point>, max: usize) -> Vec<Point> {
    if points.len() <= max || max == 0 {
        return points;
    }
    let chunk = points.len().div_ceil(max);
    points
        .chunks(chunk)
        .map(|c| Point {
            t: c[0].t.clone(),
            count: c.iter().map(|p| p.count).sum(),
            errors: c.iter().map(|p| p.errors).sum::<Option<u64>>(),
        })
        .collect()
}

/// Halve a series by merging neighbours, to shrink it for the budget.
pub fn thin(points: &mut Vec<Point>) -> bool {
    if points.len() <= 4 {
        return false;
    }
    let target = points.len().div_ceil(2);
    *points = compress(std::mem::take(points), target);
    true
}

/// Keep the first `n` entries; false when nothing was removed.
pub fn keep<T>(items: &mut Vec<T>, n: usize) -> bool {
    if items.len() > n {
        items.truncate(n);
        true
    } else {
        false
    }
}

/// Remove the last entry; false when empty.
pub fn pop<T>(items: &mut Vec<T>) -> bool {
    items.pop().is_some()
}

pub fn top(mut items: Vec<KeyCount>, n: usize) -> Vec<KeyCount> {
    items.sort_by(|a, b| b.count.cmp(&a.count));
    items.truncate(n);
    items
}

/// Nanoseconds since the epoch as RFC3339 with milliseconds.
pub fn ns_to_time(ns: i64) -> String {
    Utc.timestamp_nanos(ns)
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub fn ms(ns: u64) -> f64 {
    round2(ns as f64 / 1_000_000.0)
}

pub fn round2(v: f64) -> f64 {
    if v.is_finite() {
        (v * 100.0).round() / 100.0
    } else {
        0.0
    }
}

pub fn pct(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        round2(part as f64 * 100.0 / whole as f64)
    }
}

/// "1,284" style grouping for summaries.
pub fn thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Rush's services endpoints take "last N minutes" ending now. Use the window
/// length, and say so when the window does not end now.
pub fn minutes_ending_now(window: &Window) -> (i64, Option<String>) {
    let now = Utc::now();
    let minutes = (now - window.from).num_minutes().clamp(1, 10_080);
    let note = (window.relative_minutes.is_none() && (now - window.to).num_minutes() > 2).then(|| {
        format!(
            "Service statistics cover the last {minutes} minutes ending now; this endpoint can't stop at an earlier time."
        )
    });
    (minutes, note)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(t: &str, count: u64) -> Point {
        Point {
            t: t.into(),
            count,
            errors: Some(count / 2),
        }
    }

    #[test]
    fn compress_sums_adjacent_points() {
        let pts: Vec<Point> = (0..10).map(|i| p(&i.to_string(), 2)).collect();
        let out = compress(pts, 4);
        assert_eq!(out.len(), 4);
        assert_eq!(out.iter().map(|p| p.count).sum::<u64>(), 20);
        assert_eq!(out[0].t, "0");
        let mut pts: Vec<Point> = (0..10).map(|i| p(&i.to_string(), 1)).collect();
        assert!(thin(&mut pts));
        assert_eq!(pts.len(), 5);
        assert_eq!(pts.iter().map(|p| p.count).sum::<u64>(), 10);
    }

    #[test]
    fn query_args_add_the_service_filter_and_validate() {
        let args = QueryArgs {
            service: Some(" checkout ".into()),
            ..Default::default()
        };
        let q = args.resolve().unwrap();
        assert_eq!(q.filters, vec![Filter::eq("service_name", "checkout")]);
        let long = QueryArgs {
            search: Some("x".repeat(600)),
            ..Default::default()
        };
        assert!(long.resolve().is_err());
        let bad = QueryArgs {
            filters: vec![Filter::eq("", "v")],
            ..Default::default()
        };
        assert!(bad.resolve().is_err());
    }

    #[test]
    fn formatting_helpers() {
        assert_eq!(thousands(1_284_000), "1,284,000");
        assert_eq!(thousands(12), "12");
        assert_eq!(pct(1, 3), 33.33);
        assert_eq!(pct(1, 0), 0.0);
        assert_eq!(ms(1_234_567), 1.23);
        assert_eq!(
            ns_to_time(1_760_796_000_123_000_000),
            "2025-10-18T14:00:00.123Z"
        );
    }
}
