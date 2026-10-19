//! Links into the Rush web UI, and parsing UI URLs back into IDs.
//!
//! Every link carries `tenant=` so it opens in the right tenant (the UI
//! switches to it if the user has access).

use url::Url;

use crate::time::Window;

#[derive(Debug, Clone)]
pub struct Links {
    web: Url,
    tenant: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Logs,
    Spans,
}

impl Signal {
    pub fn as_str(self) -> &'static str {
        match self {
            Signal::Logs => "logs",
            Signal::Spans => "spans",
        }
    }
}

impl Links {
    pub fn new(web: Url, tenant: Option<String>) -> Self {
        Self { web, tenant }
    }

    pub fn with_tenant(&self, tenant: Option<String>) -> Self {
        Self {
            web: self.web.clone(),
            tenant,
        }
    }

    fn build(&self, path: &str, params: &[(&str, String)]) -> String {
        let mut url = self.web.clone();
        url.set_path(path);
        {
            let mut q = url.query_pairs_mut();
            q.clear();
            for (k, v) in params {
                if !v.is_empty() {
                    q.append_pair(k, v);
                }
            }
            if let Some(t) = &self.tenant {
                q.append_pair("tenant", t);
            }
        }
        if url.query() == Some("") {
            url.set_query(None);
        }
        url.to_string()
    }

    fn window_params(window: &Window) -> Vec<(&'static str, String)> {
        match window.relative_minutes {
            Some(m) => vec![("t", m.to_string())],
            None => vec![("from", window.from_rfc3339()), ("to", window.to_rfc3339())],
        }
    }

    /// Explore with a search-bar query (`field=value` filters plus free text).
    pub fn explore(
        &self,
        signal: Signal,
        query: &str,
        window: &Window,
        group_by: Option<&str>,
    ) -> String {
        let mut params = vec![("q", query.to_string())];
        if signal == Signal::Logs {
            params.push(("mode", "logs".into()));
        } else {
            params.push(("mode", "spans".into()));
        }
        params.extend(Self::window_params(window));
        if let Some(g) = group_by {
            params.push(("group", g.to_string()));
        }
        self.build("/", &params)
    }

    pub fn trace(&self, trace_id: &str, span_id: Option<&str>) -> String {
        let params = span_id
            .map(|s| vec![("span", s.to_string())])
            .unwrap_or_default();
        self.build(&format!("/trace/{trace_id}"), &params)
    }

    pub fn service(&self, name: &str, window: &Window) -> String {
        let minutes = window.duration().num_minutes().max(1);
        self.build(
            &format!("/services/{}", urlencode_path(name)),
            &[("t", minutes.to_string())],
        )
    }

    pub fn metrics(&self, promql: &str, window: &Window) -> String {
        let minutes = window.duration().num_minutes().max(1);
        self.build(
            "/metrics-browser",
            &[("q", promql.to_string()), ("t", minutes.to_string())],
        )
    }

    pub fn saved_query(&self, id: &str) -> String {
        self.build("/", &[("saved", id.to_string())])
    }

    pub fn deploys(&self) -> String {
        self.build("/deploys", &[])
    }
}

fn urlencode_path(segment: &str) -> String {
    url::form_urlencoded::byte_serialize(segment.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
}

/// A trace ID from a raw ID or a Rush trace URL (`…/trace/<id>`, or Explore
/// with `trace=<id>`).
pub fn trace_id_from(input: &str) -> Option<String> {
    let s = input.trim();
    if is_trace_id(s) {
        return Some(s.to_ascii_lowercase());
    }
    let url = Url::parse(s).ok()?;
    if let Some(mut segs) = url.path_segments() {
        while let Some(seg) = segs.next() {
            if seg == "trace" || seg == "traces" {
                if let Some(id) = segs.next().filter(|id| is_trace_id(id)) {
                    return Some(id.to_ascii_lowercase());
                }
            }
        }
    }
    url.query_pairs()
        .find(|(k, v)| k == "trace" && is_trace_id(v))
        .map(|(_, v)| v.to_ascii_lowercase())
}

/// A saved-query ID from a raw ID or a Rush `?saved=<id>` URL.
pub fn saved_query_id_from(input: &str) -> Option<String> {
    let s = input.trim();
    if let Ok(url) = Url::parse(s) {
        return url
            .query_pairs()
            .find(|(k, v)| k == "saved" && !v.is_empty())
            .map(|(_, v)| v.into_owned());
    }
    (!s.is_empty() && s.len() <= 128 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
        .then(|| s.to_string())
}

fn is_trace_id(s: &str) -> bool {
    (s.len() == 32 || s.len() == 16) && s.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::TimeArgs;
    use chrono::{TimeZone, Utc};

    fn links() -> Links {
        Links::new(
            Url::parse("https://rush.example.com").unwrap(),
            Some("prod".into()),
        )
    }

    fn window(relative: bool) -> Window {
        let now = Utc.with_ymd_and_hms(2026, 10, 18, 14, 0, 0).unwrap();
        let args = if relative {
            TimeArgs {
                last: Some("30m".into()),
                ..Default::default()
            }
        } else {
            TimeArgs {
                from: Some("2026-10-18 10:00".into()),
                to: Some("2026-10-18 11:00".into()),
                ..Default::default()
            }
        };
        args.resolve_at(now).unwrap()
    }

    #[test]
    fn explore_links_carry_query_mode_window_and_tenant() {
        let url = links().explore(
            Signal::Logs,
            "service.name=checkout timeout",
            &window(true),
            Some("status"),
        );
        assert_eq!(
            url,
            "https://rush.example.com/?q=service.name%3Dcheckout+timeout&mode=logs&t=30&group=status&tenant=prod"
        );
        let abs = links().explore(Signal::Spans, "", &window(false), None);
        assert!(abs.contains("from=2026-10-18T10%3A00%3A00Z&to=2026-10-18T11%3A00%3A00Z"));
        assert!(!abs.contains("q="));
    }

    #[test]
    fn entity_links() {
        let l = links();
        assert_eq!(
            l.trace("abc123", Some("def")),
            "https://rush.example.com/trace/abc123?span=def&tenant=prod"
        );
        assert_eq!(
            l.service("orders api", &window(true)),
            "https://rush.example.com/services/orders%20api?t=30&tenant=prod"
        );
        assert_eq!(
            l.saved_query("q1"),
            "https://rush.example.com/?saved=q1&tenant=prod"
        );
        let no_tenant = l.with_tenant(None);
        assert_eq!(no_tenant.deploys(), "https://rush.example.com/deploys");
    }

    #[test]
    fn ids_are_read_from_urls_or_raw_values() {
        let id = "4bf92f3577b34da6a3ce929d0e0e4736";
        assert_eq!(trace_id_from(id).as_deref(), Some(id));
        assert_eq!(
            trace_id_from(&format!("https://rush.example.com/trace/{id}?tenant=prod")).as_deref(),
            Some(id)
        );
        assert_eq!(
            trace_id_from(&format!("https://rush.example.com/?trace={id}&span=x")).as_deref(),
            Some(id)
        );
        assert_eq!(trace_id_from("not-a-trace"), None);
        assert_eq!(
            saved_query_id_from("https://rush.example.com/?saved=c7e43c71-2aa5").as_deref(),
            Some("c7e43c71-2aa5")
        );
        assert_eq!(
            saved_query_id_from("c7e43c71-2aa5").as_deref(),
            Some("c7e43c71-2aa5")
        );
        assert_eq!(saved_query_id_from("../etc"), None);
    }
}
