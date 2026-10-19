//! In-flight SRE-agent investigations.
//!
//! Rush's `POST /api/v1/investigate` answers with a server-sent event stream,
//! and the agent cancels the investigation when that stream is closed. So a
//! tool that returns before the agent finishes hands the stream to a
//! background task, which keeps reading it and records progress here.
//! `get_investigation` reads that progress while the run is going. Rush's
//! session store stays the source of truth: entries here expire 15 minutes
//! after their run ends, and only the key that started a run sees its entry.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::sync::Notify;

use crate::client::ClientKey;
use crate::envelope::clip;

/// How long a finished run stays readable here.
const KEEP_FINISHED: Duration = Duration::from_secs(15 * 60);
/// Runs this server streams at once; more are refused.
const MAX_RUNNING: usize = 32;
/// Tool steps kept per run.
const MAX_STEPS: usize = 200;

/// One agent tool call and its result, each shortened to one line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub tool: String,
    pub input: String,
    pub result: Option<String>,
}

/// Totals the agent reports when a run ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Done {
    pub rounds: u32,
    pub tool_calls: u32,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub model: String,
}

/// What one run has streamed so far.
#[derive(Debug, Default)]
pub struct Progress {
    pub session_id: Option<String>,
    pub steps: Vec<Step>,
    pub steps_dropped: usize,
    /// Latest report: (text, kind), kind being final, preliminary or question.
    pub summary: Option<(String, String)>,
    pub error: Option<String>,
    pub done: Option<Done>,
    pub finished: bool,
    finished_at: Option<Instant>,
}

impl Progress {
    /// Apply one decoded stream event.
    pub fn apply(&mut self, event: &Value) {
        let text = |k: &str| event.get(k).and_then(Value::as_str).unwrap_or_default();
        match text("type") {
            "session_created" => {
                let id = text("session_id");
                if !id.is_empty() {
                    self.session_id = Some(id.to_string());
                }
            }
            "tool_call" => {
                if self.steps.len() >= MAX_STEPS {
                    self.steps_dropped += 1;
                    return;
                }
                self.steps.push(Step {
                    tool: text("name").to_string(),
                    input: one_line(&compact(event.get("args").unwrap_or(&Value::Null)), 160),
                    result: None,
                });
            }
            "tool_result" => {
                let name = text("name");
                if let Some(step) = self
                    .steps
                    .iter_mut()
                    .rev()
                    .find(|s| s.result.is_none() && s.tool == name)
                {
                    step.result = Some(one_line(text("data"), 200));
                }
            }
            "summary" => {
                let kind = match text("kind") {
                    "" => "final",
                    k => k,
                };
                self.summary = Some((text("text").to_string(), kind.to_string()));
            }
            "error" => self.error = Some(clip(text("message"), 500)),
            "done" => {
                let n = |k: &str| event.get(k).and_then(Value::as_u64).unwrap_or(0);
                self.done = Some(Done {
                    rounds: n("rounds") as u32,
                    tool_calls: n("tool_calls") as u32,
                    prompt_tokens: n("prompt_tokens"),
                    completion_tokens: n("completion_tokens"),
                    model: text("model").to_string(),
                });
                let id = text("session_id");
                if self.session_id.is_none() && !id.is_empty() {
                    self.session_id = Some(id.to_string());
                }
            }
            _ => {}
        }
    }

    fn finish(&mut self, error: Option<String>) {
        if self.error.is_none() && self.done.is_none() {
            self.error = error;
        }
        self.finished = true;
        self.finished_at = Some(Instant::now());
    }
}

/// One run's shared progress, plus a signal for waiters.
#[derive(Debug)]
pub struct Live {
    owner: u64,
    progress: Mutex<Progress>,
    changed: Notify,
}

impl Live {
    pub fn progress(&self) -> MutexGuard<'_, Progress> {
        self.progress.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn update(&self, f: impl FnOnce(&mut Progress)) {
        f(&mut self.progress());
        self.changed.notify_waiters();
    }

    /// Record the session a follow-up continues, which the agent doesn't announce.
    pub fn set_session(&self, id: &str) {
        self.update(|p| p.session_id = Some(id.to_string()));
    }

    /// End a run that never got a stream.
    pub fn abandon(&self, error: String) {
        self.update(|p| p.finish(Some(error)));
    }

    /// Wait until `done` holds or `deadline` passes; returns whether it held.
    pub async fn wait_until(&self, deadline: Instant, done: impl Fn(&Progress) -> bool) -> bool {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if done(&self.progress()) {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            tokio::select! {
                _ = &mut notified => {}
                _ = tokio::time::sleep(deadline - now) => {}
            }
        }
    }
}

/// Runs this server is streaming, or finished recently.
#[derive(Debug, Default)]
pub struct Investigations {
    hasher: RandomState,
    runs: Mutex<Vec<Arc<Live>>>,
}

impl Investigations {
    /// Identifies the credential that started a run without keeping the key.
    fn owner(&self, key: Option<&ClientKey>) -> u64 {
        self.hasher
            .hash_one(key.map(|k| k.0.as_str()).unwrap_or(""))
    }

    fn runs(&self) -> MutexGuard<'_, Vec<Arc<Live>>> {
        let mut runs = self.runs.lock().unwrap_or_else(|e| e.into_inner());
        runs.retain(|r| {
            r.progress()
                .finished_at
                .is_none_or(|at| at.elapsed() < KEEP_FINISHED)
        });
        runs
    }

    /// Register a new run, or refuse when too many are streaming.
    pub fn begin(&self, key: Option<&ClientKey>) -> Result<Arc<Live>, String> {
        let mut runs = self.runs();
        if runs.iter().filter(|r| !r.progress().finished).count() >= MAX_RUNNING {
            return Err(format!(
                "this server is already following {MAX_RUNNING} SRE agent investigations; wait for one to finish"
            ));
        }
        let live = Arc::new(Live {
            owner: self.owner(key),
            progress: Mutex::new(Progress::default()),
            changed: Notify::new(),
        });
        runs.push(live.clone());
        Ok(live)
    }

    /// The newest run of `session_id` started with this key.
    pub fn find(&self, key: Option<&ClientKey>, session_id: &str) -> Option<Arc<Live>> {
        let owner = self.owner(key);
        self.runs()
            .iter()
            .rev()
            .find(|r| r.owner == owner && r.progress().session_id.as_deref() == Some(session_id))
            .cloned()
    }

    /// Sessions with a run still streaming for this key.
    pub fn running(&self, key: Option<&ClientKey>) -> Vec<String> {
        let owner = self.owner(key);
        self.runs()
            .iter()
            .filter(|r| r.owner == owner)
            .filter_map(|r| {
                let p = r.progress();
                (!p.finished).then(|| p.session_id.clone()).flatten()
            })
            .collect()
    }
}

/// Read the agent's event stream into `live` until it ends.
pub async fn follow(mut resp: reqwest::Response, live: Arc<Live>) {
    let mut parser = SseParser::default();
    let error = loop {
        match resp.chunk().await {
            Ok(Some(bytes)) => {
                for data in parser.push(&bytes) {
                    if let Ok(event) = serde_json::from_str::<Value>(&data) {
                        live.update(|p| p.apply(&event));
                    }
                }
            }
            Ok(None) => {
                break "the SRE agent stream ended before the investigation finished".into();
            }
            Err(e) => break format!("lost the SRE agent stream: {e}"),
        }
        if live.progress().done.is_some() {
            break String::new();
        }
    };
    live.update(|p| p.finish((!error.is_empty()).then_some(error)));
    // Keep reading after `done` so the agent can save the run before the
    // stream closes, since closing it early cancels the run.
    while let Ok(Some(_)) = resp.chunk().await {}
}

/// Splits a server-sent event stream into the `data` of each event.
#[derive(Debug, Default)]
pub struct SseParser {
    buf: String,
}

impl SseParser {
    pub fn push(&mut self, bytes: &[u8]) -> Vec<String> {
        self.buf.push_str(&String::from_utf8_lossy(bytes));
        if self.buf.contains('\r') {
            self.buf = self.buf.replace("\r\n", "\n");
        }
        let mut out = Vec::new();
        while let Some(end) = self.buf.find("\n\n") {
            let frame: String = self.buf.drain(..end + 2).collect();
            let data: Vec<&str> = frame
                .lines()
                .filter_map(|l| l.strip_prefix("data:"))
                .map(|d| d.strip_prefix(' ').unwrap_or(d))
                .collect();
            if !data.is_empty() {
                out.push(data.join("\n"));
            }
        }
        out
    }
}

/// JSON arguments as `k=v, k=v` for a step line.
fn compact(args: &Value) -> String {
    match args {
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| match v {
                Value::String(s) => format!("{k}={s}"),
                other => format!("{k}={other}"),
            })
            .collect::<Vec<_>>()
            .join(", "),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Collapse whitespace and cut to `max` characters.
pub fn one_line(s: &str, max: usize) -> String {
    clip(&s.split_whitespace().collect::<Vec<_>>().join(" "), max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sse_frames_split_across_chunks_and_line_endings() {
        let mut p = SseParser::default();
        assert!(p.push(b"data: {\"type\":\"session_").is_empty());
        let out =
            p.push(b"created\",\"session_id\":\"s1\"}\r\n\r\n: keep-alive\n\ndata: a\ndata: b\n\n");
        assert_eq!(
            out,
            vec![r#"{"type":"session_created","session_id":"s1"}"#, "a\nb"]
        );
    }

    #[test]
    fn progress_pairs_tool_calls_with_results_and_keeps_the_report() {
        let mut p = Progress::default();
        for e in [
            json!({"type":"session_created","session_id":"s1"}),
            json!({"type":"thinking_delta","text":"…"}),
            json!({"type":"tool_call","name":"search_logs","args":{"service":"checkout","limit":5}}),
            json!({"type":"tool_call","name":"get_trace","args":{"trace_id":"abc"}}),
            json!({"type":"tool_result","name":"search_logs","data":"12 errors\n  in checkout"}),
            json!({"type":"summary","text":"Root cause: pool exhaustion","kind":"final"}),
            json!({"type":"done","rounds":3,"tool_calls":2,"prompt_tokens":900,"completion_tokens":120,"session_id":"s1","model":"m"}),
        ] {
            p.apply(&e);
        }
        assert_eq!(p.session_id.as_deref(), Some("s1"));
        assert_eq!(p.steps[0].input, "limit=5, service=checkout");
        assert_eq!(p.steps[0].result.as_deref(), Some("12 errors in checkout"));
        assert_eq!(p.steps[1].result, None);
        assert_eq!(
            p.summary,
            Some(("Root cause: pool exhaustion".into(), "final".into()))
        );
        assert_eq!(p.done.as_ref().map(|d| d.prompt_tokens), Some(900));
        p.finish(Some("ignored after done".into()));
        assert!(p.finished && p.error.is_none());
    }

    #[test]
    fn a_stream_that_ends_early_is_a_failure() {
        let mut p = Progress::default();
        p.apply(&json!({"type":"session_created","session_id":"s1"}));
        p.finish(Some("stream ended".into()));
        assert_eq!(p.error.as_deref(), Some("stream ended"));
    }

    #[tokio::test]
    async fn runs_are_visible_only_to_the_key_that_started_them() {
        let runs = Investigations::default();
        let mine = ClientKey("rush_qry_mine".into());
        let other = ClientKey("rush_qry_other".into());
        let live = runs.begin(Some(&mine)).unwrap();
        live.update(|p| p.session_id = Some("s1".into()));
        assert!(runs.find(Some(&mine), "s1").is_some());
        assert!(runs.find(Some(&other), "s1").is_none());
        assert!(runs.find(None, "s1").is_none());
        assert_eq!(runs.running(Some(&mine)), vec!["s1".to_string()]);

        let waiter = {
            let live = live.clone();
            tokio::spawn(async move {
                live.wait_until(Instant::now() + Duration::from_secs(5), |p| p.finished)
                    .await
            })
        };
        live.update(|p| p.finish(None));
        assert!(waiter.await.unwrap());
        assert!(runs.running(Some(&mine)).is_empty());
    }

    #[test]
    fn too_many_streams_are_refused() {
        let runs = Investigations::default();
        for _ in 0..MAX_RUNNING {
            runs.begin(None).unwrap();
        }
        assert!(runs.begin(None).is_err());
    }
}
