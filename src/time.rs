//! Time expressions accepted by every tool, resolved to an explicit UTC window.
//!
//! Grammar: `now`, `now-<duration>`, a bare duration (`15m`, `1h30m`, `7d`) as a
//! lookback, RFC3339 (`2026-10-18T14:00:00Z`, `…+02:00`), `YYYY-MM-DD HH:MM[:SS]`
//! and `YYYY-MM-DD` (UTC), Unix seconds or milliseconds, `today`, `yesterday`.

use chrono::{DateTime, Duration, NaiveDate, NaiveDateTime, TimeZone, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Longest window a tool will request.
pub const MAX_WINDOW: Duration = Duration::days(31);
pub const DEFAULT_LOOKBACK: &str = "1h";

/// Time arguments shared by every query tool.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct TimeArgs {
    /// Lookback ending at `to` (default now), e.g. "15m", "1h", "24h", "7d". Default "1h".
    /// Ignored when `from` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last: Option<String>,
    /// Window start: RFC3339, "YYYY-MM-DD HH:MM" (UTC), Unix seconds, "now-2h", "today", "yesterday".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Window end, same formats as `from`. Default "now".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    /// Lookback in minutes when the window ends at "now", so UI links can use
    /// a relative range that stays live.
    pub relative_minutes: Option<i64>,
}

/// The window as echoed in tool results.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
pub struct WindowOut {
    pub from: String,
    pub to: String,
}

impl Window {
    pub fn out(&self) -> WindowOut {
        WindowOut {
            from: rfc3339(self.from),
            to: rfc3339(self.to),
        }
    }

    pub fn from_rfc3339(&self) -> String {
        rfc3339(self.from)
    }

    pub fn to_rfc3339(&self) -> String {
        rfc3339(self.to)
    }

    pub fn duration(&self) -> Duration {
        self.to - self.from
    }

    /// The same-length window immediately before this one.
    pub fn previous(&self) -> Window {
        let len = self.duration();
        Window {
            from: self.from - len,
            to: self.from,
            relative_minutes: None,
        }
    }
}

pub fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

impl TimeArgs {
    pub fn resolve(&self) -> Result<Window, String> {
        self.resolve_at(Utc::now())
    }

    pub fn resolve_at(&self, now: DateTime<Utc>) -> Result<Window, String> {
        let to_raw = self.to.as_deref().map(str::trim).filter(|s| !s.is_empty());
        let to = match to_raw {
            Some(raw) => parse_instant(raw, now)?,
            None => now,
        };
        let ends_now = to_raw.is_none() || to_raw.is_some_and(|r| r.eq_ignore_ascii_case("now"));
        let from_raw = self
            .from
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let (from, relative) = match from_raw {
            Some(raw) => (parse_instant(raw, now)?, None),
            None => {
                let last = self
                    .last
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or(DEFAULT_LOOKBACK);
                let len = parse_duration(last)?;
                (to - len, ends_now.then(|| len.num_minutes().max(1)))
            }
        };
        if from >= to {
            return Err(format!(
                "the window start ({}) must be before its end ({})",
                rfc3339(from),
                rfc3339(to)
            ));
        }
        if to - from > MAX_WINDOW {
            return Err("the window is longer than 31 days; narrow it".into());
        }
        Ok(Window {
            from,
            to,
            relative_minutes: relative,
        })
    }
}

/// Parse one instant relative to `now`.
pub fn parse_instant(raw: &str, now: DateTime<Utc>) -> Result<DateTime<Utc>, String> {
    let s = raw.trim();
    let lower = s.to_ascii_lowercase();
    match lower.as_str() {
        "now" => return Ok(now),
        "today" => return Ok(start_of_day(now)),
        "yesterday" => return Ok(start_of_day(now) - Duration::days(1)),
        _ => {}
    }
    if let Some(rest) = lower.strip_prefix("now-") {
        return Ok(now - parse_duration(rest)?);
    }
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()) {
        let n: i64 = s
            .parse()
            .map_err(|_| format!("`{s}` is not a valid timestamp"))?;
        let ts = if s.len() >= 13 {
            Utc.timestamp_millis_opt(n).single()
        } else {
            Utc.timestamp_opt(n, 0).single()
        };
        return ts.ok_or_else(|| format!("`{s}` is not a valid Unix timestamp"));
    }
    if let Ok(t) = DateTime::parse_from_rfc3339(s) {
        return Ok(t.with_timezone(&Utc));
    }
    for fmt in [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
    ] {
        if let Ok(t) = NaiveDateTime::parse_from_str(s, fmt) {
            return Ok(Utc.from_utc_datetime(&t));
        }
    }
    if let Ok(d) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Ok(Utc.from_utc_datetime(&d.and_hms_opt(0, 0, 0).expect("midnight is valid")));
    }
    if parse_duration(s).is_ok() {
        return Err(format!(
            "`{s}` is a duration, not an instant; use `now-{s}` or pass it as `last`"
        ));
    }
    Err(format!(
        "can't read `{s}` as a time; use RFC3339 (2026-10-18T14:00:00Z), \"YYYY-MM-DD HH:MM\" (UTC), \
         Unix seconds, \"now-1h\", \"today\" or \"yesterday\""
    ))
}

/// Parse `15m`, `1h30m`, `2d`, `1w`, `90s`.
pub fn parse_duration(raw: &str) -> Result<Duration, String> {
    let s = raw.trim().to_ascii_lowercase();
    if s.is_empty() {
        return Err("empty duration".into());
    }
    let mut total = Duration::zero();
    let mut digits = String::new();
    let mut saw_unit = false;
    for c in s.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let n: i64 = digits
            .parse()
            .map_err(|_| format!("`{raw}` is not a duration like 15m, 1h or 7d"))?;
        digits.clear();
        let unit = match c {
            's' => Duration::seconds(n),
            'm' => Duration::minutes(n),
            'h' => Duration::hours(n),
            'd' => Duration::days(n),
            'w' => Duration::weeks(n),
            _ => return Err(format!("`{raw}` is not a duration like 15m, 1h or 7d")),
        };
        total += unit;
        saw_unit = true;
    }
    if !digits.is_empty() || !saw_unit || total <= Duration::zero() {
        return Err(format!("`{raw}` is not a duration like 15m, 1h or 7d"));
    }
    Ok(total)
}

fn start_of_day(t: DateTime<Utc>) -> DateTime<Utc> {
    Utc.from_utc_datetime(
        &t.date_naive()
            .and_hms_opt(0, 0, 0)
            .expect("midnight is valid"),
    )
}

/// Pick a bucket size giving roughly `target` points across the window. Uses
/// only intervals every Rush time-series endpoint accepts.
pub fn bucket_for(window: &Window, target: i64) -> &'static str {
    const STEPS: &[(i64, &str)] = &[
        (10, "10s"),
        (60, "1m"),
        (300, "5m"),
        (900, "15m"),
        (3_600, "1h"),
        (86_400, "1d"),
    ];
    let secs = window.duration().num_seconds().max(1);
    let want = secs / target.max(1);
    STEPS
        .iter()
        .find(|(s, _)| *s >= want)
        .map(|(_, label)| *label)
        .unwrap_or("1d")
}

/// Seconds in an interval label produced by [`bucket_for`].
pub fn interval_secs(label: &str) -> i64 {
    parse_duration(label).map(|d| d.num_seconds()).unwrap_or(60)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 18, 14, 30, 0).unwrap()
    }

    fn args(last: Option<&str>, from: Option<&str>, to: Option<&str>) -> TimeArgs {
        TimeArgs {
            last: last.map(Into::into),
            from: from.map(Into::into),
            to: to.map(Into::into),
        }
    }

    #[test]
    fn defaults_to_the_last_hour_ending_now() {
        let w = TimeArgs::default().resolve_at(now()).unwrap();
        assert_eq!(w.to, now());
        assert_eq!(w.duration(), Duration::hours(1));
        assert_eq!(w.relative_minutes, Some(60));
    }

    #[test]
    fn reads_every_supported_instant_format() {
        let n = now();
        assert_eq!(
            parse_instant("now-15m", n).unwrap(),
            n - Duration::minutes(15)
        );
        assert_eq!(
            parse_instant("2026-10-18T12:00:00Z", n)
                .unwrap()
                .to_rfc3339(),
            "2026-10-18T12:00:00+00:00"
        );
        assert_eq!(
            parse_instant("2026-10-18T14:00:00+02:00", n).unwrap(),
            Utc.with_ymd_and_hms(2026, 10, 18, 12, 0, 0).unwrap()
        );
        assert_eq!(
            parse_instant("2026-10-18 09:15", n).unwrap(),
            Utc.with_ymd_and_hms(2026, 10, 18, 9, 15, 0).unwrap()
        );
        assert_eq!(
            parse_instant("2026-10-17", n).unwrap(),
            Utc.with_ymd_and_hms(2026, 10, 17, 0, 0, 0).unwrap()
        );
        assert_eq!(
            parse_instant("1760796000", n).unwrap(),
            Utc.timestamp_opt(1_760_796_000, 0).unwrap()
        );
        assert_eq!(
            parse_instant("1760796000000", n).unwrap(),
            Utc.timestamp_opt(1_760_796_000, 0).unwrap()
        );
        assert_eq!(
            parse_instant("today", n).unwrap(),
            Utc.with_ymd_and_hms(2026, 10, 18, 0, 0, 0).unwrap()
        );
        assert_eq!(
            parse_instant("Yesterday", n).unwrap(),
            Utc.with_ymd_and_hms(2026, 10, 17, 0, 0, 0).unwrap()
        );
    }

    #[test]
    fn explains_bad_input() {
        assert!(parse_instant("1h", now()).unwrap_err().contains("now-1h"));
        assert!(
            parse_instant("last tuesday", now())
                .unwrap_err()
                .contains("RFC3339")
        );
        for bad in ["", "h", "10", "1x", "-5m", "0m"] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
        assert_eq!(parse_duration("1h30m").unwrap(), Duration::minutes(90));
    }

    #[test]
    fn explicit_windows_are_absolute_and_bounded() {
        let w = args(None, Some("2026-10-18 10:00"), Some("2026-10-18 11:00"))
            .resolve_at(now())
            .unwrap();
        assert_eq!(w.relative_minutes, None);
        assert_eq!(w.out().from, "2026-10-18T10:00:00Z");
        assert!(
            args(None, Some("now"), Some("now-1h"))
                .resolve_at(now())
                .is_err()
        );
        assert!(
            args(Some("45d"), None, None)
                .resolve_at(now())
                .unwrap_err()
                .contains("31 days")
        );
        // `last` before a fixed end is absolute.
        let w = args(Some("30m"), None, Some("2026-10-18 11:00"))
            .resolve_at(now())
            .unwrap();
        assert_eq!(w.relative_minutes, None);
        assert_eq!(w.duration(), Duration::minutes(30));
    }

    #[test]
    fn previous_window_has_the_same_length() {
        let w = args(Some("2h"), None, None).resolve_at(now()).unwrap();
        let p = w.previous();
        assert_eq!(p.to, w.from);
        assert_eq!(p.duration(), w.duration());
    }

    #[test]
    fn buckets_scale_with_the_window() {
        let w = |last| args(Some(last), None, None).resolve_at(now()).unwrap();
        assert_eq!(bucket_for(&w("1h"), 60), "1m");
        assert_eq!(bucket_for(&w("24h"), 48), "1h");
        assert_eq!(bucket_for(&w("7d"), 60), "1d");
        assert_eq!(interval_secs("15m"), 900);
    }
}
