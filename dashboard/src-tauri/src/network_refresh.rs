//! Coalesce stale network checks without blocking status polling.
use serde_json::Value;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const RETRY_DELAY: Duration = Duration::from_secs(60);

#[derive(Default)]
struct RefreshState {
    running: bool,
    finished: Option<Instant>,
}

#[derive(Default)]
pub struct NetworkRefresh(Mutex<RefreshState>);

impl NetworkRefresh {
    pub fn try_start(&self, payload: &Value, now: Instant) -> bool {
        if payload.get("up").and_then(Value::as_bool) != Some(true) {
            return false;
        }
        let network = payload.get("network");
        let fresh = network.and_then(|value| value.get("stale")).and_then(Value::as_bool) == Some(false);
        let status = network.and_then(|value| value.get("status")).and_then(Value::as_str);
        if fresh && matches!(status, Some(value) if !matches!(value, "unknown" | "skipped")) {
            return false;
        }
        let Ok(mut state) = self.0.lock() else { return false; };
        if state.running || state.finished.map(|at| now.saturating_duration_since(at) < RETRY_DELAY).unwrap_or(false) {
            return false;
        }
        state.running = true;
        true
    }

    pub fn finish(&self, now: Instant) {
        if let Ok(mut state) = self.0.lock() {
            state.running = false;
            state.finished = Some(now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn stale_checks_are_coalesced_and_failures_are_paced() {
        let refresh = NetworkRefresh::default();
        let stale = json!({"up":true,"network":{"stale":true,"status":"ok"}});
        let now = Instant::now();
        assert!(refresh.try_start(&stale, now));
        assert!(!refresh.try_start(&stale, now + Duration::from_secs(90)));
        refresh.finish(now + Duration::from_secs(91));
        assert!(!refresh.try_start(&stale, now + Duration::from_secs(150)));
        assert!(refresh.try_start(&stale, now + Duration::from_secs(151)));
    }

    #[test]
    fn fresh_failures_are_not_hidden_or_reprobed_on_every_poll() {
        let refresh = NetworkRefresh::default();
        let now = Instant::now();
        for status in ["ok", "unavailable"] {
            assert!(!refresh.try_start(&json!({"up":true,"network":{"stale":false,"status":status}}), now));
        }
        assert!(!refresh.try_start(&json!({"up":false}), now));
        assert!(refresh.try_start(&json!({"up":true}), now));
    }

    #[test]
    fn successful_refresh_keeps_future_polls_cheap() {
        let refresh = NetworkRefresh::default();
        let now = Instant::now();
        assert!(refresh.try_start(&json!({"up":true}), now));
        refresh.finish(now);
        assert!(!refresh.try_start(&json!({"up":true,"network":{"stale":false,"status":"ok"}}), now + Duration::from_secs(600)));
    }

    #[test]
    fn skipped_check_is_retried_without_claiming_fresh_health() {
        let refresh = NetworkRefresh::default();
        let payload = json!({"up":true,"network":{"stale":false,"status":"skipped"}});
        assert!(refresh.try_start(&payload, Instant::now()));
    }
}
