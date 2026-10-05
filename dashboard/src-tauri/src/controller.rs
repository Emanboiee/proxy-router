//! Live controller bridge for the dashboard tray.
//!
//! The dashboard previously read a build-time fixture (`include_str!` of
//! `src/status.json`), so its tray could only ever show the preview state and
//! sat on "disconnected" while the router was up.  This module shells out to
//! the real controller with the same pinned interpreter the launchd tray uses
//! and maps the payload onto the four tray states.
//!
//! Issue: Emanboiee/proxy-router#144.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::Value;

/// Interpreter that owns the runtime (the launchd tray uses the same one).
pub const DEFAULT_PYTHON: &str = "/opt/anaconda3/bin/python3";

/// Runtime root: `PROXY_ROUTER_ROOT` override, else `~/proxy-router`.
pub fn router_root() -> PathBuf {
    if let Ok(value) = std::env::var("PROXY_ROUTER_ROOT") {
        if !value.trim().is_empty() {
            return PathBuf::from(value);
        }
    }
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join("proxy-router")
}

/// Pinned interpreter (`PROXY_ROUTER_PYTHON` override wins).
pub fn router_python() -> String {
    std::env::var("PROXY_ROUTER_PYTHON")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_PYTHON.to_string())
}

pub fn controller_path(root: &Path) -> PathBuf {
    root.join("router.py")
}

/// Run a controller subcommand and return trimmed stdout.
pub fn run_controller(root: &Path, args: &[&str]) -> Result<String, String> {
    let output = run_controller_raw(root, args, CONTROLLER_TIMEOUT)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.trim();
        return Err(if detail.is_empty() {
            format!("controller exited {}", output.status)
        } else {
            format!("controller exited {}: {detail}", output.status)
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Parse `router.py status --json`.
pub fn live_status(root: &Path) -> Result<Value, String> {
    land_status(root, &["status", "--json"])
}

/// Parse `router.py status --json --fast` (no elevation/launchd probes).
///
/// Every poll uses this: the skipped probes spawn `sudo -n` and `launchctl`,
/// they cannot change between polls, and neither the tray state nor the
/// dashboard reads them - so they were pure latency on the poll path.
pub fn live_status_fast(root: &Path) -> Result<Value, String> {
    land_status(root, &["status", "--json", "--fast"])
}

fn land_status(root: &Path, args: &[&str]) -> Result<Value, String> {
    // `status --json` exits 1 while the engine is down but still prints the
    // full JSON document; the exit code alone must not discard real state.
    let out = run_controller_allow_nonzero(root, args)?;
    serde_json::from_str::<Value>(&out)
        .map_err(|error| format!("invalid controller status: {error}"))
}

/// Run a controller subcommand and return stdout even on a non-zero exit.
///
/// Read-only JSON commands exit non-zero for legitimate states: `status --json`
/// exits 1 while the engine is down and `network-status --json` exits 1 when
/// Wi-Fi is unavailable. Treating those as failures would discard real data.
pub fn run_controller_allow_nonzero(root: &Path, args: &[&str]) -> Result<String, String> {
    let output = run_controller_raw(root, args, CONTROLLER_TIMEOUT)?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Ceiling for one controller invocation. A hung router.py must not wedge the
/// tray poll thread or a Tauri command thread forever; the stateful commands
/// all finish well inside this on a cold laptop.
const CONTROLLER_TIMEOUT: Duration = Duration::from_secs(30);

fn run_controller_raw(
    root: &Path,
    args: &[&str],
    timeout: Duration,
) -> Result<std::process::Output, String> {
    let script = controller_path(root);
    if !script.is_file() {
        return Err(format!("controller not found: {}", script.display()));
    }
    let mut child = Command::new(router_python())
        .arg(&script)
        .args(args)
        .current_dir(root)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not run controller: {error}"))?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return output_with_status(child, status);
            }
            Ok(None) => {}
            Err(error) => return Err(format!("could not run controller: {error}")),
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "controller timed out after {}s: {}",
                timeout.as_secs(),
                args.join(" ")
            ));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn output_with_status(
    mut child: std::process::Child,
    status: std::process::ExitStatus,
) -> Result<std::process::Output, String> {
    use std::io::Read;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let Some(mut stream) = child.stdout.take() {
        let _ = stream.read_to_end(&mut stdout);
    }
    if let Some(mut stream) = child.stderr.take() {
        let _ = stream.read_to_end(&mut stderr);
    }
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

/// Parse a read-only JSON subcommand's stdout.
pub fn json_command(root: &Path, args: &[&str]) -> Result<Value, String> {
    let out = run_controller_allow_nonzero(root, args)?;
    serde_json::from_str::<Value>(&out).map_err(|error| format!("invalid JSON from {args:?}: {error}"))
}

/// A transport flag that is not explicitly healthy counts as degraded, but an
/// absent/unknown field must not (the CLI omits them in some paths).
fn flag_needs_attention(status: &Value, key: &str) -> bool {
    match status.get(key).and_then(Value::as_str) {
        Some(value) => !matches!(value, "ok" | "skipped" | "unknown"),
        None => false,
    }
}

/// Map a status payload onto the tray's four visual states.
pub fn connection_state(status: &Value) -> &'static str {
    let error = status
        .get("error")
        .and_then(Value::as_str)
        .map(|text| !text.trim().is_empty())
        .unwrap_or(false);
    if error {
        return "failed";
    }
    let up = status.get("up").and_then(Value::as_bool).unwrap_or(false);
    if !up {
        return "disconnected";
    }
    let degraded_lanes = status
        .get("degraded_lanes")
        .and_then(Value::as_array)
        .map(|lanes| !lanes.is_empty())
        .unwrap_or(false);
    if degraded_lanes || flag_needs_attention(status, "system_proxy_status") {
        return "degraded";
    }
    "connected"
}

/// Tray state for a status fetch, so a dead controller is visible as failed
/// rather than silently frozen on the last good value.
pub fn state_for_result(result: &Result<Value, String>) -> &'static str {
    match result {
        Ok(status) => connection_state(status),
        Err(_) => "failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn healthy_status_is_connected() {
        let status = json!({"up": true, "mode": "proxy", "degraded_lanes": [],
                            "system_proxy_status": "ok", "network_status": "ok", "error": null});
        assert_eq!(connection_state(&status), "connected");
    }

    #[test]
    fn parked_lane_is_degraded() {
        let status = json!({"up": true, "degraded_lanes": [{"lane": "school"}], "error": null});
        assert_eq!(connection_state(&status), "degraded");
    }

    #[test]
    fn unhealthy_system_proxy_is_degraded() {
        let status =
            json!({"up": true, "degraded_lanes": [], "system_proxy_status": "unavailable"});
        assert_eq!(connection_state(&status), "degraded");
    }

    #[test]
    fn unknown_flags_do_not_fake_degradation() {
        let status = json!({"up": true, "mode": "proxy"});
        assert_eq!(connection_state(&status), "connected");
    }

    #[test]
    fn tunnel_down_is_disconnected() {
        let status = json!({"up": false, "mode": "proxy", "error": null});
        assert_eq!(connection_state(&status), "disconnected");
    }

    #[test]
    fn controller_error_is_failed() {
        let status = json!({"up": true, "error": "status parse failed"});
        assert_eq!(connection_state(&status), "failed");
    }

    #[test]
    fn unreachable_controller_is_failed_not_stale() {
        let result: Result<Value, String> = Err("controller not found".to_string());
        assert_eq!(state_for_result(&result), "failed");
        let ok: Result<Value, String> = Ok(json!({"up": true}));
        assert_eq!(state_for_result(&ok), "connected");
    }

    #[test]
    fn missing_controller_path_is_an_error() {
        let root = std::path::Path::new("/nonexistent-proxy-router-root");
        assert!(run_controller(root, &["status", "--json"]).is_err());
        assert!(live_status(root).is_err());
    }

    #[test]
    fn python_prefers_explicit_override() {
        // Guarded so a parallel test cannot race the environment.
        let previous = std::env::var("PROXY_ROUTER_PYTHON").ok();
        std::env::set_var("PROXY_ROUTER_PYTHON", "/usr/bin/python3");
        assert_eq!(router_python(), "/usr/bin/python3");
        match previous {
            Some(value) => std::env::set_var("PROXY_ROUTER_PYTHON", value),
            None => std::env::remove_var("PROXY_ROUTER_PYTHON"),
        }
    }
}
