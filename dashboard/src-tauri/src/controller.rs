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
    run_controller_with_python(root, args, timeout, &router_python())
}

fn run_controller_with_python(
    root: &Path,
    args: &[&str],
    timeout: Duration,
    python: &str,
) -> Result<std::process::Output, String> {
    let script = controller_path(root);
    if !script.is_file() {
        return Err(format!("controller not found: {}", script.display()));
    }
    let mut child = Command::new(python)
        .arg(&script)
        .args(args)
        .current_dir(root)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not run controller: {error}"))?;
    let stdout_reader = child.stdout.take().map(read_pipe);
    let stderr_reader = child.stderr.take().map(read_pipe);
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return output_with_status(status, stdout_reader, stderr_reader);
            }
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = finish_pipe_reader(stdout_reader);
                let _ = finish_pipe_reader(stderr_reader);
                return Err(format!("could not run controller: {error}"));
            }
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = finish_pipe_reader(stdout_reader);
            let _ = finish_pipe_reader(stderr_reader);
            return Err(format!(
                "controller timed out after {}s: {}",
                timeout.as_secs(),
                args.join(" ")
            ));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn read_pipe<R: std::io::Read + Send + 'static>(
    mut stream: R,
) -> std::thread::JoinHandle<std::io::Result<Vec<u8>>> {
    std::thread::spawn(move || {
        let mut output = Vec::new();
        stream.read_to_end(&mut output)?;
        Ok(output)
    })
}

fn finish_pipe_reader(
    reader: Option<std::thread::JoinHandle<std::io::Result<Vec<u8>>>>,
) -> Result<Vec<u8>, String> {
    let Some(reader) = reader else {
        return Ok(Vec::new());
    };
    reader
        .join()
        .map_err(|_| "controller output reader panicked".to_string())?
        .map_err(|error| format!("could not read controller output: {error}"))
}

fn output_with_status(
    status: std::process::ExitStatus,
    stdout_reader: Option<std::thread::JoinHandle<std::io::Result<Vec<u8>>>>,
    stderr_reader: Option<std::thread::JoinHandle<std::io::Result<Vec<u8>>>>,
) -> Result<std::process::Output, String> {
    let stdout = finish_pipe_reader(stdout_reader)?;
    let stderr = finish_pipe_reader(stderr_reader)?;
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

/// Parse a read-only JSON subcommand's stdout.
pub fn json_command(root: &Path, args: &[&str]) -> Result<Value, String> {
    let out = run_controller_allow_nonzero(root, args)?;
    serde_json::from_str::<Value>(&out)
        .map_err(|error| format!("invalid JSON from {args:?}: {error}"))
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
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestControllerRoot(PathBuf);

    impl TestControllerRoot {
        fn new(script: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock before unix epoch")
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "proxy-router-controller-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&root).expect("create temporary controller root");
            fs::write(root.join("router.py"), script).expect("write temporary controller");
            Self(root)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestControllerRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

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
    fn controller_drains_large_stdout_and_stderr_concurrently() {
        let root = TestControllerRoot::new(
            "import sys\nsys.stdout.write('out' * 131072)\nsys.stdout.flush()\nsys.stderr.write('err' * 131072)\nsys.stderr.flush()\n",
        );
        let output =
            run_controller_with_python(root.path(), &[], Duration::from_secs(10), "python3")
                .expect("controller completes after writing beyond both pipe capacities");

        assert!(output.status.success());
        assert_eq!(output.stdout, b"out".repeat(131072));
        assert_eq!(output.stderr, b"err".repeat(131072));
    }

    #[cfg(unix)]
    #[test]
    fn timed_out_controller_is_killed_and_reaped() {
        let root = TestControllerRoot::new(
            "import pathlib, sys, time\npathlib.Path(sys.argv[1]).write_text(str(__import__('os').getpid()))\ntime.sleep(60)\n",
        );
        let pid_file = root.path().join("child.pid");
        let pid_argument = pid_file.to_str().expect("temporary path is valid UTF-8");
        let result = run_controller_with_python(
            root.path(),
            &[pid_argument],
            Duration::from_secs(2),
            "python3",
        );

        let error = result.expect_err("hung controller should time out");
        assert!(error.contains("controller timed out"), "{error}");
        let pid = fs::read_to_string(pid_file)
            .expect("child started before timeout")
            .parse::<u32>()
            .expect("child wrote a process id");
        let still_running = Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .status()
            .expect("check child process");
        assert!(
            !still_running.success(),
            "timed out child {pid} is still running"
        );
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
