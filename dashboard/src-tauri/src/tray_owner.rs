//! Atomic dashboard menu-bar ownership lease shared with proxy_tray.py.
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Must stay in sync with proxy_tray.py's owner record path and JSON fields.
pub const OWNER_FILE: &str = "state/dashboard-owns-tray.json";
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub struct TrayOwnerLease {
    root: PathBuf,
    path: PathBuf,
    owner_id: String,
    stopped: Arc<(Mutex<bool>, Condvar)>,
}

impl TrayOwnerLease {
    /// Claim the tray and immediately publish the first heartbeat.
    pub fn claim(root: &Path) -> io::Result<Self> {
        let root = fs::canonicalize(root)?;
        let started_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?
            .as_nanos();
        let owner_id = format!("{}-{started_ns}", std::process::id());
        let lease = Self {
            root: root.to_path_buf(),
            path: root.join(OWNER_FILE),
            owner_id,
            stopped: Arc::new((Mutex::new(false), Condvar::new())),
        };
        lease.write_record()?;
        Ok(lease)
    }

    /// Refresh the lease on its own thread, even if a controller poll stalls.
    pub fn start_heartbeat(&self) -> io::Result<JoinHandle<()>> {
        self.start_heartbeat_every(HEARTBEAT_INTERVAL)
    }

    fn start_heartbeat_every(&self, interval: Duration) -> io::Result<JoinHandle<()>> {
        let lease = self.clone();
        thread::Builder::new()
            .name("tray-owner-heartbeat".into())
            .spawn(move || loop {
                let (lock, wake) = &*lease.stopped;
                let stopped = lock.lock().unwrap_or_else(|poison| poison.into_inner());
                let (stopped, _) = wake
                    .wait_timeout(stopped, interval)
                    .unwrap_or_else(|poison| poison.into_inner());
                if *stopped {
                    break;
                }
                drop(stopped);
                if let Err(error) = lease.heartbeat() {
                    eprintln!("tray owner heartbeat failed: {error}");
                }
            })
    }

    fn heartbeat(&self) -> io::Result<()> {
        let (lock, _) = &*self.stopped;
        let stopped = lock.lock().unwrap_or_else(|poison| poison.into_inner());
        if *stopped {
            return Ok(());
        }
        self.write_record()
    }

    fn write_record(&self) -> io::Result<()> {
        let at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?
            .as_secs_f64();
        self.write_record_at(at)
    }

    fn write_record_at(&self, at: f64) -> io::Result<()> {
        let parent = self.path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "owner path has no parent")
        })?;
        fs::create_dir_all(parent)?;
        let temp_path = parent.join(format!(".dashboard-owns-tray-{}.tmp", self.owner_id));
        let record = json!({
            "pid": std::process::id(),
            "at": at,
            "root": self.root.to_string_lossy(),
            "owner_id": self.owner_id,
        });

        let result = (|| {
            let mut temp = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)?;
            serde_json::to_writer(&mut temp, &record)
                .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?;
            temp.write_all(b"\n")?;
            temp.sync_all()?;
            drop(temp);
            fs::rename(&temp_path, &self.path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result
    }

    /// Relinquish only this process's claim so clean quit returns the tray to Python.
    pub fn release(&self) -> io::Result<()> {
        let (lock, wake) = &*self.stopped;
        let mut stopped = lock.lock().unwrap_or_else(|poison| poison.into_inner());
        *stopped = true;
        wake.notify_all();

        let contents = match fs::read_to_string(&self.path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        let current: Value = match serde_json::from_str(&contents) {
            Ok(record) => record,
            Err(_) => return Ok(()),
        };
        if current.get("owner_id").and_then(Value::as_str) != Some(&self.owner_id) {
            return Ok(());
        }
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn temp_root() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("proxy-router-owner-{nonce}"));
        fs::create_dir_all(&root).unwrap();
        fs::canonicalize(root).unwrap()
    }

    #[test]
    fn claim_and_quit_publish_and_remove_the_python_lease() {
        let root = temp_root();
        let lease = TrayOwnerLease::claim(&root).unwrap();
        let path = root.join(OWNER_FILE);
        let record: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(record["pid"], std::process::id());
        assert!(record["at"].as_f64().is_some());
        assert_eq!(record["root"], root.to_string_lossy().as_ref());
        assert!(record["owner_id"].as_str().is_some());

        lease.release().unwrap();
        assert!(!path.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn heartbeat_replaces_the_complete_record_and_stops_on_release() {
        let root = temp_root();
        let lease = TrayOwnerLease::claim(&root).unwrap();
        let path = root.join(OWNER_FILE);
        let handle = lease
            .start_heartbeat_every(Duration::from_millis(5))
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(1);
        let initial: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let mut refreshed = false;
        while Instant::now() < deadline {
            let current: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
            if current["at"] != initial["at"] {
                refreshed = true;
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(refreshed, "heartbeat did not refresh the lease");

        lease.release().unwrap();
        handle.join().unwrap();
        assert!(!path.exists());
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn quit_does_not_remove_a_replacement_owners_lease() {
        let root = temp_root();
        let lease = TrayOwnerLease::claim(&root).unwrap();
        let path = root.join(OWNER_FILE);
        let mut replacement: Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        replacement["owner_id"] = json!("replacement-owner");
        fs::write(&path, serde_json::to_vec(&replacement).unwrap()).unwrap();

        lease.release().unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(&path).unwrap()).unwrap()["owner_id"],
            "replacement-owner"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn heartbeat_uses_the_atomic_temporary_file_path() {
        let root = temp_root();
        let lease = TrayOwnerLease::claim(&root).unwrap();
        lease.write_record_at(1_000.5).unwrap();
        let path = root.join(OWNER_FILE);
        let record: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(record["at"], 1_000.5);
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
        lease.release().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
