//! The lock is acquired before loading and retained until this store is dropped.
//! A store that failed to acquire ownership never later promotes its stale state.
use crate::CollectorState;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) enum Access {
    Writer,
    Local,
}

pub(crate) struct HistoryStore {
    pub(crate) state: CollectorState,
    path: PathBuf,
    lock: Option<File>,
}

impl HistoryStore {
    pub(crate) fn open(path: PathBuf, access: Access) -> Result<Self, String> {
        let parent = path.parent().ok_or("history path has no parent")?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|e| format!("create history directory: {e}"))?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("secure history directory: {e}"))?;
        let lock_path = path.with_extension("lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|e| format!("open history lock {}: {e}", lock_path.display()))?;
        // SAFETY: the descriptor remains owned by `lock` throughout this call.
        let acquired = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0;
        let lock = if acquired {
            Some(lock)
        } else {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::WouldBlock {
                return Err(format!("lock history {}: {error}", path.display()));
            }
            if matches!(access, Access::Writer) {
                return Err(format!(
                    "history {} already has an active writer; stop the other agent or retry after the local snapshot completes",
                    path.display()
                ));
            }
            None
        };
        let state = match fs::read(&path) {
            Ok(raw) => serde_json::from_slice(&raw).map_err(|e| {
                format!(
                    "invalid history {}: {e}; file preserved, move it aside to start new history",
                    path.display()
                )
            })?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => CollectorState::default(),
            Err(e) => return Err(format!("read history {}: {e}", path.display())),
        };
        Ok(Self { state, path, lock })
    }

    pub(crate) fn is_writer(&self) -> bool {
        self.lock.is_some()
    }

    pub(crate) fn save(&self) -> Result<(), String> {
        if !self.is_writer() {
            return Ok(());
        }
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let (temporary, mut file) = loop {
            let temporary = self.path.with_extension(format!(
                "tmp.{}.{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)
            {
                Ok(file) => break (temporary, file),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("create history temporary file: {e}")),
            }
        };
        let result = (|| -> Result<(), String> {
            let bytes = serde_json::to_vec(&self.state).map_err(|e| e.to_string())?;
            file.write_all(&bytes).map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            fs::rename(&temporary, &self.path).map_err(|e| e.to_string())?;
            File::open(self.path.parent().unwrap())
                .and_then(|f| f.sync_all())
                .map_err(|e| e.to_string())?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result.map_err(|e| format!("save history {}: {e}", self.path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static SEQUENCE: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "syslens-history-test-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> PathBuf {
            self.0.join("state.json")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn round_trip_preserves_state_and_private_permissions() {
        let fixture = Fixture::new();
        let mut writer = HistoryStore::open(fixture.path(), Access::Writer).unwrap();
        writer.state.maximums.insert("cpu".into(), 42.0);
        writer.save().unwrap();
        assert_eq!(
            fs::metadata(&fixture.0).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(fixture.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(writer);
        let restored = HistoryStore::open(fixture.path(), Access::Writer).unwrap();
        assert_eq!(restored.state.maximums["cpu"], 42.0);
    }

    #[test]
    fn competing_writer_and_stale_local_copy_cannot_replace_owner_state() {
        let fixture = Fixture::new();
        let mut writer = HistoryStore::open(fixture.path(), Access::Writer).unwrap();
        assert!(HistoryStore::open(fixture.path(), Access::Writer).is_err());
        let mut local = HistoryStore::open(fixture.path(), Access::Local).unwrap();
        local.state.maximums.insert("cpu".into(), 99.0);
        writer.state.maximums.insert("cpu".into(), 42.0);
        writer.save().unwrap();
        drop(writer);
        local.save().unwrap(); // Never upgrades a stale copy to writer ownership.
        let restored = HistoryStore::open(fixture.path(), Access::Writer).unwrap();
        assert_eq!(restored.state.maximums["cpu"], 42.0);
    }

    #[test]
    fn malformed_history_is_preserved_and_lock_is_released_on_load_failure() {
        let fixture = Fixture::new();
        fs::write(fixture.path(), b"{broken").unwrap();
        assert!(HistoryStore::open(fixture.path(), Access::Writer).is_err());
        assert_eq!(fs::read(fixture.path()).unwrap(), b"{broken");
        fs::write(fixture.path(), b"{}").unwrap();
        assert!(HistoryStore::open(fixture.path(), Access::Writer).is_ok());
    }

    #[test]
    fn local_writer_releases_ownership_after_refresh() {
        let fixture = Fixture::new();
        let local = HistoryStore::open(fixture.path(), Access::Local).unwrap();
        assert!(local.is_writer());
        local.save().unwrap();
        drop(local);
        assert!(HistoryStore::open(fixture.path(), Access::Writer).is_ok());
    }

    #[test]
    fn failed_replacement_is_reported_and_temporary_file_removed() {
        let fixture = Fixture::new();
        let writer = HistoryStore::open(fixture.path(), Access::Writer).unwrap();
        fs::create_dir(fixture.path()).unwrap();
        assert!(writer.save().unwrap_err().contains("save history"));
        assert!(fixture.path().is_dir());
        assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 2); // state directory and lock
    }
}
