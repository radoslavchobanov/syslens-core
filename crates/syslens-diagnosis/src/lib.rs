//! Local evidence recording and deterministic memory diagnosis for SysLens.
//!
//! This crate deliberately has no dependency on syslens-core or MQTT.  It is
//! an optional, host-local companion and may be stopped or removed independently.

use chrono::{DateTime, Datelike, Duration, Local, TimeZone, Utc};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration as StdDuration, SystemTime, UNIX_EPOCH};

pub const SCHEMA_VERSION: i64 = 2;
pub const MIN_SQLITE: (i32, i32, i32) = (3, 51, 3);
pub const GIB: u64 = 1024 * 1024 * 1024;
const CONTROL_HEADROOM: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default = "default_interval")]
    pub interval_seconds: u64,
    #[serde(default = "default_retention")]
    pub retention_days: u32,
    #[serde(default = "default_budget")]
    pub database_budget_bytes: u64,
    #[serde(default)]
    pub storage: StorageConfig,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    #[serde(default = "default_scan_interval")]
    pub scan_interval_seconds: u64,
    #[serde(default = "default_max_depth")]
    pub max_depth: u8,
    #[serde(default = "default_max_entries")]
    pub max_entries: u64,
    #[serde(default = "default_max_duration")]
    pub max_duration_seconds: u64,
    /// When absent, eligible writable local mount roots are scanned.
    #[serde(default)]
    pub roots: Option<Vec<PathBuf>>,
}
fn default_scan_interval() -> u64 {
    3600
}
fn default_max_depth() -> u8 {
    4
}
fn default_max_entries() -> u64 {
    1_000_000
}
fn default_max_duration() -> u64 {
    120
}
impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            scan_interval_seconds: default_scan_interval(),
            max_depth: default_max_depth(),
            max_entries: default_max_entries(),
            max_duration_seconds: default_max_duration(),
            roots: None,
        }
    }
}
fn default_version() -> u32 {
    1
}
fn default_interval() -> u64 {
    30
}
fn default_retention() -> u32 {
    185
}
fn default_budget() -> u64 {
    16 * GIB
}
impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            interval_seconds: 30,
            retention_days: 185,
            database_budget_bytes: 16 * GIB,
            storage: StorageConfig::default(),
        }
    }
}
impl Config {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 {
            return Err(format!(
                "unsupported config version {}; expected 1",
                self.version
            ));
        }
        if !(5..=300).contains(&self.interval_seconds) {
            return Err("interval_seconds must be between 5 and 300".into());
        }
        if !(185..=3650).contains(&self.retention_days) {
            return Err("retention_days must be between 185 and 3650".into());
        }
        if self.database_budget_bytes < GIB {
            return Err("database_budget_bytes must be at least 1 GiB".into());
        }
        let s = &self.storage;
        if !(300..=86_400).contains(&s.scan_interval_seconds) {
            return Err("storage.scan_interval_seconds must be between 300 and 86400".into());
        }
        if !(1..=8).contains(&s.max_depth) {
            return Err("storage.max_depth must be between 1 and 8".into());
        }
        if !(1_000..=10_000_000).contains(&s.max_entries) {
            return Err("storage.max_entries must be between 1000 and 10000000".into());
        }
        if !(5..=3_600).contains(&s.max_duration_seconds) {
            return Err("storage.max_duration_seconds must be between 5 and 3600".into());
        }
        Ok(())
    }
}

pub fn config_path() -> PathBuf {
    xdg_path("XDG_CONFIG_HOME", ".config").join("syslens-diagnosis/config.toml")
}
pub fn user_service_path() -> PathBuf {
    xdg_path("XDG_CONFIG_HOME", ".config").join("systemd/user/syslens-diagnosis.service")
}
pub fn service_unit(binary: &Path, config: &Path, database: &Path) -> String {
    format!(
        "[Unit]\nDescription=SysLens local diagnosis companion\n\n[Service]\nType=simple\nExecStart={} daemon --config {} --database {}\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=default.target\n",
        binary.display(),
        config.display(),
        database.display()
    )
}
pub fn install_user_service(
    binary: &Path,
    config: &Path,
    database: &Path,
) -> Result<PathBuf, String> {
    let path = user_service_path();
    let parent = path.parent().ok_or("service path has no parent")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    fs::write(&path, service_unit(binary, config, database))
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(path)
}
pub fn linger_warning_message(user: &str, linger_enabled: bool) -> Option<String> {
    (!linger_enabled).then(|| format!("Warning: systemd user services may stop after logout because lingering is not enabled. To keep diagnosis recording, run: loginctl enable-linger {user}"))
}
pub fn state_dir() -> PathBuf {
    xdg_path("XDG_STATE_HOME", ".local/state").join("syslens-diagnosis")
}
pub fn database_path() -> PathBuf {
    state_dir().join("diagnosis.sqlite")
}
pub fn database_path_for_config(config: &Path) -> PathBuf {
    if config == config_path() {
        database_path()
    } else {
        config.with_extension("sqlite")
    }
}
fn xdg_path(var: &str, fallback: &str) -> PathBuf {
    std::env::var_os(var).map(PathBuf::from).unwrap_or_else(|| {
        std::env::var_os("HOME")
            .map(|h| PathBuf::from(h).join(fallback))
            .unwrap_or_else(|| PathBuf::from(fallback))
    })
}
pub fn load_config(path: &Path) -> Result<Config, String> {
    let text =
        fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let config: Config =
        toml::from_str(&text).map_err(|e| format!("invalid {}: {e}", path.display()))?;
    config.validate()?;
    Ok(config)
}
pub fn ensure_config(path: &Path) -> Result<Config, String> {
    if path.exists() {
        return load_config(path);
    }
    let parent = path.parent().ok_or("config path has no parent")?;
    fs::create_dir_all(parent).map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("cannot secure {}: {e}", parent.display()))?;
    let text = toml::to_string_pretty(&Config::default()).map_err(|e| e.to_string())?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    use std::io::Write;
    file.write_all(text.as_bytes())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Config::default().validate()?;
    Ok(Config::default())
}

#[derive(Debug)]
pub struct WriterLock {
    _file: File,
}
pub fn acquire_writer_lock(dir: &Path) -> Result<WriterLock, String> {
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let p = dir.join("daemon.lock");
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&p)
        .map_err(|e| format!("cannot open writer lock: {e}"))?;
    // `flock` stays held for this open descriptor and is released on process exit.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("another syslens-diagnosis daemon is already recording".into());
    }
    Ok(WriterLock { _file: file })
}

pub fn open_db(path: &Path) -> Result<Connection, String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| e.to_string())?;
    conn.busy_timeout(StdDuration::from_secs(5))
        .map_err(|e| e.to_string())?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|e| e.to_string())?;
    let foreign_keys: i64 = conn
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(|e| e.to_string())?;
    if foreign_keys != 1 {
        return Err("SQLite foreign-key enforcement is unavailable".into());
    }
    let busy_timeout: i64 = conn
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .map_err(|e| e.to_string())?;
    if busy_timeout != 5_000 {
        return Err(format!(
            "SQLite busy timeout is {busy_timeout}ms, expected 5000ms"
        ));
    }
    let mode: String = conn
        .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if mode.to_lowercase() != "wal" {
        return Err(format!("SQLite refused WAL mode: {mode}"));
    }
    let version: String = conn
        .query_row("SELECT sqlite_version()", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if !version_at_least(&version, MIN_SQLITE) {
        return Err(format!(
            "SQLite {version} is too old; need at least {}.{}.{}",
            MIN_SQLITE.0, MIN_SQLITE.1, MIN_SQLITE.2
        ));
    }
    migrate(&conn)?;
    Ok(conn)
}
pub fn initialize_db(path: &Path, config: &Config) -> Result<Connection, String> {
    let conn = open_db(path)?;
    conn.execute("INSERT INTO metadata(key,value) VALUES('interval_seconds',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [config.interval_seconds.to_string()]).map_err(|e| e.to_string())?;
    Ok(conn)
}
fn version_at_least(text: &str, min: (i32, i32, i32)) -> bool {
    let p: Vec<i32> = text.split('.').filter_map(|x| x.parse().ok()).collect();
    (
        p.first().copied().unwrap_or(0),
        p.get(1).copied().unwrap_or(0),
        p.get(2).copied().unwrap_or(0),
    ) >= min
}
fn migrate(conn: &Connection) -> Result<(), String> {
    let v: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if v > SCHEMA_VERSION {
        return Err(format!(
            "database schema {v} is newer than supported {SCHEMA_VERSION}"
        ));
    }
    if v == SCHEMA_VERSION {
        return Ok(());
    }
    if v == 0 {
        conn.execute_batch("PRAGMA auto_vacuum=INCREMENTAL; VACUUM;")
            .map_err(|e| e.to_string())?;
        let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
        tx.execute_batch("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE host_samples (timestamp INTEGER PRIMARY KEY, boot_id TEXT NOT NULL, duration_ms INTEGER NOT NULL, status TEXT NOT NULL, mem_total INTEGER, mem_available INTEGER, mem_free INTEGER, buffers INTEGER, cached INTEGER, slab INTEGER, swap_total INTEGER, swap_free INTEGER, psi_some REAL, psi_full REAL);
CREATE TABLE process_identities (id INTEGER PRIMARY KEY, boot_id TEXT NOT NULL, pid INTEGER NOT NULL, start_ticks INTEGER NOT NULL, name TEXT NOT NULL, executable TEXT, uid INTEGER, cgroup_name TEXT, UNIQUE(boot_id,pid,start_ticks));
CREATE TABLE process_samples (timestamp INTEGER NOT NULL REFERENCES host_samples(timestamp) ON DELETE CASCADE, identity_id INTEGER NOT NULL REFERENCES process_identities(id) ON DELETE CASCADE, rss_anon INTEGER, rss_file INTEGER, rss_shmem INTEGER, rss_total INTEGER, cpu_ticks INTEGER, read_bytes INTEGER, write_bytes INTEGER, PRIMARY KEY(timestamp,identity_id));
CREATE INDEX process_samples_identity_time ON process_samples(identity_id,timestamp);
CREATE INDEX process_samples_time ON process_samples(timestamp);
CREATE TABLE collection_gaps (id INTEGER PRIMARY KEY, timestamp INTEGER NOT NULL, reason TEXT NOT NULL, duration_ms INTEGER, UNIQUE(timestamp,reason));
PRAGMA user_version=1;").map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
    }
    // v2 adds storage tables without changing any retained RAM rows.
    let v: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if v == 1 {
        conn.execute_batch("BEGIN IMMEDIATE;
CREATE TABLE mount_samples (timestamp INTEGER NOT NULL, mount_id TEXT NOT NULL, mount_point TEXT NOT NULL, fs_type TEXT NOT NULL, total_bytes INTEGER, free_bytes INTEGER, used_bytes INTEGER, total_inodes INTEGER, free_inodes INTEGER, read_only INTEGER NOT NULL, capability TEXT NOT NULL, PRIMARY KEY(timestamp,mount_id));
CREATE INDEX mount_samples_id_time ON mount_samples(mount_id,timestamp);
CREATE TABLE storage_scans (id INTEGER PRIMARY KEY, root TEXT NOT NULL, mount_id TEXT, started_at INTEGER NOT NULL, ended_at INTEGER NOT NULL, status TEXT NOT NULL, reason TEXT, entries_seen INTEGER NOT NULL, UNIQUE(root,started_at));
CREATE INDEX storage_scans_root_time ON storage_scans(root,started_at);
CREATE TABLE directory_samples (scan_id INTEGER NOT NULL REFERENCES storage_scans(id) ON DELETE CASCADE, path TEXT NOT NULL, allocated_bytes INTEGER NOT NULL, apparent_bytes INTEGER NOT NULL, entry_count INTEGER NOT NULL, file_count INTEGER NOT NULL, PRIMARY KEY(scan_id,path));
CREATE INDEX directory_samples_path ON directory_samples(path);
PRAGMA user_version=2; COMMIT;").map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct HostSample {
    pub timestamp: i64,
    pub boot_id: String,
    pub duration_ms: i64,
    pub mem_total: Option<i64>,
    pub mem_available: Option<i64>,
    pub mem_free: Option<i64>,
    pub buffers: Option<i64>,
    pub cached: Option<i64>,
    pub slab: Option<i64>,
    pub swap_total: Option<i64>,
    pub swap_free: Option<i64>,
    pub psi_some: Option<f64>,
    pub psi_full: Option<f64>,
}
#[derive(Debug, Clone)]
pub struct ProcessSample {
    pub pid: i64,
    pub start_ticks: i64,
    pub name: String,
    pub executable: Option<String>,
    pub uid: Option<i64>,
    pub cgroup_name: Option<String>,
    pub rss_anon: Option<i64>,
    pub rss_file: Option<i64>,
    pub rss_shmem: Option<i64>,
    pub rss_total: Option<i64>,
    pub cpu_ticks: Option<i64>,
    pub read_bytes: Option<i64>,
    pub write_bytes: Option<i64>,
}
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub host: HostSample,
    pub processes: Vec<ProcessSample>,
    pub gaps: Vec<String>,
}

pub fn insert_snapshot(conn: &mut Connection, snapshot: &Snapshot) -> Result<(), String> {
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    insert_snapshot_tx(&tx, snapshot)?;
    tx.commit().map_err(|e| e.to_string())
}
fn insert_snapshot_tx(tx: &Transaction<'_>, s: &Snapshot) -> Result<(), String> {
    let h = &s.host;
    tx.execute(
        "INSERT OR REPLACE INTO host_samples VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        params![
            h.timestamp,
            h.boot_id,
            h.duration_ms,
            "ok",
            h.mem_total,
            h.mem_available,
            h.mem_free,
            h.buffers,
            h.cached,
            h.slab,
            h.swap_total,
            h.swap_free,
            h.psi_some,
            h.psi_full
        ],
    )
    .map_err(|e| e.to_string())?;
    for p in &s.processes {
        tx.execute("INSERT INTO process_identities(boot_id,pid,start_ticks,name,executable,uid,cgroup_name) VALUES(?,?,?,?,?,?,?) ON CONFLICT(boot_id,pid,start_ticks) DO UPDATE SET name=excluded.name, executable=COALESCE(excluded.executable,process_identities.executable), uid=COALESCE(excluded.uid,process_identities.uid), cgroup_name=COALESCE(excluded.cgroup_name,process_identities.cgroup_name)", params![h.boot_id,p.pid,p.start_ticks,p.name,p.executable,p.uid,p.cgroup_name]).map_err(|e| e.to_string())?;
        let id: i64 = tx
            .query_row(
                "SELECT id FROM process_identities WHERE boot_id=? AND pid=? AND start_ticks=?",
                params![h.boot_id, p.pid, p.start_ticks],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT OR REPLACE INTO process_samples VALUES(?,?,?,?,?,?,?,?,?)",
            params![
                h.timestamp,
                id,
                p.rss_anon,
                p.rss_file,
                p.rss_shmem,
                p.rss_total,
                p.cpu_ticks,
                p.read_bytes,
                p.write_bytes
            ],
        )
        .map_err(|e| e.to_string())?;
    }
    for reason in &s.gaps {
        tx.execute(
            "INSERT OR IGNORE INTO collection_gaps(timestamp,reason,duration_ms) VALUES(?,?,?)",
            params![h.timestamp, reason, h.duration_ms],
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}
pub fn housekeeping(conn: &mut Connection, cutoff: i64, now: i64) -> Result<usize, String> {
    let next: i64 = conn
        .query_row(
            "SELECT value FROM metadata WHERE key='next_housekeeping'",
            [],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .map_err(|e| e.to_string())?
        .and_then(|x| x.parse().ok())
        .unwrap_or(0);
    if now < next {
        return Ok(0);
    }
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute_batch("CREATE TEMP TABLE IF NOT EXISTS expired_identity_ids(id INTEGER PRIMARY KEY); DELETE FROM expired_identity_ids;").map_err(|e|e.to_string())?;
    tx.execute("INSERT OR IGNORE INTO expired_identity_ids SELECT DISTINCT identity_id FROM process_samples WHERE timestamp < ? LIMIT 10000",[cutoff]).map_err(|e|e.to_string())?;
    let count=tx.execute("DELETE FROM host_samples WHERE timestamp IN (SELECT timestamp FROM host_samples WHERE timestamp < ? LIMIT 10000)", [cutoff])
        .map_err(|e| e.to_string())?;
    tx.execute("DELETE FROM process_identities WHERE id IN (SELECT id FROM expired_identity_ids) AND NOT EXISTS (SELECT 1 FROM process_samples WHERE process_samples.identity_id=process_identities.id)", []).map_err(|e|e.to_string())?;
    tx.execute("INSERT INTO metadata(key,value) VALUES('next_housekeeping',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[(now+3600).to_string()]).map_err(|e|e.to_string())?;
    tx.execute("DELETE FROM mount_samples WHERE rowid IN (SELECT rowid FROM mount_samples WHERE timestamp < ? LIMIT 10000)", [cutoff]).map_err(|e|e.to_string())?;
    tx.execute("DELETE FROM storage_scans WHERE id IN (SELECT id FROM storage_scans WHERE ended_at < ? LIMIT 1000)", [cutoff]).map_err(|e|e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;
    conn.execute_batch("PRAGMA incremental_vacuum(1000); PRAGMA wal_checkpoint(PASSIVE);")
        .map_err(|e| e.to_string())?;
    Ok(count)
}
pub fn cleanup(conn: &mut Connection, cutoff: i64) -> Result<usize, String> {
    housekeeping(conn, cutoff, i64::MAX / 2)
}

pub fn database_size(path: &Path) -> u64 {
    [
        path.to_path_buf(),
        path.with_extension("sqlite-wal"),
        path.with_extension("sqlite-shm"),
    ]
    .iter()
    .filter_map(|p| fs::metadata(p).ok())
    .map(|m| m.len())
    .sum()
}
pub fn budget_allows(path: &Path, budget: u64) -> bool {
    database_size(path).saturating_add(CONTROL_HEADROOM) <= budget
}
pub fn filesystem_has_reserve(path: &Path) -> bool {
    let parent = path.parent().unwrap_or(path);
    let c_path = match std::ffi::CString::new(parent.as_os_str().as_encoded_bytes()) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let mut info = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(c_path.as_ptr(), info.as_mut_ptr()) } != 0 {
        return false;
    }
    let info = unsafe { info.assume_init() };
    let available = info.f_bavail.saturating_mul(info.f_frsize);
    let total = info.f_blocks.saturating_mul(info.f_frsize);
    available >= GIB.max(total / 20)
}
pub fn recover_budget_after_cleanup(
    conn: &mut Connection,
    path: &Path,
    budget: u64,
    now: i64,
    deleted: usize,
) -> Result<bool, String> {
    if budget_allows(path, budget) {
        return Ok(true);
    }
    if deleted == 0 {
        return Ok(false);
    }
    let last: i64 = conn
        .query_row(
            "SELECT value FROM metadata WHERE key='last_budget_vacuum'",
            [],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .map_err(|e| e.to_string())?
        .and_then(|x| x.parse().ok())
        .unwrap_or(0);
    if last != 0 && now < last + 3600 {
        return Ok(false);
    }
    let parent = path.parent().unwrap_or(path);
    let c_path = std::ffi::CString::new(parent.as_os_str().as_encoded_bytes())
        .map_err(|_| "database path contains NUL")?;
    let mut info = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(c_path.as_ptr(), info.as_mut_ptr()) } != 0 {
        return Ok(false);
    }
    let info = unsafe { info.assume_init() };
    let available = info.f_bavail.saturating_mul(info.f_frsize);
    let required = database_size(path)
        .saturating_add(GIB.max(info.f_blocks.saturating_mul(info.f_frsize) / 20));
    if available < required {
        return Ok(false);
    }
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;")
        .map_err(|e| e.to_string())?;
    conn.execute("INSERT INTO metadata(key,value) VALUES('last_budget_vacuum',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[(now).to_string()]).map_err(|e|e.to_string())?;
    Ok(budget_allows(path, budget))
}

#[derive(Debug, Clone)]
pub struct MountSample {
    pub timestamp: i64,
    pub mount_id: String,
    pub mount_point: String,
    pub fs_type: String,
    pub total_bytes: Option<i64>,
    pub free_bytes: Option<i64>,
    pub used_bytes: Option<i64>,
    pub total_inodes: Option<i64>,
    pub free_inodes: Option<i64>,
    pub read_only: bool,
    pub capability: String,
}
pub trait FilesystemReader {
    fn mounts(&self) -> Result<Vec<MountInfo>, String>;
    fn stat(&self, path: &Path) -> Result<FsStat, String>;
}
#[derive(Debug, Clone)]
pub struct MountInfo {
    pub mount_point: PathBuf,
    pub fs_type: String,
    pub device: String,
    pub read_only: bool,
}
#[derive(Debug, Clone)]
pub struct FsStat {
    pub blocks: u64,
    pub blocks_free: u64,
    pub block_size: u64,
    pub files: u64,
    pub files_free: u64,
}
pub struct LinuxFilesystemReader;
impl FilesystemReader for LinuxFilesystemReader {
    fn mounts(&self) -> Result<Vec<MountInfo>, String> {
        read_mountinfo(Path::new("/proc/self/mountinfo"))
    }
    fn stat(&self, path: &Path) -> Result<FsStat, String> {
        stat_filesystem(path)
    }
}
fn unescape_mount(s: &str) -> PathBuf {
    PathBuf::from(
        s.replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\134", "\\"),
    )
}
pub fn read_mountinfo(path: &Path) -> Result<Vec<MountInfo>, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("mountinfo unavailable: {e}"))?;
    let mut out = Vec::new();
    for line in text.lines() {
        let Some((before, after)) = line.split_once(" - ") else {
            continue;
        };
        let left: Vec<_> = before.split_whitespace().collect();
        let right: Vec<_> = after.split_whitespace().collect();
        if left.len() < 6 || right.len() < 2 {
            continue;
        }
        let opts = left[5].split(',').any(|x| x == "ro");
        out.push(MountInfo {
            mount_point: unescape_mount(left[4]),
            fs_type: right[0].into(),
            device: right[1].into(),
            read_only: opts,
        });
    }
    Ok(out)
}
fn stat_filesystem(path: &Path) -> Result<FsStat, String> {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| "mount path has NUL")?;
    let mut s = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(c.as_ptr(), s.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().to_string());
    };
    let s = unsafe { s.assume_init() };
    Ok(FsStat {
        blocks: s.f_blocks,
        blocks_free: s.f_bavail,
        block_size: s.f_frsize,
        files: s.f_files,
        files_free: s.f_ffree,
    })
}
fn excluded_filesystem(t: &str) -> bool {
    matches!(
        t,
        "proc"
            | "sysfs"
            | "tmpfs"
            | "devtmpfs"
            | "devpts"
            | "cgroup"
            | "cgroup2"
            | "overlay"
            | "squashfs"
            | "nsfs"
            | "mqueue"
            | "securityfs"
            | "tracefs"
            | "debugfs"
            | "pstore"
            | "fusectl"
            | "autofs"
            | "configfs"
            | "ramfs"
    ) || t.starts_with("nfs")
        || t == "cifs"
        || t == "sshfs"
}
pub fn collect_mounts(
    reader: &dyn FilesystemReader,
    timestamp: i64,
) -> (Vec<MountSample>, Vec<String>) {
    let mounts = match reader.mounts() {
        Ok(v) => v,
        Err(e) => return (vec![], vec![e]),
    };
    let mut seen = HashSet::new();
    let mut out = vec![];
    let mut gaps = vec![];
    for m in mounts {
        let id = format!("{}|{}|{}", m.device, m.fs_type, m.mount_point.display());
        if !seen.insert(id.clone()) {
            continue;
        };
        if excluded_filesystem(&m.fs_type) {
            out.push(MountSample {
                timestamp,
                mount_id: id,
                mount_point: m.mount_point.display().to_string(),
                fs_type: m.fs_type,
                total_bytes: None,
                free_bytes: None,
                used_bytes: None,
                total_inodes: None,
                free_inodes: None,
                read_only: m.read_only,
                capability: "excluded filesystem type".into(),
            });
            continue;
        }
        match reader.stat(&m.mount_point) {
            Ok(s) => {
                let total = s.blocks.saturating_mul(s.block_size) as i64;
                let free = s.blocks_free.saturating_mul(s.block_size) as i64;
                out.push(MountSample {
                    timestamp,
                    mount_id: id,
                    mount_point: m.mount_point.display().to_string(),
                    fs_type: m.fs_type,
                    total_bytes: Some(total),
                    free_bytes: Some(free),
                    used_bytes: Some(total.saturating_sub(free)),
                    total_inodes: Some(s.files as i64),
                    free_inodes: Some(s.files_free as i64),
                    read_only: m.read_only,
                    capability: if m.read_only {
                        "read-only".into()
                    } else {
                        "available".into()
                    },
                })
            }
            Err(e) => {
                gaps.push(format!(
                    "mount {} unavailable: {e}",
                    m.mount_point.display()
                ));
                out.push(MountSample {
                    timestamp,
                    mount_id: id,
                    mount_point: m.mount_point.display().to_string(),
                    fs_type: m.fs_type,
                    total_bytes: None,
                    free_bytes: None,
                    used_bytes: None,
                    total_inodes: None,
                    free_inodes: None,
                    read_only: m.read_only,
                    capability: "unavailable".into(),
                })
            }
        }
    }
    (out, gaps)
}
pub fn insert_mounts(conn: &mut Connection, samples: &[MountSample]) -> Result<(), String> {
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    for s in samples {
        tx.execute(
            "INSERT OR REPLACE INTO mount_samples VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            params![
                s.timestamp,
                s.mount_id,
                s.mount_point,
                s.fs_type,
                s.total_bytes,
                s.free_bytes,
                s.used_bytes,
                s.total_inodes,
                s.free_inodes,
                s.read_only as i64,
                s.capability
            ],
        )
        .map_err(|e| e.to_string())?;
    }
    tx.commit().map_err(|e| e.to_string())
}
pub fn insert_collection_gaps(
    conn: &mut Connection,
    timestamp: i64,
    reasons: &[String],
) -> Result<(), String> {
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    for reason in reasons {
        tx.execute(
            "INSERT OR IGNORE INTO collection_gaps(timestamp,reason,duration_ms) VALUES(?,?,NULL)",
            params![timestamp, reason],
        )
        .map_err(|e| e.to_string())?;
    }
    tx.commit().map_err(|e| e.to_string())
}

#[derive(Debug, Clone)]
pub struct DirectorySample {
    pub path: String,
    pub allocated_bytes: i64,
    pub apparent_bytes: i64,
    pub entry_count: i64,
    pub file_count: i64,
}
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub root: String,
    pub mount_id: Option<String>,
    pub started_at: i64,
    pub ended_at: i64,
    pub status: String,
    pub reason: Option<String>,
    pub entries_seen: i64,
    pub directories: Vec<DirectorySample>,
}
pub fn scan_directory(
    root: &Path,
    mount_id: Option<String>,
    cfg: &StorageConfig,
    now: i64,
) -> ScanResult {
    let start = std::time::Instant::now();
    let root_s = root.display().to_string();
    let root_meta = match fs::symlink_metadata(root) {
        Ok(x) => x,
        Err(e) => {
            return ScanResult {
                root: root_s,
                mount_id,
                started_at: now,
                ended_at: now,
                status: "partial".into(),
                reason: Some(format!("root unavailable: {e}")),
                entries_seen: 0,
                directories: vec![],
            };
        }
    };
    let root_dev = std::os::unix::fs::MetadataExt::dev(&root_meta);
    let mut directories = BTreeMap::<PathBuf, DirectorySample>::new();
    directories.insert(
        root.to_path_buf(),
        DirectorySample {
            path: root_s.clone(),
            allocated_bytes: 0,
            apparent_bytes: 0,
            entry_count: 0,
            file_count: 0,
        },
    );
    let mut seen = HashSet::new();
    let mut entries = 0u64;
    let mut reason = None;
    #[allow(clippy::too_many_arguments)]
    fn walk(
        dir: &Path,
        dev: u64,
        depth: u8,
        cfg: &StorageConfig,
        start: &std::time::Instant,
        seen: &mut HashSet<(u64, u64)>,
        entries: &mut u64,
        dirs: &mut BTreeMap<PathBuf, DirectorySample>,
        reason: &mut Option<String>,
    ) {
        if reason.is_some() {
            return;
        }
        if start.elapsed().as_secs() >= cfg.max_duration_seconds {
            *reason = Some("scan duration limit reached".into());
            return;
        }
        let rd = match fs::read_dir(dir) {
            Ok(x) => x,
            Err(e) => {
                *reason = Some(format!("cannot read {}: {e}", dir.display()));
                return;
            }
        };
        for ent in rd {
            if reason.is_some() {
                break;
            }
            if *entries >= cfg.max_entries {
                *reason = Some("scan entry limit reached".into());
                break;
            }
            if start.elapsed().as_secs() >= cfg.max_duration_seconds {
                *reason = Some("scan duration limit reached".into());
                break;
            };
            let ent = match ent {
                Ok(x) => x,
                Err(e) => {
                    *reason = Some(format!("directory entry unavailable: {e}"));
                    break;
                }
            };
            *entries += 1;
            let path = ent.path();
            let m = match fs::symlink_metadata(&path) {
                Ok(x) => x,
                Err(e) => {
                    *reason = Some(format!("cannot stat {}: {e}", path.display()));
                    break;
                }
            };
            if m.file_type().is_symlink() {
                continue;
            };
            if std::os::unix::fs::MetadataExt::dev(&m) != dev {
                continue;
            };
            let is_dir = m.is_dir();
            let key = (
                std::os::unix::fs::MetadataExt::dev(&m),
                std::os::unix::fs::MetadataExt::ino(&m),
            );
            let unique = seen.insert(key);
            let allocated = if unique {
                (std::os::unix::fs::MetadataExt::blocks(&m) as i64) * 512
            } else {
                0
            };
            let apparent = if unique {
                std::os::unix::fs::MetadataExt::size(&m) as i64
            } else {
                0
            };
            let ancestors: Vec<PathBuf> = dirs
                .keys()
                .filter(|p| path.starts_with(p))
                .cloned()
                .collect();
            for a in ancestors {
                let d = dirs.get_mut(&a).unwrap();
                d.allocated_bytes += allocated;
                d.apparent_bytes += apparent;
                d.entry_count += 1;
                if !is_dir {
                    d.file_count += 1
                }
            }
            if is_dir && depth < cfg.max_depth {
                dirs.entry(path.clone()).or_insert(DirectorySample {
                    path: path.display().to_string(),
                    allocated_bytes: 0,
                    apparent_bytes: 0,
                    entry_count: 0,
                    file_count: 0,
                });
                walk(
                    &path,
                    dev,
                    depth + 1,
                    cfg,
                    start,
                    seen,
                    entries,
                    dirs,
                    reason,
                )
            }
        }
    }
    walk(
        root,
        root_dev,
        0,
        cfg,
        &start,
        &mut seen,
        &mut entries,
        &mut directories,
        &mut reason,
    );
    let ended = now + start.elapsed().as_secs() as i64;
    ScanResult {
        root: root_s,
        mount_id,
        started_at: now,
        ended_at: ended,
        status: if reason.is_some() {
            "partial".into()
        } else {
            "complete".into()
        },
        reason,
        entries_seen: entries as i64,
        directories: directories.into_values().collect(),
    }
}
pub fn insert_scan(conn: &mut Connection, s: &ScanResult) -> Result<(), String> {
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute("INSERT INTO storage_scans(root,mount_id,started_at,ended_at,status,reason,entries_seen) VALUES(?,?,?,?,?,?,?)",params![s.root,s.mount_id,s.started_at,s.ended_at,s.status,s.reason,s.entries_seen]).map_err(|e|e.to_string())?;
    let id = tx.last_insert_rowid();
    for d in &s.directories {
        tx.execute(
            "INSERT INTO directory_samples VALUES(?,?,?,?,?,?)",
            params![
                id,
                d.path,
                d.allocated_bytes,
                d.apparent_bytes,
                d.entry_count,
                d.file_count
            ],
        )
        .map_err(|e| e.to_string())?;
    }
    tx.commit().map_err(|e| e.to_string())
}

pub struct Collector {
    proc_root: PathBuf,
}
impl Collector {
    pub fn new(proc_root: PathBuf) -> Self {
        Self { proc_root }
    }
    pub fn collect(&self, now: i64) -> Snapshot {
        let started = std::time::Instant::now();
        let mut gaps = Vec::new();
        let boot_id =
            read_trim(&self.proc_root.join("sys/kernel/random/boot_id")).unwrap_or_else(|_| {
                gaps.push("boot_id unavailable".into());
                "unknown".into()
            });
        let mem = parse_meminfo(&self.proc_root.join("meminfo"), &mut gaps);
        let (some, full) = parse_psi(&self.proc_root.join("pressure/memory"), &mut gaps);
        let mut processes = Vec::new();
        let mut status_unreadable = 0_u64;
        let mut io_unreadable = 0_u64;
        let mut process_unreadable = 0_u64;
        match fs::read_dir(&self.proc_root) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    if let Ok(pid) = entry.file_name().to_string_lossy().parse::<i64>() {
                        let base = self.proc_root.join(pid.to_string());
                        if fs::read_to_string(base.join("status")).is_err() {
                            status_unreadable += 1;
                        }
                        if fs::read_to_string(base.join("io")).is_err() {
                            io_unreadable += 1;
                        }
                        match self.process(pid) {
                            Ok(p) => processes.push(p),
                            Err(_) => process_unreadable += 1,
                        }
                    }
                }
            }
            Err(e) => gaps.push(format!("cannot enumerate proc: {e}")),
        }
        if status_unreadable > 0 {
            gaps.push(format!(
                "process status unreadable for {status_unreadable} visible processes"
            ));
        }
        if io_unreadable > 0 {
            gaps.push(format!(
                "process io unreadable for {io_unreadable} visible processes"
            ));
        }
        if process_unreadable > 0 {
            gaps.push(format!(
                "process stat unreadable for {process_unreadable} visible processes"
            ));
        }
        Snapshot {
            host: HostSample {
                timestamp: now,
                boot_id,
                duration_ms: started.elapsed().as_millis() as i64,
                mem_total: mem.get("MemTotal").copied(),
                mem_available: mem.get("MemAvailable").copied(),
                mem_free: mem.get("MemFree").copied(),
                buffers: mem.get("Buffers").copied(),
                cached: mem.get("Cached").copied(),
                slab: mem.get("Slab").copied(),
                swap_total: mem.get("SwapTotal").copied(),
                swap_free: mem.get("SwapFree").copied(),
                psi_some: some,
                psi_full: full,
            },
            processes,
            gaps,
        }
    }
    fn process(&self, pid: i64) -> Result<ProcessSample, String> {
        let base = self.proc_root.join(pid.to_string());
        let stat = fs::read_to_string(base.join("stat")).map_err(|e| e.to_string())?;
        let end = stat.rfind(')').ok_or("invalid stat")?;
        let fields: Vec<&str> = stat[end + 2..].split_whitespace().collect();
        if fields.len() < 20 {
            return Err("short stat".into());
        }
        let name = stat[stat.find('(').ok_or("invalid stat")? + 1..end].to_string();
        let start_ticks = fields[19].parse().map_err(|_| "invalid start_ticks")?;
        let cpu_ticks = fields[11]
            .parse::<i64>()
            .ok()
            .zip(fields[12].parse::<i64>().ok())
            .map(|(a, b)| a + b);
        let status = parse_status(&base.join("status"));
        let io = parse_key_values(&base.join("io"));
        let executable = fs::read_link(base.join("exe"))
            .ok()
            .map(|p| p.display().to_string());
        let uid = status
            .get("Uid")
            .and_then(|s| s.split_whitespace().next())
            .and_then(|x| x.parse().ok());
        let cgroup = fs::read_to_string(base.join("cgroup"))
            .ok()
            .and_then(|x| x.lines().next().map(str::to_owned));
        Ok(ProcessSample {
            pid,
            start_ticks,
            name,
            executable,
            uid,
            cgroup_name: cgroup,
            rss_anon: status.get("RssAnon").and_then(|value| kb(value)),
            rss_file: status.get("RssFile").and_then(|value| kb(value)),
            rss_shmem: status.get("RssShmem").and_then(|value| kb(value)),
            rss_total: status.get("VmRSS").and_then(|value| kb(value)),
            cpu_ticks,
            read_bytes: io.get("read_bytes").and_then(|x| x.parse().ok()),
            write_bytes: io.get("write_bytes").and_then(|x| x.parse().ok()),
        })
    }
}
fn read_trim(p: &Path) -> io::Result<String> {
    fs::read_to_string(p).map(|x| x.trim().to_owned())
}
fn parse_key_values(p: &Path) -> BTreeMap<String, String> {
    fs::read_to_string(p)
        .ok()
        .map(|s| {
            s.lines()
                .filter_map(|l| {
                    l.split_once(':')
                        .map(|(a, b)| (a.trim().to_string(), b.trim().to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}
fn parse_status(p: &Path) -> BTreeMap<String, String> {
    parse_key_values(p)
}
fn kb(s: &str) -> Option<i64> {
    s.split_whitespace()
        .next()?
        .parse::<i64>()
        .ok()
        .map(|x| x * 1024)
}
fn parse_meminfo(p: &Path, gaps: &mut Vec<String>) -> BTreeMap<String, i64> {
    let raw = fs::read_to_string(p);
    let Ok(raw) = raw else {
        gaps.push("meminfo unavailable".into());
        return BTreeMap::new();
    };
    raw.lines()
        .filter_map(|l| {
            let (a, b) = l.split_once(':')?;
            Some((a.to_owned(), kb(b.trim())?))
        })
        .collect()
}
fn parse_psi(p: &Path, gaps: &mut Vec<String>) -> (Option<f64>, Option<f64>) {
    match fs::read_to_string(p) {
        Ok(s) => {
            let val = |k: &str| {
                s.lines().find(|x| x.starts_with(k)).and_then(|x| {
                    x.split_whitespace()
                        .find(|x| x.starts_with("avg10="))
                        .and_then(|x| x[6..].parse().ok())
                })
            };
            (val("some"), val("full"))
        }
        Err(_) => {
            gaps.push("memory PSI unavailable".into());
            (None, None)
        }
    }
}

#[derive(Serialize)]
pub struct Diagnosis {
    pub version: u32,
    pub status: String,
    pub current: Interval,
    pub comparison: Interval,
    pub coverage: Coverage,
    pub findings: Vec<String>,
    pub processes: Vec<ProcessFinding>,
    pub limitations: Vec<String>,
}
#[derive(Serialize)]
pub struct Interval {
    pub start_utc: String,
    pub end_utc: String,
    pub mean_mem_total_bytes: Option<f64>,
    pub mean_mem_available_bytes: Option<f64>,
}
#[derive(Serialize)]
pub struct Coverage {
    pub current_samples: i64,
    pub comparison_samples: i64,
    pub expected_samples: i64,
    pub current_ratio: f64,
    pub comparison_ratio: f64,
    pub current_gaps: i64,
    pub comparison_gaps: i64,
}
#[derive(Serialize)]
pub struct ProcessFinding {
    pub name: String,
    pub executable: Option<String>,
    pub rss_anon_change_bytes: i64,
    pub first_seen_utc: String,
    pub last_seen_utc: String,
}
type MemoryAverages = (Option<f64>, Option<f64>, Option<f64>);
pub fn diagnose_memory(path: &Path, since: &str, compare: &str) -> Result<Diagnosis, String> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| format!("cannot open evidence database: {e}"))?;
    let now = Utc::now();
    let (start, end) = parse_interval(since, now)?;
    let duration = end - start;
    if compare != "previous-week" {
        return Err("only --compare previous-week is supported".into());
    };
    let cstart = start - Duration::days(7);
    let cend = end - Duration::days(7);
    let count = |a: DateTime<Utc>, b: DateTime<Utc>| -> Result<i64, String> {
        conn.query_row(
            "SELECT count(*) FROM host_samples WHERE timestamp>=? AND timestamp<=? AND mem_total IS NOT NULL AND mem_available IS NOT NULL",
            params![a.timestamp(), b.timestamp()],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())
    };
    let n = count(start, end)?;
    let cn = count(cstart, cend)?;
    let interval_seconds: i64 = conn
        .query_row(
            "SELECT value FROM metadata WHERE key='interval_seconds'",
            [],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .map_err(|e| e.to_string())?
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    let expected = ((duration.num_seconds() + interval_seconds - 1) / interval_seconds).max(1);
    let gaps = |a: DateTime<Utc>, b: DateTime<Utc>| -> Result<i64, String> {
        conn.query_row(
            "SELECT count(*) FROM collection_gaps WHERE timestamp>=? AND timestamp<=?",
            params![a.timestamp(), b.timestamp()],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())
    };
    let current_gaps = gaps(start, end)?;
    let comparison_gaps = gaps(cstart, cend)?;
    let memory_gaps = |a: DateTime<Utc>, b: DateTime<Utc>| -> Result<i64, String> {
        conn.query_row("SELECT count(*) FROM collection_gaps WHERE timestamp>=? AND timestamp<=? AND reason LIKE 'meminfo%'", params![a.timestamp(),b.timestamp()], |r|r.get(0)).map_err(|e|e.to_string())
    };
    let current_memory_gaps = memory_gaps(start, end)?;
    let comparison_memory_gaps = memory_gaps(cstart, cend)?;
    let coverage = Coverage {
        current_samples: n,
        comparison_samples: cn,
        expected_samples: expected,
        current_ratio: n as f64 / expected as f64,
        comparison_ratio: cn as f64 / expected as f64,
        current_gaps,
        comparison_gaps,
    };
    let fmt = |x: DateTime<Utc>| x.to_rfc3339();
    let mut findings = Vec::new();
    let mut limitations=vec!["RssAnon is anonymous resident memory, not private/USS; process RSS cannot exactly reconcile physical RAM.".into()];
    if coverage.current_ratio < 0.8
        || coverage.comparison_ratio < 0.8
        || current_memory_gaps > 0
        || comparison_memory_gaps > 0
    {
        limitations.push("At least 80% valid RAM coverage is required in each interval; stored evidence is incomplete.".into());
        if current_memory_gaps > 0 || comparison_memory_gaps > 0 {
            limitations.push("meminfo collection gaps make the RAM evidence incomplete.".into());
        }
        return Ok(Diagnosis {
            version: 1,
            status: "insufficient evidence".into(),
            current: Interval {
                start_utc: fmt(start),
                end_utc: fmt(end),
                mean_mem_total_bytes: None,
                mean_mem_available_bytes: None,
            },
            comparison: Interval {
                start_utc: fmt(cstart),
                end_utc: fmt(cend),
                mean_mem_total_bytes: None,
                mean_mem_available_bytes: None,
            },
            coverage,
            findings,
            processes: vec![],
            limitations,
        });
    }
    let avg = |a: DateTime<Utc>, b: DateTime<Utc>| -> Result<MemoryAverages, String> {
        conn.query_row("SELECT avg(mem_total),avg(mem_available),avg(cached+buffers+slab) FROM host_samples WHERE timestamp>=? AND timestamp<=?",params![a.timestamp(),b.timestamp()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(|e|e.to_string())
    };
    let (total, avail, cache) = avg(start, end)?;
    let (ctotal, cavail, ccache) = avg(cstart, cend)?;
    if let (Some(t), Some(a), Some(ct), Some(ca)) = (total, avail, ctotal, cavail) {
        let cur = (t - a) / t * 100.;
        let old = (ct - ca) / ct * 100.;
        findings.push(format!("Average used RAM was {:.1}% versus {:.1}% in the comparison interval ({:+.1} percentage points).",cur,old,cur-old));
    }
    if let (Some(x), Some(y)) = (cache, ccache) {
        findings.push(format!(
            "Cache, buffers, and slab changed by {:+} MiB.",
            ((x - y) / 1048576.) as i64
        ));
    }
    let mut stmt=conn.prepare("WITH current AS (SELECT ps.identity_id, min(ps.timestamp) first_seen,max(ps.timestamp) last_seen, max(ps.rss_anon) max_rss FROM process_samples ps WHERE ps.timestamp>=?1 AND ps.timestamp<=?2 GROUP BY ps.identity_id), previous AS (SELECT ps.identity_id,max(ps.rss_anon) max_rss FROM process_samples ps WHERE ps.timestamp>=?3 AND ps.timestamp<=?4 GROUP BY ps.identity_id) SELECT pi.name,pi.executable,current.max_rss-COALESCE(previous.max_rss,0),current.first_seen,current.last_seen FROM current JOIN process_identities pi ON pi.id=current.identity_id LEFT JOIN previous ON previous.identity_id=current.identity_id WHERE current.max_rss IS NOT NULL ORDER BY 3 DESC LIMIT 10").map_err(|e|e.to_string())?;
    let mut rows = stmt
        .query(params![
            start.timestamp(),
            end.timestamp(),
            cstart.timestamp(),
            cend.timestamp()
        ])
        .map_err(|e| e.to_string())?;
    let mut processes = vec![];
    while let Some(r) = rows.next().map_err(|e| e.to_string())? {
        let d: i64 = r.get(2).map_err(|e| e.to_string())?;
        if d <= 0 {
            continue;
        }
        let first: i64 = r.get(3).map_err(|e| e.to_string())?;
        let last: i64 = r.get(4).map_err(|e| e.to_string())?;
        processes.push(ProcessFinding {
            name: r.get(0).map_err(|e| e.to_string())?,
            executable: r.get(1).map_err(|e| e.to_string())?,
            rss_anon_change_bytes: d,
            first_seen_utc: Utc
                .timestamp_opt(first, 0)
                .single()
                .ok_or("invalid process timestamp")?
                .to_rfc3339(),
            last_seen_utc: Utc
                .timestamp_opt(last, 0)
                .single()
                .ok_or("invalid process timestamp")?
                .to_rfc3339(),
        });
    }
    if processes.is_empty() {
        findings.push("No process showed a positive observed anonymous-memory increase across the retained samples.".into())
    } else {
        findings.push(format!(
            "Top observed anonymous-memory growth: {} ({:+} MiB).",
            processes[0].name,
            processes[0].rss_anon_change_bytes / 1048576
        ));
    }
    Ok(Diagnosis {
        version: 1,
        status: "ok".into(),
        current: Interval {
            start_utc: fmt(start),
            end_utc: fmt(end),
            mean_mem_total_bytes: total,
            mean_mem_available_bytes: avail,
        },
        comparison: Interval {
            start_utc: fmt(cstart),
            end_utc: fmt(cend),
            mean_mem_total_bytes: ctotal,
            mean_mem_available_bytes: cavail,
        },
        coverage,
        findings,
        processes,
        limitations,
    })
}
#[derive(Serialize)]
pub struct StorageDiagnosis {
    pub version: u32,
    pub status: String,
    pub current: StorageInterval,
    pub comparison: StorageInterval,
    pub mounts: Vec<MountFinding>,
    pub directories: Vec<DirectoryFinding>,
    pub limitations: Vec<String>,
}
#[derive(Serialize)]
pub struct StorageInterval {
    pub start_utc: String,
    pub end_utc: String,
}
#[derive(Serialize)]
pub struct MountFinding {
    pub mount_point: String,
    pub fs_type: String,
    pub used_bytes_change: i64,
    pub current_used_bytes: i64,
    pub comparison_used_bytes: i64,
}
#[derive(Serialize)]
pub struct DirectoryFinding {
    pub path: String,
    pub allocated_bytes_change: i64,
    pub apparent_bytes_change: i64,
}
pub fn diagnose_storage(
    path: &Path,
    since: &str,
    compare: &str,
) -> Result<StorageDiagnosis, String> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| format!("cannot open evidence database: {e}"))?;
    let now = Utc::now();
    let (start, end) = parse_interval(since, now)?;
    if compare != "previous-week" {
        return Err("only --compare previous-week is supported".into());
    };
    let (cs, ce) = (start - Duration::days(7), end - Duration::days(7));
    let fmt = |x: DateTime<Utc>| x.to_rfc3339();
    let mut limits=vec!["Directory evidence is unprivileged and local. It does not attribute storage use to a process.".into()];
    let mut stmt=conn.prepare("SELECT a.mount_point,a.fs_type,a.used_bytes,b.used_bytes FROM mount_samples a JOIN mount_samples b ON a.mount_id=b.mount_id WHERE a.timestamp=(SELECT max(timestamp) FROM mount_samples x WHERE x.mount_id=a.mount_id AND x.timestamp>=?1 AND x.timestamp<=?2 AND x.used_bytes IS NOT NULL) AND b.timestamp=(SELECT max(timestamp) FROM mount_samples y WHERE y.mount_id=b.mount_id AND y.timestamp>=?3 AND y.timestamp<=?4 AND y.used_bytes IS NOT NULL)").map_err(|e|e.to_string())?;
    let rows = stmt
        .query_map(
            params![
                start.timestamp(),
                end.timestamp(),
                cs.timestamp(),
                ce.timestamp()
            ],
            |r| {
                Ok(MountFinding {
                    mount_point: r.get(0)?,
                    fs_type: r.get(1)?,
                    current_used_bytes: r.get(2)?,
                    comparison_used_bytes: r.get(3)?,
                    used_bytes_change: r.get::<_, i64>(2)? - r.get::<_, i64>(3)?,
                })
            },
        )
        .map_err(|e| e.to_string())?;
    let mounts: Vec<_> = rows.filter_map(Result::ok).collect();
    if mounts.is_empty() {
        limits
            .push("No comparable available mount-capacity samples exist in both intervals.".into());
        return Ok(StorageDiagnosis {
            version: 1,
            status: "insufficient evidence".into(),
            current: StorageInterval {
                start_utc: fmt(start),
                end_utc: fmt(end),
            },
            comparison: StorageInterval {
                start_utc: fmt(cs),
                end_utc: fmt(ce),
            },
            mounts: vec![],
            directories: vec![],
            limitations: limits,
        });
    }
    let mut dstmt=conn.prepare("SELECT dc.path,dc.allocated_bytes-dp.allocated_bytes,dc.apparent_bytes-dp.apparent_bytes FROM storage_scans sc JOIN directory_samples dc ON dc.scan_id=sc.id JOIN storage_scans sp ON sp.root=sc.root JOIN directory_samples dp ON dp.scan_id=sp.id AND dp.path=dc.path WHERE sc.status='complete' AND sp.status='complete' AND sc.started_at=(SELECT max(x.started_at) FROM storage_scans x WHERE x.root=sc.root AND x.status='complete' AND x.started_at>=?1 AND x.started_at<=?2) AND sp.started_at=(SELECT max(y.started_at) FROM storage_scans y WHERE y.root=sp.root AND y.status='complete' AND y.started_at>=?3 AND y.started_at<=?4) ORDER BY 2 DESC LIMIT 20").map_err(|e|e.to_string())?;
    let r = dstmt
        .query_map(
            params![
                start.timestamp(),
                end.timestamp(),
                cs.timestamp(),
                ce.timestamp()
            ],
            |x| {
                Ok(DirectoryFinding {
                    path: x.get(0)?,
                    allocated_bytes_change: x.get(1)?,
                    apparent_bytes_change: x.get(2)?,
                })
            },
        )
        .map_err(|e| e.to_string())?;
    let directories: Vec<_> = r
        .filter_map(Result::ok)
        .filter(|x| x.allocated_bytes_change > 0)
        .collect();
    if directories.is_empty() {
        limits.push("No pair of complete, comparable directory scans was retained; mount growth cannot yet be attributed to a path.".into())
    };
    let status = if directories.is_empty() {
        "insufficient evidence"
    } else {
        "ok"
    };
    Ok(StorageDiagnosis {
        version: 1,
        status: status.into(),
        current: StorageInterval {
            start_utc: fmt(start),
            end_utc: fmt(end),
        },
        comparison: StorageInterval {
            start_utc: fmt(cs),
            end_utc: fmt(ce),
        },
        mounts,
        directories,
        limitations: limits,
    })
}
pub fn render_storage_diagnosis(d: &StorageDiagnosis) -> String {
    let mut s = format!(
        "Storage diagnosis: {}\nCurrent: {} to {}\nComparison: {} to {}\n",
        d.status,
        d.current.start_utc,
        d.current.end_utc,
        d.comparison.start_utc,
        d.comparison.end_utc
    );
    for m in &d.mounts {
        s.push_str(&format!(
            "- Mount {} ({}): {:+} MiB used\n",
            m.mount_point,
            m.fs_type,
            m.used_bytes_change / 1048576
        ));
    }
    for x in &d.directories {
        s.push_str(&format!(
            "- Directory {}: {:+} MiB allocated\n",
            x.path,
            x.allocated_bytes_change / 1048576
        ));
    }
    for x in &d.limitations {
        s.push_str(&format!("Limitation: {x}\n"));
    }
    s
}
fn parse_interval(
    input: &str,
    now: DateTime<Utc>,
) -> Result<(DateTime<Utc>, DateTime<Utc>), String> {
    if input == "today" {
        let local = now.with_timezone(&Local);
        let start = Local
            .with_ymd_and_hms(local.year(), local.month(), local.day(), 0, 0, 0)
            .single()
            .ok_or("cannot resolve local midnight")?
            .with_timezone(&Utc);
        return Ok((start, now));
    }
    let n = input
        .strip_suffix('h')
        .and_then(|x| x.parse::<i64>().ok())
        .or_else(|| {
            input
                .strip_suffix('d')
                .and_then(|x| x.parse::<i64>().ok().map(|x| x * 24))
        })
        .ok_or("--since must be today, <hours>h, or <days>d")?;
    if n <= 0 {
        return Err("--since duration must be positive".into());
    }
    Ok((now - Duration::hours(n), now))
}
pub fn render_diagnosis(d: &Diagnosis) -> String {
    let mut s = format!(
        "Memory diagnosis: {}\nCurrent: {} to {}\nComparison: {} to {}\nCoverage: {} current samples, {} comparison samples\n",
        d.status,
        d.current.start_utc,
        d.current.end_utc,
        d.comparison.start_utc,
        d.comparison.end_utc,
        d.coverage.current_samples,
        d.coverage.comparison_samples
    );
    for f in &d.findings {
        s.push_str(&format!("- {f}\n"));
    }
    for p in &d.processes {
        s.push_str(&format!(
            "- Process {}: {:+} MiB RssAnon ({} to {})\n",
            p.name,
            p.rss_anon_change_bytes / 1048576,
            p.first_seen_utc,
            p.last_seen_utc
        ));
    }
    for l in &d.limitations {
        s.push_str(&format!("Limitation: {l}\n"));
    }
    s
}
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    #[test]
    fn config_defaults_validate() {
        Config::default().validate().unwrap();
        assert!(
            Config {
                interval_seconds: 4,
                ..Config::default()
            }
            .validate()
            .is_err()
        )
    }
    #[test]
    fn config_rejects_unknown_fields_and_boundaries() {
        let d = tempdir().unwrap();
        let path = d.path().join("config.toml");
        fs::write(&path, "interval_seconds = 4\n").unwrap();
        assert!(load_config(&path).is_err());
        fs::write(&path, "unknown = 1\n").unwrap();
        assert!(load_config(&path).is_err());
        fs::write(&path, "[storage]\nunknown = 1\n").unwrap();
        assert!(load_config(&path).is_err());
        fs::write(&path, "[storage]\nmax_depth = 9\n").unwrap();
        assert!(load_config(&path).is_err());
        fs::write(
            &path,
            "interval_seconds = 5\nretention_days = 185\ndatabase_budget_bytes = 1073741824\n",
        )
        .unwrap();
        assert!(load_config(&path).is_ok());
    }
    #[test]
    fn schema_and_pid_reuse() {
        let d = tempdir().unwrap();
        let mut c = open_db(&d.path().join("x.sqlite")).unwrap();
        let mut a = Snapshot {
            host: HostSample {
                timestamp: 1,
                boot_id: "b".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        a.processes.push(ProcessSample {
            pid: 1,
            start_ticks: 1,
            name: "a".into(),
            executable: None,
            uid: None,
            cgroup_name: None,
            rss_anon: Some(1),
            rss_file: None,
            rss_shmem: None,
            rss_total: None,
            cpu_ticks: None,
            read_bytes: None,
            write_bytes: None,
        });
        insert_snapshot(&mut c, &a).unwrap();
        a.host.timestamp = 2;
        a.processes[0].start_ticks = 2;
        insert_snapshot(&mut c, &a).unwrap();
        assert_eq!(
            c.query_row("select count(*) from process_identities", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            2
        )
    }

    #[test]
    fn memory_diagnosis_reports_observed_growth() {
        let d = tempdir().unwrap();
        let path = d.path().join("x.sqlite");
        let mut c = open_db(&path).unwrap();
        c.execute(
            "INSERT INTO metadata(key,value) VALUES('interval_seconds','300')",
            [],
        )
        .unwrap();
        let now = unix_now();
        for i in 0..12 {
            for (timestamp, rss) in [
                (now - 7 * 86_400 - 3600 + i * 300 + 60, 11 * 1024 * 1024),
                (now - i * 300 - 60, 13 * 1024 * 1024),
            ] {
                let snapshot = Snapshot {
                    host: HostSample {
                        timestamp,
                        boot_id: "b".into(),
                        mem_total: Some(
                            (if rss > 12 * 1024 * 1024 { 100 } else { 200 }) * 1024 * 1024,
                        ),
                        mem_available: Some(
                            (if rss > 12 * 1024 * 1024 { 87 } else { 178 }) * 1024 * 1024,
                        ),
                        ..Default::default()
                    },
                    processes: vec![ProcessSample {
                        pid: 7,
                        start_ticks: 4,
                        name: "growing".into(),
                        executable: Some("/usr/bin/growing".into()),
                        uid: Some(1000),
                        cgroup_name: None,
                        rss_anon: Some(rss),
                        rss_file: None,
                        rss_shmem: None,
                        rss_total: Some(rss),
                        cpu_ticks: None,
                        read_bytes: None,
                        write_bytes: None,
                    }],
                    gaps: vec![],
                };
                insert_snapshot(&mut c, &snapshot).unwrap();
            }
        }
        let result = diagnose_memory(&path, "1h", "previous-week").unwrap();
        assert_eq!(result.status, "ok");
        assert_eq!(result.processes[0].name, "growing");
        assert_eq!(result.processes[0].rss_anon_change_bytes, 2 * 1024 * 1024);
        assert_eq!(
            result.current.mean_mem_total_bytes,
            Some((100 * 1024 * 1024) as f64)
        );
        assert_eq!(
            result.comparison.mean_mem_total_bytes,
            Some((200 * 1024 * 1024) as f64)
        );
    }

    #[test]
    fn schema_lock_and_retention_are_enforced() {
        let d = tempdir().unwrap();
        let path = d.path().join("x.sqlite");
        let mut c = open_db(&path).unwrap();
        let lock = acquire_writer_lock(d.path()).unwrap();
        assert!(acquire_writer_lock(d.path()).is_err());
        drop(lock);
        c.execute_batch("PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000")
            .unwrap();
        let fk: i64 = c
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        let timeout: i64 = c
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap();
        assert_eq!((fk, timeout), (1, 5000));
        let snapshot = Snapshot {
            host: HostSample {
                timestamp: 1,
                boot_id: "b".into(),
                ..Default::default()
            },
            processes: vec![ProcessSample {
                pid: 1,
                start_ticks: 1,
                name: "old".into(),
                executable: None,
                uid: None,
                cgroup_name: None,
                rss_anon: None,
                rss_file: None,
                rss_shmem: None,
                rss_total: None,
                cpu_ticks: None,
                read_bytes: None,
                write_bytes: None,
            }],
            gaps: vec!["test gap".into()],
        };
        insert_snapshot(&mut c, &snapshot).unwrap();
        cleanup(&mut c, 2).unwrap();
        assert_eq!(
            c.query_row("SELECT count(*) FROM process_identities", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        c.execute_batch("PRAGMA user_version=99").unwrap();
        drop(c);
        assert!(open_db(&path).is_err());
    }

    #[test]
    fn fake_proc_records_missing_sources_as_bounded_gaps() {
        let d = tempdir().unwrap();
        fs::create_dir_all(d.path().join("sys/kernel/random")).unwrap();
        fs::create_dir_all(d.path().join("pressure")).unwrap();
        fs::create_dir_all(d.path().join("42")).unwrap();
        fs::write(d.path().join("sys/kernel/random/boot_id"), "boot\n").unwrap();
        fs::write(
            d.path().join("42/stat"),
            "42 (fake) S 0 0 0 0 0 0 0 0 0 0 1 2 0 0 0 0 0 0 9\n",
        )
        .unwrap();
        let snapshot = Collector::new(d.path().to_path_buf()).collect(1);
        assert!(snapshot.host.mem_total.is_none());
        assert!(snapshot.gaps.iter().any(|g| g.contains("meminfo")));
        assert!(
            snapshot
                .gaps
                .iter()
                .any(|g| g.contains("process status unreadable"))
        );
    }

    #[test]
    fn service_unit_keeps_custom_config_and_database_together() {
        let unit = service_unit(
            Path::new("/opt/syslens-diagnosis"),
            Path::new("/tmp/custom.toml"),
            Path::new("/tmp/custom.sqlite"),
        );
        assert!(unit.contains("--config /tmp/custom.toml --database /tmp/custom.sqlite"));
    }
    #[test]
    fn package_service_and_linger_warning_are_truthful() {
        let asset = include_str!("../../../packaging/debian/syslens-diagnosis.service");
        assert!(asset.contains("daemon --config %h/.config/syslens-diagnosis/config.toml --database %h/.local/state/syslens-diagnosis/diagnosis.sqlite"));
        assert!(asset.contains("Type=simple"));
        let repo_asset = include_str!("../../../systemd/syslens-diagnosis.service");
        assert!(repo_asset.contains("Type=simple"));
        assert!(repo_asset.contains("daemon --config %h/.config/syslens-diagnosis/config.toml --database %h/.local/state/syslens-diagnosis/diagnosis.sqlite"));
        assert!(
            service_unit(Path::new("/bin/d"), Path::new("/c"), Path::new("/d"))
                .contains("Type=simple")
        );
        assert!(
            linger_warning_message("alice", false)
                .unwrap()
                .contains("loginctl enable-linger alice")
        );
        assert!(linger_warning_message("alice", true).is_none());
    }

    #[test]
    fn housekeeping_is_hourly_batched_and_removes_expired_identity() {
        let d = tempdir().unwrap();
        let path = d.path().join("x.sqlite");
        let mut c = open_db(&path).unwrap();
        let snapshot = Snapshot {
            host: HostSample {
                timestamp: 1,
                boot_id: "b".into(),
                ..Default::default()
            },
            processes: vec![ProcessSample {
                pid: 1,
                start_ticks: 1,
                name: "old".into(),
                executable: None,
                uid: None,
                cgroup_name: None,
                rss_anon: None,
                rss_file: None,
                rss_shmem: None,
                rss_total: None,
                cpu_ticks: None,
                read_bytes: None,
                write_bytes: None,
            }],
            gaps: vec![],
        };
        insert_snapshot(&mut c, &snapshot).unwrap();
        assert_eq!(housekeeping(&mut c, 2, 100).unwrap(), 1);
        assert_eq!(housekeeping(&mut c, 2, 101).unwrap(), 0);
        assert_eq!(
            c.query_row("SELECT count(*) FROM process_identities", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    #[test]
    fn expired_rows_can_compact_an_over_budget_database_and_resume() {
        let d = tempdir().unwrap();
        let path = d.path().join("x.sqlite");
        let mut c = open_db(&path).unwrap();
        let auto: i64 = c.query_row("PRAGMA auto_vacuum", [], |r| r.get(0)).unwrap();
        assert_eq!(auto, 2);
        for pid in 0..4 {
            let snapshot = Snapshot {
                host: HostSample {
                    timestamp: pid + 1,
                    boot_id: "b".into(),
                    ..Default::default()
                },
                processes: vec![ProcessSample {
                    pid,
                    start_ticks: pid,
                    name: "x".repeat(1024 * 1024),
                    executable: None,
                    uid: None,
                    cgroup_name: None,
                    rss_anon: None,
                    rss_file: None,
                    rss_shmem: None,
                    rss_total: None,
                    cpu_ticks: None,
                    read_bytes: None,
                    write_bytes: None,
                }],
                gaps: vec![],
            };
            insert_snapshot(&mut c, &snapshot).unwrap();
        }
        let budget = CONTROL_HEADROOM + database_size(&path) - 1;
        assert!(!budget_allows(&path, budget));
        let deleted = housekeeping(&mut c, 10, 100).unwrap();
        assert!(deleted > 0);
        assert!(recover_budget_after_cleanup(&mut c, &path, budget, 100, deleted).unwrap());
        assert!(budget_allows(&path, budget));
        insert_snapshot(
            &mut c,
            &Snapshot {
                host: HostSample {
                    timestamp: 200,
                    boot_id: "b".into(),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
    }

    #[test]
    fn v1_database_migrates_without_losing_ram_evidence() {
        let d = tempdir().unwrap();
        let path = d.path().join("x.sqlite");
        let mut c = open_db(&path).unwrap();
        insert_snapshot(
            &mut c,
            &Snapshot {
                host: HostSample {
                    timestamp: 9,
                    boot_id: "boot".into(),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
        c.execute_batch("DROP TABLE directory_samples; DROP TABLE storage_scans; DROP TABLE mount_samples; PRAGMA user_version=1;").unwrap();
        drop(c);
        let c = open_db(&path).unwrap();
        assert_eq!(
            c.query_row("SELECT count(*) FROM host_samples", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            c.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            2
        );
    }

    #[test]
    fn mounts_use_injectable_reader_and_keep_unavailable_as_gap() {
        struct Fake;
        impl FilesystemReader for Fake {
            fn mounts(&self) -> Result<Vec<MountInfo>, String> {
                Ok(vec![
                    MountInfo {
                        mount_point: PathBuf::from("/data"),
                        fs_type: "ext4".into(),
                        device: "/dev/x".into(),
                        read_only: false,
                    },
                    MountInfo {
                        mount_point: PathBuf::from("/proc"),
                        fs_type: "proc".into(),
                        device: "proc".into(),
                        read_only: true,
                    },
                ])
            }
            fn stat(&self, _: &Path) -> Result<FsStat, String> {
                Ok(FsStat {
                    blocks: 20,
                    blocks_free: 5,
                    block_size: 1024,
                    files: 10,
                    files_free: 2,
                })
            }
        }
        let (m, gaps) = collect_mounts(&Fake, 4);
        assert!(gaps.is_empty());
        assert_eq!(m[0].used_bytes, Some(15 * 1024));
        assert_eq!(m[1].capability, "excluded filesystem type");
    }

    #[test]
    fn directory_scan_excludes_symlinks_and_hardlinks() {
        let d = tempdir().unwrap();
        let root = d.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("one"), vec![1_u8; 4096]).unwrap();
        std::fs::hard_link(root.join("one"), root.join("two")).unwrap();
        std::os::unix::fs::symlink(root.join("one"), root.join("link")).unwrap();
        let scan = scan_directory(
            &root,
            None,
            &StorageConfig {
                max_depth: 4,
                ..Default::default()
            },
            1,
        );
        assert_eq!(scan.status, "complete");
        assert_eq!(scan.entries_seen, 3);
        let r = scan
            .directories
            .iter()
            .find(|x| x.path == root.display().to_string())
            .unwrap();
        assert_eq!(r.file_count, 2);
        assert!(r.apparent_bytes >= 4096 && r.apparent_bytes < 8192);
    }

    #[test]
    fn storage_diagnosis_requires_complete_comparable_scans() {
        let d = tempdir().unwrap();
        let path = d.path().join("x.sqlite");
        let mut c = open_db(&path).unwrap();
        let now = unix_now();
        for (time, used, size) in [
            (
                now - 7 * 86400 - 60,
                15_i64 * GIB as i64,
                15_i64 * GIB as i64,
            ),
            (now - 60, 20_i64 * GIB as i64, 20_i64 * GIB as i64),
        ] {
            insert_mounts(
                &mut c,
                &[MountSample {
                    timestamp: time,
                    mount_id: "dev|ext4|/data".into(),
                    mount_point: "/data".into(),
                    fs_type: "ext4".into(),
                    total_bytes: Some(100 * GIB as i64),
                    free_bytes: Some(100 * GIB as i64 - used),
                    used_bytes: Some(used),
                    total_inodes: None,
                    free_inodes: None,
                    read_only: false,
                    capability: "available".into(),
                }],
            )
            .unwrap();
            insert_scan(
                &mut c,
                &ScanResult {
                    root: "/data".into(),
                    mount_id: Some("dev|ext4|/data".into()),
                    started_at: time,
                    ended_at: time,
                    status: "complete".into(),
                    reason: None,
                    entries_seen: 1,
                    directories: vec![DirectorySample {
                        path: "/data/growing".into(),
                        allocated_bytes: size,
                        apparent_bytes: size,
                        entry_count: 1,
                        file_count: 1,
                    }],
                },
            )
            .unwrap();
        }
        let out = diagnose_storage(&path, "1h", "previous-week").unwrap();
        assert_eq!(out.status, "ok");
        assert_eq!(out.mounts[0].used_bytes_change, 5_i64 * GIB as i64);
        assert_eq!(
            out.directories[0].allocated_bytes_change,
            5_i64 * GIB as i64
        );
        c.execute(
            "UPDATE storage_scans SET status='partial' WHERE started_at>?",
            [now - 3600],
        )
        .unwrap();
        assert_eq!(
            diagnose_storage(&path, "1h", "previous-week")
                .unwrap()
                .status,
            "insufficient evidence"
        );
    }

    #[test]
    fn housekeeping_removes_aged_storage_evidence() {
        let d = tempdir().unwrap();
        let path = d.path().join("x.sqlite");
        let mut c = open_db(&path).unwrap();
        insert_mounts(
            &mut c,
            &[MountSample {
                timestamp: 1,
                mount_id: "m".into(),
                mount_point: "/data".into(),
                fs_type: "ext4".into(),
                total_bytes: Some(1),
                free_bytes: Some(1),
                used_bytes: Some(0),
                total_inodes: None,
                free_inodes: None,
                read_only: false,
                capability: "available".into(),
            }],
        )
        .unwrap();
        insert_scan(
            &mut c,
            &ScanResult {
                root: "/data".into(),
                mount_id: Some("m".into()),
                started_at: 1,
                ended_at: 1,
                status: "complete".into(),
                reason: None,
                entries_seen: 0,
                directories: vec![],
            },
        )
        .unwrap();
        cleanup(&mut c, 2).unwrap();
        assert_eq!(
            c.query_row("SELECT count(*) FROM mount_samples", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            c.query_row("SELECT count(*) FROM storage_scans", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn sparse_history_is_insufficient_evidence() {
        let d = tempdir().unwrap();
        let path = d.path().join("x.sqlite");
        let mut c = open_db(&path).unwrap();
        let now = unix_now();
        for timestamp in [now - 3600, now - 7 * 86400 - 3 * 3600] {
            insert_snapshot(
                &mut c,
                &Snapshot {
                    host: HostSample {
                        timestamp,
                        boot_id: "b".into(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .unwrap();
        }
        assert_eq!(
            diagnose_memory(&path, "2h", "previous-week")
                .unwrap()
                .status,
            "insufficient evidence"
        );
    }

    #[test]
    fn dense_null_meminfo_samples_cannot_claim_a_process_cause() {
        let d = tempdir().unwrap();
        let path = d.path().join("x.sqlite");
        let mut c = open_db(&path).unwrap();
        c.execute(
            "INSERT INTO metadata(key,value) VALUES('interval_seconds','300')",
            [],
        )
        .unwrap();
        let now = unix_now();
        for i in 0..12 {
            for (timestamp, valid) in [
                (now - i * 300 - 60, false),
                (now - 7 * 86400 - 3600 + i * 300 + 60, true),
            ] {
                insert_snapshot(
                    &mut c,
                    &Snapshot {
                        host: HostSample {
                            timestamp,
                            boot_id: "b".into(),
                            mem_total: valid.then_some(100),
                            mem_available: valid.then_some(80),
                            ..Default::default()
                        },
                        processes: vec![ProcessSample {
                            pid: 1,
                            start_ticks: 1,
                            name: "would-be-cause".into(),
                            executable: None,
                            uid: None,
                            cgroup_name: None,
                            rss_anon: Some(100),
                            rss_file: None,
                            rss_shmem: None,
                            rss_total: None,
                            cpu_ticks: None,
                            read_bytes: None,
                            write_bytes: None,
                        }],
                        gaps: if valid {
                            vec![]
                        } else {
                            vec!["meminfo unavailable".into()]
                        },
                    },
                )
                .unwrap();
            }
        }
        let result = diagnose_memory(&path, "1h", "previous-week").unwrap();
        assert_eq!(result.status, "insufficient evidence");
        assert!(result.processes.is_empty());
    }
}
