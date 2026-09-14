//! Local evidence recording and deterministic memory diagnosis for SysLens.
//!
//! This crate deliberately has no dependency on syslens-core or MQTT.  It is
//! an optional, host-local companion and may be stopped or removed independently.

use chrono::{DateTime, Datelike, Duration, Local, TimeZone, Utc};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration as StdDuration, SystemTime, UNIX_EPOCH};

pub const SCHEMA_VERSION: i64 = 1;
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
    tx.commit().map_err(|e| e.to_string())
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
