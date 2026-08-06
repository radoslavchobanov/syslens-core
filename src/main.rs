use chrono::{Datelike, Local, TimeZone};
use clap::{Args, Parser, Subcommand};
use rumqttc::{Client, Event, LastWill, MqttOptions, Packet, QoS, Transport};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{self, Write};
use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::process::ExitCode;
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const PROC: &str = "/proc";
const SYS: &str = "/sys";
const SECTOR_BYTES: f64 = 512.0;
const HOUR_SECONDS: f64 = 60.0 * 60.0;
const DAY_SECONDS: f64 = 24.0 * HOUR_SECONDS;
const HOURLY_BUCKET_RETENTION: i64 = 24;
const DAILY_BUCKET_RETENTION: i64 = 30;
const PROCESS_CPU_RESPONSE_SECONDS: f64 = 120.0;
static PCI_GPU_MODEL_CACHE: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();
static EMBEDDED_GPU_MODEL: OnceLock<Option<String>> = OnceLock::new();

#[derive(Parser, Debug)]
#[command(
    name = "syslens",
    about = "Low-overhead Linux telemetry collector for SysLens"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    /// Compatibility mode: print a JSON snapshot.
    #[arg(long, global = true)]
    json: bool,
    /// Pretty-print JSON output.
    #[arg(long, global = true)]
    pretty: bool,
    /// Compatibility mode: create an interactive configuration.
    #[arg(long, global = true)]
    setup: bool,
    /// Path written by --setup.
    #[arg(long, global = true)]
    setup_config: Option<PathBuf>,
    /// MQTT configuration file.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Compatibility mode: publish snapshots to MQTT.
    #[arg(long, global = true)]
    publish: bool,
    /// With --publish, send one snapshot and exit.
    #[arg(long, global = true)]
    once: bool,
    /// Validate configuration without connecting.
    #[arg(long, global = true)]
    validate_config: bool,
    #[command(flatten)]
    snapshot: SnapshotArgs,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print one local telemetry snapshot.
    Snapshot(SnapshotArgs),
    /// Create a local or MQTT publisher configuration interactively.
    Setup {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Publish snapshots continuously to MQTT.
    Agent(AgentArgs),
    /// Manage the optional privileged hardware-inventory helper.
    Inventory {
        #[command(subcommand)]
        command: InventoryCommand,
    },
}

#[derive(Subcommand, Debug)]
enum InventoryCommand {
    /// Install the root-owned DMI probe and daily systemd timer.
    Enable,
    /// Stop scheduled hardware inventory collection and clear its cached data.
    Disable,
    /// Internal: write the sanitised inventory cache. Used by the system service.
    Probe {
        #[arg(long, default_value = "/var/cache/syslens/hardware-inventory.json")]
        output: PathBuf,
    },
    /// Show whether the managed inventory cache is available.
    Status,
}

#[derive(Args, Debug, Clone)]
struct SnapshotArgs {
    /// Seconds used to calculate live rates and CPU usage.
    #[arg(long, default_value_t = 0.35)]
    sample_window: f64,
    /// Number of top processes included in the snapshot.
    #[arg(long, default_value_t = 6)]
    process_limit: usize,
}

#[derive(Args, Debug)]
struct AgentArgs {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    once: bool,
}

#[derive(Debug, Deserialize)]
struct RuntimeConfig {
    #[serde(default)]
    agent: AgentConfig,
    #[serde(default)]
    collection: CollectionConfig,
    mqtt: MqttConfig,
}

#[derive(Debug, Deserialize)]
struct AgentConfig {
    #[serde(default = "default_host_id")]
    host_id: String,
    #[serde(default = "default_interval")]
    interval_seconds: f64,
    #[serde(default = "default_sample_window")]
    sample_window_seconds: f64,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            host_id: default_host_id(),
            interval_seconds: default_interval(),
            sample_window_seconds: default_sample_window(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct CollectionConfig {
    #[serde(default = "default_process_limit")]
    process_limit: usize,
}

impl Default for CollectionConfig {
    fn default() -> Self {
        Self {
            process_limit: default_process_limit(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct MqttConfig {
    host: String,
    #[serde(default = "default_port")]
    port: u16,
    #[serde(default = "default_topic_prefix")]
    topic_prefix: String,
    username: Option<String>,
    password_env: Option<String>,
    client_id: Option<String>,
    #[serde(default)]
    tls: bool,
    #[serde(default = "default_keepalive")]
    keepalive_seconds: u64,
    #[serde(default = "default_qos")]
    qos: u8,
    #[serde(default = "default_retain")]
    retain: bool,
}

fn default_host_id() -> String {
    hostname::get()
        .ok()
        .and_then(|name| name.into_string().ok())
        .map(|name| sanitize_host_id(&name))
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "syslens".into())
}
fn default_interval() -> f64 {
    5.0
}
fn default_sample_window() -> f64 {
    0.35
}
fn default_process_limit() -> usize {
    6
}
fn default_port() -> u16 {
    1883
}
fn default_topic_prefix() -> String {
    "syslens".into()
}
fn default_keepalive() -> u64 {
    60
}
fn default_qos() -> u8 {
    1
}
fn default_retain() -> bool {
    true
}

fn sanitize_host_id(value: &str) -> String {
    value
        .chars()
        .map(|char| {
            if char.is_ascii_alphanumeric() || char == '_' || char == '-' {
                char.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_owned()
}

fn now_epoch() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or_default()
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct MetricSample {
    t: f64,
    v: f64,
    #[serde(default)]
    n: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct WeightedAverage {
    #[serde(default)]
    mean: f64,
    #[serde(default)]
    n: u64,
}

impl WeightedAverage {
    fn observe(&mut self, value: f64) {
        self.merge(value, 1);
    }

    fn merge(&mut self, mean: f64, n: u64) {
        if n == 0 || !finite(mean) {
            return;
        }
        let total = self.n.saturating_add(n);
        if total == 0 {
            return;
        }
        self.mean += (mean - self.mean) * n as f64 / total as f64;
        self.n = total;
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct MetricHistory {
    // Legacy five-minute buckets. They are read once and migrated to compact
    // hourly/daily weighted aggregates on the next snapshot.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    samples: Vec<MetricSample>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    hourly: BTreeMap<i64, WeightedAverage>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    daily: BTreeMap<i64, WeightedAverage>,
    #[serde(default)]
    all_time: WeightedAverage,
    // Pre-aggregate schema fields retained only for backwards-compatible
    // deserialization; they are intentionally omitted from new state files.
    #[serde(default, skip_serializing)]
    running_n: u64,
    #[serde(default, skip_serializing)]
    running_mean: f64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct TrafficBucket {
    #[serde(default)]
    rx_bytes: u64,
    #[serde(default)]
    tx_bytes: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct NetworkInterfaceHistory {
    #[serde(default)]
    rx_bytes: u64,
    #[serde(default)]
    tx_bytes: u64,
    #[serde(default)]
    updated_at: f64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct NetworkHistory {
    #[serde(default)]
    boot_id: String,
    #[serde(default)]
    interfaces: HashMap<String, NetworkInterfaceHistory>,
    #[serde(default)]
    daily: BTreeMap<String, TrafficBucket>,
    #[serde(default)]
    weekly: BTreeMap<String, TrafficBucket>,
    #[serde(default)]
    monthly: BTreeMap<String, TrafficBucket>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ProcessHistory {
    #[serde(default)]
    cpu_average_percent: f64,
    #[serde(default)]
    last_seen: f64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct RamModule {
    #[serde(default)]
    slot: String,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    capacity: Option<String>,
    #[serde(default)]
    ram_type: Option<String>,
    #[serde(default)]
    nominal_data_rate: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct RamInventory {
    #[serde(default)]
    available: bool,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    modules: Vec<RamModule>,
    #[serde(default)]
    manufacturer: Option<String>,
    #[serde(default)]
    ram_type: Option<String>,
    #[serde(default)]
    slots_populated: Option<usize>,
    #[serde(default)]
    slots_total: Option<usize>,
    #[serde(default)]
    nominal_data_rate: Option<String>,
    #[serde(default)]
    slot_layout: Option<String>,
    #[serde(default)]
    source: String,
    #[serde(default)]
    detail: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct NvmeHealth {
    #[serde(default)]
    available: bool,
    #[serde(default)]
    remaining_percent: Option<u8>,
    #[serde(default)]
    data_written_bytes: Option<u64>,
    #[serde(default)]
    critical_warning: Option<String>,
    #[serde(default)]
    power_on_hours: Option<u64>,
    #[serde(default)]
    source: String,
    #[serde(default)]
    detail: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct CollectorState {
    #[serde(default)]
    metrics: HashMap<String, MetricHistory>,
    #[serde(default)]
    maximums: HashMap<String, f64>,
    #[serde(default)]
    network: NetworkHistory,
    #[serde(default)]
    processes: HashMap<String, ProcessHistory>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HardwareInventory {
    schema_version: u8,
    collected_at: f64,
    ram: RamInventory,
    #[serde(default)]
    disk_health: Option<NvmeHealth>,
}

fn state_path() -> PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("syslens-core/state.json")
}

fn load_state() -> CollectorState {
    fs::read_to_string(state_path())
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn save_state(state: &CollectorState) {
    let path = state_path();
    let Some(parent) = path.parent() else {
        return;
    };
    if fs::create_dir_all(parent).is_err() {
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }
    let temporary = path.with_extension("tmp");
    let Ok(serialized) = serde_json::to_vec(state) else {
        return;
    };
    if fs::write(&temporary, serialized).is_ok() {
        let _ = fs::rename(&temporary, &path);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
    }
}

fn finite(value: f64) -> bool {
    value.is_finite()
}

fn time_bucket(timestamp: f64, seconds: f64) -> i64 {
    (timestamp / seconds).floor() as i64
}

fn weighted_bucket_average<'a>(buckets: impl Iterator<Item = &'a WeightedAverage>) -> Option<f64> {
    let mut aggregate = WeightedAverage::default();
    for bucket in buckets {
        aggregate.merge(bucket.mean, bucket.n);
    }
    (aggregate.n > 0).then_some(round(aggregate.mean, 1))
}

fn migrate_metric_history(history: &mut MetricHistory) {
    if history.all_time.n == 0 && history.running_n > 0 {
        history
            .all_time
            .merge(history.running_mean, history.running_n);
    }
    let rebuild_all_time_from_samples = history.all_time.n == 0;
    for sample in history.samples.drain(..).filter(|sample| finite(sample.v)) {
        let sample_count = sample.n.max(1) as u64;
        history
            .hourly
            .entry(time_bucket(sample.t, HOUR_SECONDS))
            .or_default()
            .merge(sample.v, sample_count);
        history
            .daily
            .entry(time_bucket(sample.t, DAY_SECONDS))
            .or_default()
            .merge(sample.v, sample_count);
        if rebuild_all_time_from_samples {
            history.all_time.merge(sample.v, sample_count);
        }
    }
    history.running_n = 0;
    history.running_mean = 0.0;
}

fn metric_averages(state: &mut CollectorState, key: &str, value: Option<f64>) -> Value {
    let Some(value) = value.filter(|value| finite(*value)) else {
        return json!({"period1":Value::Null,"period2":Value::Null,"overall":Value::Null});
    };
    let now = now_epoch();
    let history = state.metrics.entry(key.to_owned()).or_default();
    migrate_metric_history(history);
    let hour = time_bucket(now, HOUR_SECONDS);
    let day = time_bucket(now, DAY_SECONDS);
    history
        .hourly
        .retain(|bucket, _| *bucket > hour - HOURLY_BUCKET_RETENTION);
    history
        .daily
        .retain(|bucket, _| *bucket > day - DAILY_BUCKET_RETENTION);
    history.hourly.entry(hour).or_default().observe(value);
    history.daily.entry(day).or_default().observe(value);
    history.all_time.observe(value);
    json!({
        "period1":weighted_bucket_average(history.hourly.values()),
        "period2":weighted_bucket_average(history.daily.values()),
        "overall":(history.all_time.n > 0).then(|| round(history.all_time.mean,1))
    })
}

fn read_boot_id() -> String {
    read(format!("{PROC}/sys/kernel/random/boot_id")).unwrap_or_default()
}

fn read(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn read_i64(path: impl AsRef<Path>) -> Option<i64> {
    read(path)?.parse().ok()
}
fn read_f64(path: impl AsRef<Path>) -> Option<f64> {
    read(path)?.parse().ok()
}
fn round(value: f64, decimals: u32) -> f64 {
    let scale = 10_f64.powi(decimals as i32);
    (value * scale).round() / scale
}
fn pct(used: f64, total: f64) -> Option<f64> {
    (total > 0.0).then(|| round((used / total) * 100.0, 1))
}

fn parse_kv(path: &str, separator: char) -> BTreeMap<String, String> {
    read(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            line.split_once(separator)
                .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        })
        .collect()
}

fn cpu_times() -> Vec<Vec<u64>> {
    read(format!("{PROC}/stat"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next()?;
            if name == "cpu"
                || (name.starts_with("cpu") && name[3..].chars().all(|char| char.is_ascii_digit()))
            {
                Some(
                    fields
                        .filter_map(|value| value.parse::<u64>().ok())
                        .collect(),
                )
            } else {
                None
            }
        })
        .collect()
}

fn usage_percent(before: &[u64], after: &[u64]) -> f64 {
    let total_before: u64 = before.iter().sum();
    let total_after: u64 = after.iter().sum();
    let idle_before = before.get(3).copied().unwrap_or(0) + before.get(4).copied().unwrap_or(0);
    let idle_after = after.get(3).copied().unwrap_or(0) + after.get(4).copied().unwrap_or(0);
    let total = total_after.saturating_sub(total_before);
    if total == 0 {
        0.0
    } else {
        round(
            (1.0 - idle_after.saturating_sub(idle_before) as f64 / total as f64) * 100.0,
            1,
        )
    }
}

fn cpu_info() -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    for block in read(format!("{PROC}/cpuinfo"))
        .unwrap_or_default()
        .split("\n\n")
    {
        for line in block.lines() {
            if let Some((key, value)) = line.split_once(':') {
                result
                    .entry(key.trim().to_owned())
                    .or_insert_with(|| value.trim().to_owned());
            }
        }
    }
    result
}

fn cpu_list_count(list: &str) -> Option<usize> {
    let mut identifiers = std::collections::BTreeSet::new();
    for item in list.trim().split(',').filter(|item| !item.is_empty()) {
        let (first, last) = match item.split_once('-') {
            Some((first, last)) => (
                first.trim().parse::<usize>().ok()?,
                last.trim().parse::<usize>().ok()?,
            ),
            None => {
                let identifier = item.trim().parse::<usize>().ok()?;
                (identifier, identifier)
            }
        };
        if last < first {
            return None;
        }
        identifiers.extend(first..=last);
    }
    (!identifiers.is_empty()).then_some(identifiers.len())
}

fn sysfs_cpu_count(name: &str) -> Option<usize> {
    read(format!("{SYS}/devices/system/cpu/{name}")).and_then(|value| cpu_list_count(&value))
}

fn arm_cpu_model() -> Option<String> {
    if !matches!(std::env::consts::ARCH, "aarch64" | "arm") {
        return None;
    }
    let root = Path::new(SYS).join("devices/system/cpu");
    let mut families = BTreeMap::<String, usize>::new();
    for entry in fs::read_dir(root).ok()?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("cpu")
            || !name[3..]
                .chars()
                .all(|character| character.is_ascii_digit())
        {
            continue;
        }
        let Some(compatible) = read(entry.path().join("of_node/compatible")) else {
            continue;
        };
        let Some(family) = compatible
            .split('\0')
            .find(|value| value.starts_with("arm,cortex-"))
        else {
            continue;
        };
        let label = match family {
            "arm,cortex-a55" => "Cortex-A55".to_owned(),
            "arm,cortex-a76" => "Cortex-A76".to_owned(),
            _ => family
                .strip_prefix("arm,")
                .map(|value| {
                    let mut characters = value.chars();
                    characters
                        .next()
                        .map(|first| {
                            format!("{}{}", first.to_ascii_uppercase(), characters.as_str())
                        })
                        .unwrap_or_else(|| "ARM CPU".to_owned())
                })
                .unwrap_or_else(|| family.to_owned()),
        };
        *families.entry(label).or_default() += 1;
    }
    (!families.is_empty()).then(|| {
        let description = families
            .into_iter()
            .map(|(family, count)| format!("{count}\u{00d7} {family}"))
            .collect::<Vec<_>>()
            .join(" + ");
        format!("ARM {description}")
    })
}

fn cpu_vendor(info: &BTreeMap<String, String>) -> Option<String> {
    match info.get("CPU implementer").map(String::as_str) {
        Some("0x41") => Some("ARM".to_owned()),
        _ => info
            .get("vendor_id")
            .or_else(|| info.get("CPU implementer"))
            .cloned(),
    }
}

fn current_cpu_mhz() -> Vec<f64> {
    let mut values = Vec::new();
    let root = Path::new(SYS).join("devices/system/cpu");
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("cpu") || !name[3..].chars().all(|char| char.is_ascii_digit()) {
                continue;
            }
            let base = entry.path().join("cpufreq");
            let raw = read_f64(base.join("scaling_cur_freq"))
                .or_else(|| read_f64(base.join("cpuinfo_cur_freq")));
            if let Some(raw) = raw {
                values.push(if raw > 10_000.0 { raw / 1000.0 } else { raw });
            }
        }
    }
    if values.is_empty() {
        for block in read(format!("{PROC}/cpuinfo"))
            .unwrap_or_default()
            .split("\n\n")
        {
            if let Some(value) = block.lines().find_map(|line| {
                line.strip_prefix("cpu MHz")
                    .and_then(|line| line.split_once(':'))
                    .and_then(|(_, value)| value.trim().parse::<f64>().ok())
            }) {
                values.push(value);
            }
        }
    }
    values
}

#[derive(Clone)]
struct RaplCounter {
    path: PathBuf,
    name: String,
    energy_uj: u64,
    max_energy_uj: u64,
}

fn rapl_counters() -> Vec<RaplCounter> {
    let mut candidates = Vec::new();
    for root in [
        Path::new(SYS).join("class/powercap"),
        Path::new(SYS).join("devices/virtual/powercap"),
    ] {
        let Ok(entries) = fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let mut paths = vec![entry.path()];
            if let Ok(children) = fs::read_dir(entry.path()) {
                paths.extend(children.flatten().map(|child| child.path()));
            }
            for path in paths {
                let Some(energy_uj) = read_i64(path.join("energy_uj")).filter(|value| *value >= 0)
                else {
                    continue;
                };
                let name = read(path.join("name")).unwrap_or_default();
                if !name.to_ascii_lowercase().contains("package") {
                    continue;
                }
                let canonical = fs::canonicalize(&path).unwrap_or(path);
                candidates.push(RaplCounter {
                    path: canonical.clone(),
                    name,
                    energy_uj: energy_uj as u64,
                    max_energy_uj: read_i64(canonical.join("max_energy_range_uj"))
                        .filter(|value| *value > 0)
                        .map(|value| value as u64)
                        .unwrap_or(0),
                });
            }
        }
    }
    candidates.sort_by(|left, right| left.path.cmp(&right.path));
    candidates.dedup_by(|left, right| left.path == right.path);
    candidates
}

fn rapl_power_watts(before: &[RaplCounter], after: &[RaplCounter], elapsed: f64) -> Option<f64> {
    if elapsed <= 0.0 {
        return None;
    }
    let before_by_path: HashMap<&Path, &RaplCounter> = before
        .iter()
        .map(|counter| (counter.path.as_path(), counter))
        .collect();
    let mut total_uj = 0_u64;
    let mut matched = false;
    for current in after {
        let Some(previous) = before_by_path.get(current.path.as_path()) else {
            continue;
        };
        let delta = if current.energy_uj >= previous.energy_uj {
            current.energy_uj - previous.energy_uj
        } else if current.max_energy_uj > previous.energy_uj {
            current
                .max_energy_uj
                .saturating_sub(previous.energy_uj)
                .saturating_add(current.energy_uj)
        } else {
            continue;
        };
        total_uj = total_uj.saturating_add(delta);
        matched = true;
    }
    matched.then(|| round(total_uj as f64 / 1_000_000.0 / elapsed, 2))
}

fn cpu_snapshot(before: &[Vec<u64>], after: &[Vec<u64>], power_watts: Option<f64>) -> Value {
    let usage = if before.is_empty() || after.is_empty() {
        0.0
    } else {
        usage_percent(&before[0], &after[0])
    };
    let per_core: Vec<Value> = before
        .iter()
        .skip(1)
        .zip(after.iter().skip(1))
        .map(|(left, right)| json!(usage_percent(left, right)))
        .collect();
    let info = cpu_info();
    let clocks = current_cpu_mhz();
    let logical = sysfs_cpu_count("online")
        .or_else(|| {
            std::thread::available_parallelism()
                .map(|count| count.get())
                .ok()
        })
        .unwrap_or_else(|| per_core.len().max(1));
    let model = info
        .get("model name")
        .or_else(|| info.get("Hardware"))
        .or_else(|| info.get("Processor"))
        .cloned()
        .or_else(arm_cpu_model)
        .unwrap_or_else(|| "Unknown CPU".into());
    let vendor = cpu_vendor(&info);
    let cpufreq = json!({
        "available": !clocks.is_empty(),
        "current_mhz_avg": clocks.iter().copied().reduce(|left, right| left + right).map(|sum| round(sum / clocks.len() as f64, 1)),
        "current_mhz_min": clocks.iter().copied().reduce(f64::min).map(|value| round(value, 1)),
        "current_mhz_max": clocks.iter().copied().reduce(f64::max).map(|value| round(value, 1)),
        "governors": cpu_governors(),
        "scaling_min_mhz": read_f64(format!("{SYS}/devices/system/cpu/cpu0/cpufreq/scaling_min_freq")).map(|value| value / 1000.0),
        "scaling_max_mhz": read_f64(format!("{SYS}/devices/system/cpu/cpu0/cpufreq/scaling_max_freq")).map(|value| value / 1000.0),
        "boost": Vec::<String>::new(),
    });
    json!({
        "available": true, "architecture": std::env::consts::ARCH, "model": model, "vendor": vendor,
        // CPU feature flags are very large and not rendered by SysLens.  Keep
        // the stable field but omit them so MQTT snapshots fit conservative
        // broker packet limits (including the 10 KiB Mosquitto default here).
        "logical_cores": logical, "physical_cores": physical_core_count(&info).or_else(|| sysfs_cpu_count("present")).or_else(|| sysfs_cpu_count("possible")).unwrap_or(logical), "flags": Vec::<String>::new(),
        "microcode": info.get("microcode"), "cache": info.get("cache size"), "usage_percent": usage,
        "per_core_percent": per_core, "current_mhz_avg": cpufreq["current_mhz_avg"],
        "current_mhz_min": cpufreq["current_mhz_min"], "current_mhz_max": cpufreq["current_mhz_max"],
        "cpufreq": cpufreq, "load_average": load_average(), "power_watts": power_watts,
        "usage_average_percent": {"period1": Value::Null, "period2": Value::Null, "overall": Value::Null},
        "power_watts_average": {"period1": Value::Null, "period2": Value::Null, "overall": Value::Null},
        "usage_average_coverage_seconds": {"1d": 0, "1mo": 0, "overall": 0}
    })
}

fn physical_core_count(info: &BTreeMap<String, String>) -> Option<usize> {
    let cores = info.get("cpu cores")?.parse::<usize>().ok()?;
    let packages = read(format!("{PROC}/cpuinfo"))
        .unwrap_or_default()
        .split("\n\n")
        .filter_map(|block| {
            block.lines().find_map(|line| {
                line.strip_prefix("physical id")
                    .and_then(|line| line.split_once(':'))
                    .map(|(_, value)| value.trim().to_owned())
            })
        })
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    Some(cores * packages.max(1))
}

fn cpu_governors() -> Vec<String> {
    let root = Path::new(SYS).join("devices/system/cpu");
    let mut values = std::collections::BTreeSet::new();
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            if let Some(value) = read(entry.path().join("cpufreq/scaling_governor")) {
                values.insert(value);
            }
        }
    }
    values.into_iter().collect()
}

fn load_average() -> Value {
    let values: Vec<f64> = read(format!("{PROC}/loadavg"))
        .unwrap_or_default()
        .split_whitespace()
        .take(3)
        .filter_map(|value| value.parse().ok())
        .collect();
    json!({"1m": values.first().copied(), "5m": values.get(1).copied(), "15m": values.get(2).copied()})
}

fn usable_dmi_value(value: Option<&String>) -> Option<String> {
    let value = value?.trim();
    (!value.is_empty()
        && !matches!(
            value.to_ascii_lowercase().as_str(),
            "unknown" | "not specified" | "none" | "n/a"
        ))
    .then(|| value.to_owned())
}

fn ram_model_summary(modules: &[RamModule]) -> Option<String> {
    (!modules.is_empty()).then(|| {
        if let Some(model) = modules[0].model.as_deref().filter(|model| {
            modules
                .iter()
                .all(|module| module.model.as_deref() == Some(*model))
        }) {
            if modules.len() == 1 {
                model.to_owned()
            } else {
                format!("{} × {model}", modules.len())
            }
        } else {
            modules
                .iter()
                .map(|module| {
                    format!(
                        "{}: {}",
                        module.slot,
                        module.model.as_deref().unwrap_or("Not exposed")
                    )
                })
                .collect::<Vec<_>>()
                .join(" · ")
        }
    })
}

fn dmi_memory_inventory(output: &str) -> Option<RamInventory> {
    let mut manufacturers = std::collections::BTreeSet::new();
    let mut types = std::collections::BTreeSet::new();
    let mut speeds = std::collections::BTreeSet::new();
    let mut total_slots = 0_usize;
    let mut populated_slots = 0_usize;
    let mut modules = Vec::new();

    for block in output.split("\n\n") {
        if !block.lines().any(|line| line.trim() == "Memory Device") {
            continue;
        }
        total_slots += 1;
        let fields = block
            .lines()
            .filter_map(|line| line.trim().split_once(':'))
            .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
            .collect::<BTreeMap<_, _>>();
        let Some(size) = usable_dmi_value(fields.get("Size")) else {
            continue;
        };
        let is_populated = !size.eq_ignore_ascii_case("No Module Installed")
            && size
                .split_whitespace()
                .next()
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|value| value > 0);
        if !is_populated {
            continue;
        }
        populated_slots += 1;
        let ram_type = usable_dmi_value(fields.get("Type"));
        let nominal_data_rate = usable_dmi_value(
            fields
                .get("Configured Memory Speed")
                .or_else(|| fields.get("Speed")),
        );
        let slot = usable_dmi_value(fields.get("Locator"))
            .unwrap_or_else(|| format!("DIMM {populated_slots}"));
        modules.push(RamModule {
            slot,
            model: usable_dmi_value(fields.get("Part Number")),
            capacity: Some(size),
            ram_type: ram_type.clone(),
            nominal_data_rate: nominal_data_rate.clone(),
        });
        if let Some(value) = usable_dmi_value(fields.get("Manufacturer")) {
            manufacturers.insert(value);
        }
        if let Some(value) = ram_type {
            types.insert(value);
        }
        if let Some(value) = nominal_data_rate {
            speeds.insert(value);
        }
    }

    (total_slots > 0).then(|| RamInventory {
        available: populated_slots > 0,
        model: ram_model_summary(&modules),
        modules,
        manufacturer: (!manufacturers.is_empty())
            .then(|| manufacturers.into_iter().collect::<Vec<_>>().join(" / ")),
        ram_type: (!types.is_empty()).then(|| types.into_iter().collect::<Vec<_>>().join(" / ")),
        slots_populated: Some(populated_slots),
        slots_total: Some(total_slots),
        nominal_data_rate: (!speeds.is_empty())
            .then(|| speeds.into_iter().collect::<Vec<_>>().join(" / ")),
        slot_layout: None,
        source: "dmi".into(),
        detail: None,
    })
}

fn unavailable_ram_inventory() -> RamInventory {
    let has_dmi = Path::new("/sys/firmware/dmi/tables/DMI").exists();
    RamInventory {
        available: false,
        model: None,
        modules: Vec::new(),
        manufacturer: (!has_dmi).then(|| "Board-integrated".into()),
        ram_type: None,
        slots_populated: None,
        slots_total: None,
        nominal_data_rate: None,
        slot_layout: (!has_dmi).then(|| "Board-integrated".into()),
        source: if has_dmi {
            "dmi-access-required".into()
        } else {
            "firmware-unavailable".into()
        },
        detail: Some(if has_dmi {
            "DMI inventory requires the optional read-only helper".into()
        } else {
            "Firmware does not expose DIMM inventory".into()
        }),
    }
}

fn hardware_inventory_path() -> PathBuf {
    PathBuf::from(INVENTORY_CACHE)
}

fn managed_ram_inventory() -> Option<RamInventory> {
    fs::read_to_string(hardware_inventory_path())
        .ok()
        .and_then(|raw| serde_json::from_str::<HardwareInventory>(&raw).ok())
        .filter(|inventory| inventory.schema_version == 1)
        .map(|inventory| inventory.ram)
}

fn collected_ram_inventory() -> RamInventory {
    ProcessCommand::new("/usr/sbin/dmidecode")
        .args(["--type", "17", "--quiet"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|output| dmi_memory_inventory(&output))
        .unwrap_or_else(unavailable_ram_inventory)
}

fn memory_snapshot() -> Value {
    let fields = parse_kv(&format!("{PROC}/meminfo"), ':');
    let kib = |name: &str| {
        fields
            .get(name)
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0)
    };
    let total = kib("MemTotal") * 1024;
    let available = kib("MemAvailable").max(kib("MemFree")) * 1024;
    let used = total.saturating_sub(available);
    let swap_total = kib("SwapTotal") * 1024;
    let swap_free = kib("SwapFree") * 1024;
    json!({
        "available": total > 0, "total_bytes": total, "used_bytes": used, "free_bytes": kib("MemFree") * 1024,
        "available_bytes": available, "usage_percent": pct(used as f64, total as f64), "buffers_bytes": kib("Buffers") * 1024,
        "cached_bytes": kib("Cached") * 1024, "dirty_bytes": kib("Dirty") * 1024, "slab_bytes": kib("Slab") * 1024,
        "inventory": managed_ram_inventory().unwrap_or_else(unavailable_ram_inventory),
        "swap": {"available": swap_total > 0, "total_bytes": swap_total, "used_bytes": swap_total.saturating_sub(swap_free), "free_bytes": swap_free, "usage_percent": pct(swap_total.saturating_sub(swap_free) as f64, swap_total as f64), "zswap_bytes": kib("Zswap") * 1024, "zswapped_bytes": kib("Zswapped") * 1024},
        "usage_average_percent": {"period1": Value::Null, "period2": Value::Null, "overall": Value::Null}
    })
}

fn hwmon_sensors() -> Vec<Value> {
    let mut sensors = Vec::new();
    for root in [
        Path::new(SYS).join("class/hwmon"),
        Path::new(SYS).join("class/thermal"),
    ] {
        let Ok(entries) = fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let source = read(path.join("name"))
                .or_else(|| read(path.join("type")))
                .unwrap_or_else(|| entry.file_name().to_string_lossy().into_owned());
            let Ok(files) = fs::read_dir(&path) else {
                continue;
            };
            for file in files.flatten() {
                let filename = file.file_name().to_string_lossy().into_owned();
                if !filename.starts_with("temp") || !filename.ends_with("_input") {
                    continue;
                }
                let Some(raw) = read_f64(file.path()) else {
                    continue;
                };
                let celsius = if raw.abs() > 300.0 { raw / 1000.0 } else { raw };
                let prefix = filename.trim_end_matches("_input");
                let label =
                    read(path.join(format!("{prefix}_label"))).unwrap_or_else(|| source.clone());
                let category =
                    temperature_category(&label, &source, &file.path().to_string_lossy());
                sensors.push(json!({"label": label, "source": source, "path": file.path(), "celsius": round(celsius, 1), "category": category}));
            }
        }
    }
    sensors
}

fn temperature_category(label: &str, source: &str, path: &str) -> &'static str {
    let text = format!("{} {} {}", label, source, path).to_ascii_lowercase();
    if ["amdgpu", "radeon", "nouveau", "nvidia", "i915", "xe", "gpu"]
        .iter()
        .any(|term| text.contains(term))
    {
        "gpu"
    } else if [
        "nvme",
        "ssd",
        "drivetemp",
        "sata",
        "ata",
        "scsi",
        "hdd",
        "disk",
    ]
    .iter()
    .any(|term| text.contains(term))
    {
        "storage"
    } else if [
        "cpu", "core", "package", "k10temp", "tctl", "tdie", "zenpower",
    ]
    .iter()
    .any(|term| text.contains(term))
    {
        "cpu"
    } else {
        "other"
    }
}

fn temperature_display_label(category: &str, raw_label: &str, source: &str) -> String {
    let raw = raw_label.to_ascii_lowercase();
    let source = source.to_ascii_lowercase();
    match category {
        "gpu" if raw.contains("edge") => "GPU edge temperature".into(),
        "gpu" if raw.contains("junction") => "GPU junction temperature".into(),
        "gpu" => "GPU temperature".into(),
        "storage" if source.contains("nvme") || raw.contains("composite") => {
            "NVMe temperature".into()
        }
        "storage" => "Storage temperature".into(),
        "cpu" => "CPU temperature".into(),
        _ => raw_label.to_owned(),
    }
}

fn temperature_group(sensors: &[Value], category: &str) -> Value {
    let mut candidates: Vec<&Value> = sensors
        .iter()
        .filter(|sensor| sensor.get("category").and_then(Value::as_str) == Some(category))
        .collect();
    if category == "storage" {
        let preferred: Vec<&Value> = candidates
            .iter()
            .copied()
            .filter(|sensor| {
                sensor
                    .get("label")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .contains("composite")
            })
            .collect();
        if !preferred.is_empty() {
            candidates = preferred;
        }
    } else if category == "gpu" {
        let preferred: Vec<&Value> = candidates
            .iter()
            .copied()
            .filter(|sensor| {
                sensor
                    .get("label")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .contains("edge")
            })
            .collect();
        if !preferred.is_empty() {
            candidates = preferred;
        }
    }
    let primary = candidates
        .iter()
        .max_by(|left, right| {
            left.get("celsius")
                .and_then(Value::as_f64)
                .unwrap_or_default()
                .total_cmp(
                    &right
                        .get("celsius")
                        .and_then(Value::as_f64)
                        .unwrap_or_default(),
                )
        })
        .copied();
    let raw_label = primary
        .and_then(|sensor| sensor.get("label"))
        .and_then(Value::as_str);
    let source = primary
        .and_then(|sensor| sensor.get("source"))
        .and_then(Value::as_str);
    json!({
        "available": primary.is_some(),
        "current_celsius": primary.and_then(|sensor| sensor.get("celsius")),
        "label": raw_label.map(|label| temperature_display_label(category, label, source.unwrap_or_default())),
        "raw_label": raw_label,
        "source": primary.and_then(|sensor| sensor.get("source")),
        "sensors": sensors.iter().filter(|sensor| sensor.get("category").and_then(Value::as_str) == Some(category)).collect::<Vec<_>>()
    })
}

fn temperature_snapshot() -> Value {
    let sensors = hwmon_sensors();
    let cpu: Vec<&Value> = sensors
        .iter()
        .filter(|sensor| sensor.get("category").and_then(Value::as_str) == Some("cpu"))
        .collect();
    let cpu_current = if cpu.is_empty() {
        None
    } else {
        Some(round(
            cpu.iter()
                .filter_map(|sensor| sensor.get("celsius").and_then(Value::as_f64))
                .sum::<f64>()
                / cpu.len() as f64,
            1,
        ))
    };
    let cpu_max = cpu
        .iter()
        .filter_map(|sensor| sensor.get("celsius").and_then(Value::as_f64))
        .max_by(f64::total_cmp)
        .map(|value| round(value, 1));
    let hottest = sensors.iter().max_by(|left, right| {
        left.get("celsius")
            .and_then(Value::as_f64)
            .unwrap_or_default()
            .total_cmp(
                &right
                    .get("celsius")
                    .and_then(Value::as_f64)
                    .unwrap_or_default(),
            )
    });
    json!({
        "available": !sensors.is_empty(), "hottest_celsius": hottest.and_then(|sensor| sensor.get("celsius")), "hottest_label": hottest.and_then(|sensor| sensor.get("label")),
        "cpu_current_celsius": cpu_current, "cpu_current_sensor_max_celsius": cpu_max, "cpu_average_celsius": cpu_current,
        "cpu_maximum_celsius": cpu_max, "cpu_minimum_celsius": cpu_current, "cpu_history_seconds": 0,
        "source": if sensors.is_empty() { Value::Null } else { json!("sysfs") }, "sensors": sensors,
        "hardware": {"gpu": temperature_group(&sensors, "gpu"), "storage": temperature_group(&sensors, "storage"), "other": temperature_group(&sensors, "other")}
    })
}

#[derive(Clone, Default)]
struct DiskCounters {
    reads: u64,
    read_sectors: u64,
    writes: u64,
    write_sectors: u64,
    io_ms: u64,
}

fn disk_counters() -> HashMap<String, DiskCounters> {
    let mut disks = HashMap::new();
    for line in read(format!("{PROC}/diskstats"))
        .unwrap_or_default()
        .lines()
    {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 14 {
            continue;
        }
        let name = fields[2];
        if !(name.starts_with("sd")
            || name.starts_with("vd")
            || name.starts_with("xvd")
            || name.starts_with("nvme")
            || name.starts_with("mmcblk")
            || name.starts_with("md"))
        {
            continue;
        }
        // `/proc/diskstats` reports both whole drives and their partitions.
        // Presenting both doubles I/O in the UI and turns one physical disk
        // into a noisy table, so keep only block-device level readings.
        if Path::new(SYS)
            .join("class/block")
            .join(name)
            .join("partition")
            .exists()
        {
            continue;
        }
        let parsed = |index: usize| {
            fields
                .get(index)
                .and_then(|value| value.parse().ok())
                .unwrap_or_default()
        };
        disks.insert(
            name.into(),
            DiskCounters {
                reads: parsed(3),
                read_sectors: parsed(5),
                writes: parsed(7),
                write_sectors: parsed(9),
                io_ms: parsed(12),
            },
        );
    }
    disks
}

fn root_usage() -> Value {
    let path = std::ffi::CString::new("/").expect("static path");
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut stat) } != 0 {
        return json!({"mount":"/"});
    }
    let block_size = stat.f_frsize as u64;
    let total = stat.f_blocks.saturating_mul(block_size);
    let free = stat.f_bavail.saturating_mul(block_size);
    let used = total.saturating_sub(stat.f_bfree.saturating_mul(block_size));
    json!({"mount":"/", "total_bytes":total, "used_bytes":used, "free_bytes":free, "reserved_bytes": total.saturating_sub(used).saturating_sub(free), "usage_percent": pct(used as f64, (used + free) as f64), "usage_percent_total": pct(used as f64, total as f64)})
}

fn root_block_device() -> Option<PathBuf> {
    let mounts = read(format!("{PROC}/mounts"))?;
    let source = mounts
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            (fields.get(1) == Some(&"/")).then(|| fields.first().copied())?
        })
        .find(|source| source.starts_with("/dev/"))?;
    let device = Path::new(source).file_name()?.to_str()?;
    let class_path = Path::new(SYS).join("class/block").join(device);
    let canonical = fs::canonicalize(&class_path).ok()?;
    if class_path.join("partition").exists() {
        canonical.parent().map(Path::to_path_buf)
    } else {
        Some(canonical)
    }
}

fn disk_kind(name: &str, device: &Path) -> Option<String> {
    if name.starts_with("nvme") {
        return Some("NVMe SSD".into());
    }
    if name.starts_with("mmcblk") {
        return Some("eMMC / SD".into());
    }
    match read(device.join("queue/rotational")).as_deref() {
        Some("0") => Some("Solid-state drive".into()),
        Some("1") => Some("Hard disk drive".into()),
        _ => None,
    }
}

fn pci_link_speed(start: &Path) -> Option<String> {
    let mut current = fs::canonicalize(start).ok()?;
    while current.starts_with(SYS) {
        let speed = read(current.join("current_link_speed"));
        let width = read(current.join("current_link_width"));
        if speed.is_some() || width.is_some() {
            return match (speed, width) {
                (Some(speed), Some(width)) => Some(format!("{speed} ×{width}")),
                (Some(speed), None) => Some(speed),
                (None, Some(width)) => Some(format!("PCIe ×{width}")),
                (None, None) => None,
            };
        }
        if !current.pop() {
            break;
        }
    }
    None
}

#[repr(C)]
#[derive(Default)]
struct NvmePassthruCmd {
    opcode: u8,
    flags: u8,
    rsvd1: u16,
    nsid: u32,
    cdw2: u32,
    cdw3: u32,
    metadata: u64,
    addr: u64,
    metadata_len: u32,
    data_len: u32,
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
    cdw13: u32,
    cdw14: u32,
    cdw15: u32,
    timeout_ms: u32,
    result: u32,
}

fn nvme_admin_ioctl() -> libc::c_ulong {
    const IOC_WRITE: u64 = 1;
    const IOC_READ: u64 = 2;
    const IOC_NRSHIFT: u64 = 0;
    const IOC_TYPESHIFT: u64 = 8;
    const IOC_SIZESHIFT: u64 = 16;
    const IOC_DIRSHIFT: u64 = 30;
    ((IOC_READ | IOC_WRITE) << IOC_DIRSHIFT
        | (std::mem::size_of::<NvmePassthruCmd>() as u64) << IOC_SIZESHIFT
        | (b'N' as u64) << IOC_TYPESHIFT
        | 0x41 << IOC_NRSHIFT) as libc::c_ulong
}

fn nvme_controller_for_block_device(name: &str) -> Option<&str> {
    let suffix = name.strip_prefix("nvme")?;
    let controller_digits = suffix
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .count();
    (controller_digits > 0 && suffix.get(controller_digits..)?.starts_with('n'))
        .then(|| &name[..4 + controller_digits])
}

fn little_endian_u128(bytes: &[u8]) -> u128 {
    bytes
        .iter()
        .take(16)
        .enumerate()
        .fold(0_u128, |value, (index, byte)| {
            value | ((*byte as u128) << (index * 8))
        })
}

fn nvme_critical_warning(warning: u8) -> String {
    if warning == 0 {
        return "No warnings".into();
    }
    let labels = [
        (0, "Spare below threshold"),
        (1, "Temperature critical"),
        (2, "Reliability degraded"),
        (3, "Media read-only"),
        (4, "Volatile memory backup failed"),
    ];
    let mut reported = labels
        .iter()
        .filter_map(|(bit, label)| (warning & (1 << bit) != 0).then_some(*label))
        .collect::<Vec<_>>();
    if warning & !0b1_1111 != 0 {
        reported.push("Vendor warning");
    }
    format!("Warning: {}", reported.join(", "))
}

fn parse_nvme_smart_log(log: &[u8]) -> Option<NvmeHealth> {
    (log.len() >= 144).then(|| {
        let percentage_used = log[5];
        let written_units = little_endian_u128(&log[48..64]);
        let written_bytes = written_units.saturating_mul(512_000).min(u64::MAX as u128) as u64;
        let power_on_hours = little_endian_u128(&log[128..144]).min(u64::MAX as u128) as u64;
        NvmeHealth {
            available: true,
            remaining_percent: Some(100_u8.saturating_sub(percentage_used.min(100))),
            data_written_bytes: Some(written_bytes),
            critical_warning: Some(nvme_critical_warning(log[0])),
            power_on_hours: Some(power_on_hours),
            source: "nvme-smart".into(),
            detail: None,
        }
    })
}

fn nvme_health_for_block_device(name: &str) -> Option<NvmeHealth> {
    let controller = nvme_controller_for_block_device(name)?;
    let device = fs::OpenOptions::new()
        .read(true)
        .open(format!("/dev/{controller}"))
        .ok()?;
    let mut log = [0_u8; 512];
    let mut command = NvmePassthruCmd {
        opcode: 0x02,
        nsid: u32::MAX,
        addr: log.as_mut_ptr() as u64,
        data_len: log.len() as u32,
        // Get Log Page: LID 0x02 (SMART / health), NUMD 127 for 512 bytes.
        cdw10: 0x02 | (127 << 16),
        ..Default::default()
    };
    let result = unsafe { libc::ioctl(device.as_raw_fd(), nvme_admin_ioctl(), &mut command) };
    (result == 0).then(|| parse_nvme_smart_log(&log)).flatten()
}

fn managed_disk_health() -> Option<NvmeHealth> {
    fs::read_to_string(hardware_inventory_path())
        .ok()
        .and_then(|raw| serde_json::from_str::<HardwareInventory>(&raw).ok())
        .filter(|inventory| inventory.schema_version == 1)
        .and_then(|inventory| inventory.disk_health)
}

fn root_disk_inventory() -> Value {
    let Some(device) = root_block_device() else {
        return json!({"available":false});
    };
    let name = device
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let hardware = device.join("device");
    json!({
        "available":true,
        "device":name,
        "model":read(hardware.join("model")),
        "manufacturer":read(hardware.join("vendor")),
        "type":disk_kind(name, &device),
        "link_speed":pci_link_speed(&hardware),
        "health":managed_disk_health(),
    })
}

fn disk_snapshot(
    before: &HashMap<String, DiskCounters>,
    after: &HashMap<String, DiskCounters>,
    elapsed: f64,
) -> Value {
    let mut devices = Vec::new();
    let mut read_total = 0.0;
    let mut write_total = 0.0;
    let mut names: Vec<_> = after.keys().collect();
    names.sort();
    for name in names {
        let Some(previous) = before.get(name) else {
            continue;
        };
        let current = &after[name];
        let read = current.read_sectors.saturating_sub(previous.read_sectors) as f64 * SECTOR_BYTES
            / elapsed;
        let write = current.write_sectors.saturating_sub(previous.write_sectors) as f64
            * SECTOR_BYTES
            / elapsed;
        read_total += read;
        write_total += write;
        devices.push(json!({"name":name, "read_bytes_per_sec":round(read,1), "write_bytes_per_sec":round(write,1), "reads_per_sec":round(current.reads.saturating_sub(previous.reads) as f64/elapsed,1), "writes_per_sec":round(current.writes.saturating_sub(previous.writes) as f64/elapsed,1), "busy_percent":pct(current.io_ms.saturating_sub(previous.io_ms) as f64, elapsed * 1000.0)}));
    }
    json!({"available":!devices.is_empty(),"root":root_usage(),"inventory":root_disk_inventory(),"total_read_bytes_per_sec":round(read_total,1),"total_write_bytes_per_sec":round(write_total,1),"devices":devices})
}

#[derive(Clone, Default)]
struct NetCounters {
    rx: u64,
    tx: u64,
    drops: u64,
    state: String,
    speed_mbps: Option<u64>,
}

fn net_counters() -> HashMap<String, NetCounters> {
    let mut result = HashMap::new();
    for line in read(format!("{PROC}/net/dev"))
        .unwrap_or_default()
        .lines()
        .skip(2)
    {
        let Some((name, values)) = line.split_once(':') else {
            continue;
        };
        let fields: Vec<&str> = values.split_whitespace().collect();
        if fields.len() < 12 {
            continue;
        }
        let interface = name.trim().to_owned();
        let parse = |index: usize| {
            fields
                .get(index)
                .and_then(|value| value.parse().ok())
                .unwrap_or_default()
        };
        let base = Path::new(SYS).join("class/net").join(&interface);
        result.insert(
            interface,
            NetCounters {
                rx: parse(0),
                tx: parse(8),
                drops: parse(3) + parse(11),
                state: read(base.join("operstate")).unwrap_or_default(),
                speed_mbps: read_i64(base.join("speed"))
                    .filter(|value| *value > 0)
                    .map(|value| value as u64),
            },
        );
    }
    result
}

fn is_virtual_interface(name: &str) -> bool {
    ["lo", "docker", "veth", "br-", "virbr", "tun", "tap"]
        .iter()
        .any(|prefix| name == *prefix || name.starts_with(prefix))
}

fn local_ipv4() -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("1.1.1.1:80").ok()?;
    Some(socket.local_addr().ok()?.ip().to_string())
}

fn network_snapshot(
    before: &HashMap<String, NetCounters>,
    after: &HashMap<String, NetCounters>,
    elapsed: f64,
) -> Value {
    let mut interfaces = Vec::new();
    let mut traffic = Vec::new();
    let mut rx_total = 0.0;
    let mut tx_total = 0.0;
    let mut names: Vec<_> = after.keys().collect();
    names.sort();
    for name in names {
        let current = &after[name];
        let previous = before.get(name).unwrap_or(current);
        let rx = current.rx.saturating_sub(previous.rx) as f64 / elapsed;
        let tx = current.tx.saturating_sub(previous.tx) as f64 / elapsed;
        let item = json!({"name":name,"state":current.state,"speed_mbps":current.speed_mbps,"drops":current.drops,"rx_bytes_per_sec":round(rx,1),"tx_bytes_per_sec":round(tx,1)});
        // Docker bridges and veth pairs can number in the dozens. They add no
        // useful host-level signal and can make an MQTT state larger than a
        // broker's packet limit, so only expose usable host links here.
        if (!is_virtual_interface(name) && current.state == "up")
            || (!is_virtual_interface(name) && current.speed_mbps.is_some())
        {
            interfaces.push(item.clone());
        }
        if !is_virtual_interface(name) && current.state == "up" {
            rx_total += rx;
            tx_total += tx;
            traffic.push(item);
        }
    }
    let primary = traffic
        .first()
        .cloned()
        .unwrap_or_else(|| interfaces.first().cloned().unwrap_or_else(|| json!({})));
    json!({"available":!interfaces.is_empty(),"interfaces":interfaces,"traffic_interfaces":traffic,"interface_count":after.len(),"virtual_interface_count":after.keys().filter(|name| is_virtual_interface(name)).count(),"primary":primary,"download_bytes_per_sec":round(rx_total,1),"upload_bytes_per_sec":round(tx_total,1),"local_ipv4":local_ipv4(),"global_ipv4":{"available":false,"address":Value::Null},"totals":{"daily":{},"weekly":{},"monthly":{}},"download_average":{"period1":Value::Null,"period2":Value::Null,"overall":Value::Null},"upload_average":{"period1":Value::Null,"period2":Value::Null,"overall":Value::Null}})
}

fn driver_name(device: &Path) -> Option<String> {
    read(device.join("uevent")).and_then(|uevent| {
        uevent
            .lines()
            .find_map(|line| line.strip_prefix("DRIVER=").map(str::to_owned))
    })
}

fn pci_gpu_model(device: &Path) -> Option<String> {
    let slot = read(device.join("uevent")).and_then(|uevent| {
        uevent
            .lines()
            .find_map(|line| line.strip_prefix("PCI_SLOT_NAME=").map(str::to_owned))
    })?;
    let cache = PCI_GPU_MODEL_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(cache) = cache.lock()
        && let Some(model) = cache.get(&slot)
    {
        return model.clone();
    }
    let model = ProcessCommand::new("lspci")
        .args(["-nn", "-s", &slot])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|output| output.lines().next().map(str::to_owned))
        .and_then(|line| line.split_once(": ").map(|(_, value)| value.to_owned()))
        .map(|value| {
            value
                .rsplit_once(" [")
                .map(|(model, _)| model)
                .unwrap_or(&value)
                .split(" (rev ")
                .next()
                .unwrap_or(&value)
                .trim()
                .to_owned()
        })
        .filter(|model| !model.is_empty());
    if let Ok(mut cache) = cache.lock() {
        cache.insert(slot, model.clone());
    }
    model
}

fn embedded_gpu_model() -> Option<String> {
    EMBEDDED_GPU_MODEL
        .get_or_init(|| {
            let compatible = fs::read("/proc/device-tree/compatible").ok()?;
            let mut entries = compatible
                .split(|byte| *byte == 0)
                .filter_map(|value| std::str::from_utf8(value).ok());
            entries
                .any(|entry| matches!(entry, "rockchip,rk3588" | "rockchip,rk3588s"))
                .then(|| "ARM Mali-G610 MP4".into())
        })
        .clone()
}

fn gpu_model(device: &Path) -> Option<String> {
    pci_gpu_model(device).or_else(embedded_gpu_model)
}

fn active_dpm_clock_mhz(content: &str) -> Option<f64> {
    content.lines().find_map(|line| {
        line.contains('*').then(|| {
            line.split_whitespace().find_map(|token| {
                token
                    .strip_suffix("Mhz")
                    .or_else(|| token.strip_suffix("MHz"))
                    .and_then(|value| value.parse::<f64>().ok())
            })
        })?
    })
}

fn gpu_hwmon_frequency_mhz(device: &Path) -> Option<f64> {
    fs::read_dir(device.join("hwmon"))
        .ok()?
        .flatten()
        .find_map(|entry| {
            read_f64(entry.path().join("freq1_input")).map(|hertz| hertz / 1_000_000.0)
        })
}

fn gpu_clock_mhz(device: &Path, dpm_file: &str) -> Option<f64> {
    read(device.join(dpm_file))
        .and_then(|content| active_dpm_clock_mhz(&content))
        .or_else(|| {
            (dpm_file == "pp_dpm_sclk")
                .then(|| gpu_hwmon_frequency_mhz(device))
                .flatten()
        })
}

fn gpu_snapshot() -> Value {
    let mut devices = Vec::new();
    let root = Path::new(SYS).join("class/drm");
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("card") || !name[4..].chars().all(|char| char.is_ascii_digit()) {
                continue;
            }
            let device = entry.path().join("device");
            if !device.exists() {
                continue;
            }
            let usage = read_f64(device.join("gpu_busy_percent"));
            let used = read_i64(device.join("mem_info_vram_used"))
                .filter(|value| *value >= 0)
                .map(|value| value as u64);
            let total = read_i64(device.join("mem_info_vram_total"))
                .filter(|value| *value > 0)
                .map(|value| value as u64);
            let label = read(device.join("product"))
                .or_else(|| {
                    read(device.join("uevent"))
                        .and_then(|value| value.lines().next().map(str::to_owned))
                })
                .unwrap_or_else(|| name.clone());
            devices.push(json!({"name":name,"model":gpu_model(&device),"driver":driver_name(&device),"vendor_id":read(device.join("vendor")),"device_id":read(device.join("device")),"label":label,"core_clock_mhz":gpu_clock_mhz(&device,"pp_dpm_sclk").map(|value|round(value,0)),"vram_clock_mhz":gpu_clock_mhz(&device,"pp_dpm_mclk").map(|value|round(value,0)),"usage_percent":usage.map(|value|round(value,1)),"vram_used_bytes":used,"vram_total_bytes":total,"vram_usage_percent":match (used,total) {(Some(used),Some(total)) => pct(used as f64,total as f64), _ => None}}));
        }
    }
    json!({"available":!devices.is_empty(),"devices":devices,"usage_average_percent":{"period1":Value::Null,"period2":Value::Null,"overall":Value::Null},"vram_average_percent":{"period1":Value::Null,"period2":Value::Null,"overall":Value::Null}})
}

fn power_snapshot(cpu_power_watts: Option<f64>, rapl: &[RaplCounter]) -> Value {
    let mut supplies = Vec::new();
    let root = Path::new(SYS).join("class/power_supply");
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            let kind = read(path.join("type")).unwrap_or_default();
            let power = read_f64(path.join("power_now")).map(|value| value / 1_000_000.0);
            supplies.push(json!({"name":name,"type":kind,"status":read(path.join("status")),"capacity_percent":read_f64(path.join("capacity")),"power_watts":power.map(|value|round(value,3)),"energy_now_wh":read_f64(path.join("energy_now")).map(|value|round(value/1_000_000.0,3)),"energy_full_wh":read_f64(path.join("energy_full")).map(|value|round(value/1_000_000.0,3)),"voltage_volts":read_f64(path.join("voltage_now")).map(|value|round(value/1_000_000.0,3)),"cycle_count":read_i64(path.join("cycle_count")),"technology":read(path.join("technology")),"model":read(path.join("model_name"))}));
        }
    }
    json!({
        "available": !supplies.is_empty() || cpu_power_watts.is_some(),
        "supplies": supplies,
        "rapl": rapl.iter().map(|counter| json!({"name":counter.name,"power_watts":cpu_power_watts})).collect::<Vec<_>>()
    })
}

fn battery_snapshot(power: &Value) -> Value {
    power
        .get("supplies")
        .and_then(Value::as_array)
        .and_then(|items| {
            items
                .iter()
                .find(|item| item.get("type").and_then(Value::as_str) == Some("Battery"))
        })
        .cloned()
        .unwrap_or_else(|| json!({"available":false}))
}

#[derive(Clone, Default)]
struct ProcessCounters {
    ticks: u64,
    start_ticks: u64,
    rss_bytes: u64,
    name: String,
}

fn process_counters() -> HashMap<u32, ProcessCounters> {
    let mut processes = HashMap::new();
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(1) as u64;
    let Ok(entries) = fs::read_dir(PROC) else {
        return processes;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let Some(stat) = read(entry.path().join("stat")) else {
            continue;
        };
        let Some(open) = stat.find('(') else {
            continue;
        };
        let Some(close) = stat.rfind(')') else {
            continue;
        };
        let process_name = stat
            .get(open.saturating_add(1)..close)
            .unwrap_or_default()
            .to_owned();
        let fields: Vec<&str> = stat
            .get(close + 2..)
            .unwrap_or_default()
            .split_whitespace()
            .collect();
        let ticks = fields
            .get(11)
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or_default()
            .saturating_add(
                fields
                    .get(12)
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or_default(),
            );
        let rss_pages = fields
            .get(21)
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or_default();
        let start_ticks = fields
            .get(19)
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or_default();
        processes.insert(
            pid,
            ProcessCounters {
                ticks,
                start_ticks,
                rss_bytes: rss_pages.saturating_mul(page_size),
                name: process_name,
            },
        );
    }
    processes
}

fn process_snapshot(
    before: &HashMap<u32, ProcessCounters>,
    after: &HashMap<u32, ProcessCounters>,
    elapsed: f64,
    limit: usize,
    state: &mut CollectorState,
) -> Value {
    let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as f64;
    let now = now_epoch();
    let mut top: Vec<Value> = after
        .iter()
        .map(|(pid, current)| {
            let previous = before
                .get(pid)
                .filter(|previous| previous.start_ticks == current.start_ticks)
                .unwrap_or(current);
            let cpu = current.ticks.saturating_sub(previous.ticks) as f64 / ticks_per_second
                / elapsed
                * 100.0;
            let key = format!("{pid}:{}", current.start_ticks);
            let history = state.processes.entry(key).or_default();
            let average = if history.last_seen > 0.0 && now > history.last_seen {
                let interval = (now - history.last_seen).min(300.0);
                let alpha = 1.0 - (-interval / PROCESS_CPU_RESPONSE_SECONDS).exp();
                history.cpu_average_percent + alpha * (cpu - history.cpu_average_percent)
            } else {
                cpu
            };
            history.cpu_average_percent = average.max(0.0);
            history.last_seen = now;
            json!({"pid":pid,"name":current.name,"cpu_percent":round(cpu,1),"cpu_average_percent":round(history.cpu_average_percent,1),"rss_bytes":current.rss_bytes})
        })
        .collect();
    state
        .processes
        .retain(|_, history| now - history.last_seen <= 600.0);
    // Use the same (smoothed) CPU value on both sides of the comparison.
    // A raw/smoothed mix is not transitive and can make Rust's sort panic.
    // Quantising to the value actually published (one decimal place) also
    // gives a stable order for brief process spikes.
    top.sort_by_key(|process| {
        let cpu = process
            .get("cpu_average_percent")
            .and_then(Value::as_f64)
            .filter(|value| value.is_finite())
            .unwrap_or_default();
        let memory = process
            .get("rss_bytes")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let pid = process
            .get("pid")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        (
            std::cmp::Reverse((cpu * 10.0).round() as i64),
            std::cmp::Reverse(memory),
            pid,
        )
    });
    top.truncate(limit);
    json!({"available":true,"count":after.len(),"top":top})
}

fn uptime_snapshot() -> Value {
    let seconds = read(format!("{PROC}/uptime"))
        .and_then(|value| value.split_whitespace().next()?.parse::<f64>().ok())
        .unwrap_or_default();
    let hostname = hostname::get()
        .ok()
        .and_then(|name| name.into_string().ok())
        .unwrap_or_else(|| "unknown".into());
    let os = read("/etc/os-release")
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                line.strip_prefix("PRETTY_NAME=")
                    .map(|value| value.trim_matches('"').to_owned())
            })
        })
        .unwrap_or_else(|| std::env::consts::OS.to_owned());
    json!({"seconds":round(seconds,1),"boot_time_epoch":round(now_epoch()-seconds,1),"kernel":read(format!("{PROC}/sys/kernel/osrelease")),"hostname":hostname,"os":os,"architecture":std::env::consts::ARCH})
}

fn period_key(timestamp: f64, period: &str) -> String {
    let date = Local
        .timestamp_opt(timestamp as i64, 0)
        .single()
        .unwrap_or_else(Local::now);
    match period {
        "daily" => format!("{:04}-{:02}-{:02}", date.year(), date.month(), date.day()),
        "weekly" => {
            let week = date.iso_week();
            format!("{}-W{:02}", week.year(), week.week())
        }
        "monthly" => format!("{:04}-{:02}", date.year(), date.month()),
        _ => String::new(),
    }
}

fn trim_period(periods: &mut BTreeMap<String, TrafficBucket>, keep: usize) {
    while periods.len() > keep {
        let Some(oldest) = periods.keys().next().cloned() else {
            break;
        };
        periods.remove(&oldest);
    }
}

fn total_with_average(periods: &BTreeMap<String, TrafficBucket>, key: &str) -> Value {
    let current = periods.get(key).cloned().unwrap_or_default();
    let historical: Vec<&TrafficBucket> = periods
        .iter()
        .filter(|(period_key, _)| period_key.as_str() != key)
        .map(|(_, value)| value)
        .collect();
    let average = |field: fn(&TrafficBucket) -> u64| {
        (!historical.is_empty()).then(|| {
            historical.iter().map(|value| field(value)).sum::<u64>() / historical.len() as u64
        })
    };
    json!({"key":key,"rx_bytes":current.rx_bytes,"tx_bytes":current.tx_bytes,"rx_avg_bytes":average(|bucket|bucket.rx_bytes),"tx_avg_bytes":average(|bucket|bucket.tx_bytes)})
}

fn update_network_totals(
    state: &mut CollectorState,
    counters: &HashMap<String, NetCounters>,
) -> Value {
    let now = now_epoch();
    let boot_id = read_boot_id();
    let history = &mut state.network;
    if history.boot_id != boot_id {
        history.interfaces.clear();
        history.boot_id = boot_id;
    }
    for (name, current) in counters {
        if is_virtual_interface(name) {
            continue;
        }
        match history.interfaces.get(name) {
            Some(previous)
                if current.rx >= previous.rx_bytes && current.tx >= previous.tx_bytes =>
            {
                let rx_delta = current.rx - previous.rx_bytes;
                let tx_delta = current.tx - previous.tx_bytes;
                // Collection happens every few seconds. Assigning a boundary
                // straddling delta to its current period keeps history compact
                // while introducing at most one poll interval of drift.
                for (period, buckets) in [
                    ("daily", &mut history.daily),
                    ("weekly", &mut history.weekly),
                    ("monthly", &mut history.monthly),
                ] {
                    let bucket = buckets.entry(period_key(now, period)).or_default();
                    bucket.rx_bytes = bucket.rx_bytes.saturating_add(rx_delta);
                    bucket.tx_bytes = bucket.tx_bytes.saturating_add(tx_delta);
                }
            }
            _ => {}
        }
        history.interfaces.insert(
            name.clone(),
            NetworkInterfaceHistory {
                rx_bytes: current.rx,
                tx_bytes: current.tx,
                updated_at: now,
            },
        );
    }
    history
        .interfaces
        .retain(|name, _| counters.contains_key(name));
    let daily_key = period_key(now, "daily");
    let weekly_key = period_key(now, "weekly");
    let monthly_key = period_key(now, "monthly");
    history.daily.entry(daily_key.clone()).or_default();
    history.weekly.entry(weekly_key.clone()).or_default();
    history.monthly.entry(monthly_key.clone()).or_default();
    trim_period(&mut history.daily, 45);
    trim_period(&mut history.weekly, 16);
    trim_period(&mut history.monthly, 18);
    json!({"daily":total_with_average(&history.daily,&daily_key),"weekly":total_with_average(&history.weekly,&weekly_key),"monthly":total_with_average(&history.monthly,&monthly_key)})
}

fn number_at(data: &Value, pointer: &str) -> Option<f64> {
    data.pointer(pointer)
        .and_then(Value::as_f64)
        .filter(|value| finite(*value))
}

fn enrich_history(
    snapshot: &mut Value,
    state: &mut CollectorState,
    net_counters: &HashMap<String, NetCounters>,
) {
    let cpu_usage = number_at(snapshot, "/cpu/usage_percent");
    let cpu_power = number_at(snapshot, "/cpu/power_watts");
    let memory = number_at(snapshot, "/memory/usage_percent");
    let swap = number_at(snapshot, "/memory/swap/usage_percent");
    let gpu = number_at(snapshot, "/gpu/devices/0/usage_percent");
    let vram = number_at(snapshot, "/gpu/devices/0/vram_usage_percent");
    let cpu_temp = number_at(snapshot, "/temperature/cpu_current_celsius");
    let gpu_temp = number_at(snapshot, "/temperature/hardware/gpu/current_celsius");
    let storage_temp = number_at(snapshot, "/temperature/hardware/storage/current_celsius");
    let download = number_at(snapshot, "/network/download_bytes_per_sec");
    let upload = number_at(snapshot, "/network/upload_bytes_per_sec");
    let disk_read = number_at(snapshot, "/disk/total_read_bytes_per_sec");
    let disk_write = number_at(snapshot, "/disk/total_write_bytes_per_sec");

    snapshot["cpu"]["usage_average_percent"] = metric_averages(state, "cpu_usage", cpu_usage);
    snapshot["cpu"]["power_watts_average"] = metric_averages(state, "cpu_power", cpu_power);
    snapshot["memory"]["usage_average_percent"] = metric_averages(state, "memory_usage", memory);
    snapshot["memory"]["swap"]["usage_average_percent"] =
        metric_averages(state, "swap_usage", swap);
    snapshot["gpu"]["usage_average_percent"] = metric_averages(state, "gpu_usage", gpu);
    snapshot["gpu"]["vram_average_percent"] = metric_averages(state, "vram_usage", vram);
    snapshot["network"]["download_average"] = metric_averages(state, "network_download", download);
    snapshot["network"]["upload_average"] = metric_averages(state, "network_upload", upload);
    snapshot["disk"]["read_average"] = metric_averages(state, "disk_read", disk_read);
    snapshot["disk"]["write_average"] = metric_averages(state, "disk_write", disk_write);
    snapshot["network"]["totals"] = update_network_totals(state, net_counters);

    for (metric_key, pointer, current) in [
        ("cpu_temperature", "/temperature", cpu_temp),
        ("gpu_temperature", "/temperature/hardware/gpu", gpu_temp),
        (
            "storage_temperature",
            "/temperature/hardware/storage",
            storage_temp,
        ),
    ] {
        let averages = metric_averages(state, metric_key, current);
        if let Some(current) = current {
            let maximum = state
                .maximums
                .entry(metric_key.to_owned())
                .or_insert(current);
            *maximum = maximum.max(current);
            if let Some(target) = snapshot.pointer_mut(pointer) {
                target["average_celsius"] = averages["overall"].clone();
                target["maximum_celsius"] = json!(round(*maximum, 1));
            }
        }
    }
}

fn snapshot(args: &SnapshotArgs, state: &mut CollectorState) -> Value {
    let window = args.sample_window.clamp(0.05, 2.0);
    let cpu_before = cpu_times();
    let rapl_before = rapl_counters();
    let disk_before = disk_counters();
    let net_before = net_counters();
    let process_before = process_counters();
    let started = std::time::Instant::now();
    thread::sleep(Duration::from_secs_f64(window));
    let elapsed = started.elapsed().as_secs_f64().max(0.001);
    let cpu_after = cpu_times();
    let rapl_after = rapl_counters();
    let disk_after = disk_counters();
    let net_after = net_counters();
    let process_after = process_counters();
    let cpu_power_watts = rapl_power_watts(&rapl_before, &rapl_after, elapsed);
    let power = power_snapshot(cpu_power_watts, &rapl_after);
    let mut snapshot = json!({
        "schema_version":1,"timestamp":now_epoch(),"sample_window_seconds":round(elapsed,3),"uptime":uptime_snapshot(),
        "cpu":cpu_snapshot(&cpu_before,&cpu_after,cpu_power_watts),"memory":memory_snapshot(),"temperature":temperature_snapshot(),
        "power":power,"battery":battery_snapshot(&power),"gpu":gpu_snapshot(),"disk":disk_snapshot(&disk_before,&disk_after,elapsed),
        "network":network_snapshot(&net_before,&net_after,elapsed),"processes":process_snapshot(&process_before,&process_after,elapsed,args.process_limit,state)
    });
    enrich_history(&mut snapshot, state, &net_after);
    snapshot
}

fn default_config_path() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("syslens/config.toml")
}

fn validate_config(config: &RuntimeConfig) -> Result<(), String> {
    if config.agent.host_id.is_empty()
        || !config
            .agent
            .host_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        return Err(
            "agent.host_id may contain only letters, numbers, underscores, and hyphens".into(),
        );
    }
    if !config.agent.interval_seconds.is_finite() || config.agent.interval_seconds < 0.5 {
        return Err("agent.interval_seconds must be at least 0.5".into());
    }
    if !config.agent.sample_window_seconds.is_finite() || config.agent.sample_window_seconds < 0.05
    {
        return Err("agent.sample_window_seconds must be at least 0.05".into());
    }
    if config.agent.sample_window_seconds > config.agent.interval_seconds {
        return Err("agent.sample_window_seconds must not exceed agent.interval_seconds".into());
    }
    if config.collection.process_limit > 1000 {
        return Err("collection.process_limit must not exceed 1000".into());
    }
    if config.mqtt.host.trim().is_empty() {
        return Err("mqtt.host is required with --publish".into());
    }
    if config.mqtt.topic_prefix.trim_matches('/').is_empty()
        || config.mqtt.topic_prefix.split('/').any(str::is_empty)
    {
        return Err("mqtt.topic_prefix must contain non-empty topic segments".into());
    }
    if !(0..=2).contains(&config.mqtt.qos) {
        return Err("mqtt.qos must be 0, 1, or 2".into());
    }
    if config.mqtt.keepalive_seconds == 0 {
        return Err("mqtt.keepalive_seconds must be at least 1".into());
    }
    if config.mqtt.password_env.is_some() && config.mqtt.username.is_none() {
        return Err("mqtt.username is required when mqtt.password_env is set".into());
    }
    Ok(())
}

fn load_config(path: &Path) -> Result<RuntimeConfig, String> {
    let raw = fs::read_to_string(path).map_err(|error| {
        format!(
            "could not read configuration file {}: {error}",
            path.display()
        )
    })?;
    let config: RuntimeConfig = toml::from_str(&raw)
        .map_err(|error| format!("invalid TOML in {}: {error}", path.display()))?;
    validate_config(&config)?;
    Ok(config)
}

fn qos(value: u8) -> QoS {
    match value {
        0 => QoS::AtMostOnce,
        1 => QoS::AtLeastOnce,
        _ => QoS::ExactlyOnce,
    }
}

fn topic_base(config: &RuntimeConfig) -> String {
    format!(
        "{}/{}",
        config.mqtt.topic_prefix.trim_matches('/'),
        config.agent.host_id
    )
}

fn redacted_config(path: &Path, config: &RuntimeConfig) -> Value {
    json!({
        "valid": true,
        "path": path,
        "agent": {"host_id":config.agent.host_id,"interval_seconds":config.agent.interval_seconds,"sample_window_seconds":config.agent.sample_window_seconds},
        "collection": {"process_limit":config.collection.process_limit},
        "mqtt": {"host":config.mqtt.host,"port":config.mqtt.port,"topic_prefix":config.mqtt.topic_prefix.trim_matches('/'),"username_configured":config.mqtt.username.is_some(),"password_env_configured":config.mqtt.password_env.is_some(),"client_id":config.mqtt.client_id.clone().unwrap_or_else(||format!("syslens-{}",config.agent.host_id)),"tls":config.mqtt.tls,"qos":config.mqtt.qos,"retain":config.mqtt.retain}
    })
}

struct ConnectionControl {
    stop: Arc<AtomicBool>,
    join: thread::JoinHandle<()>,
}

fn create_client(config: &RuntimeConfig) -> Result<(Client, ConnectionControl), String> {
    let base = topic_base(config);
    let client_id = config
        .mqtt
        .client_id
        .clone()
        .unwrap_or_else(|| format!("syslens-{}", config.agent.host_id));
    let mut options = MqttOptions::new(client_id, &config.mqtt.host, config.mqtt.port);
    options.set_keep_alive(Duration::from_secs(config.mqtt.keepalive_seconds));
    options.set_last_will(LastWill::new(
        format!("{base}/availability"),
        "offline",
        qos(config.mqtt.qos),
        true,
    ));
    if let Some(username) = &config.mqtt.username {
        let password = match &config.mqtt.password_env {
            Some(name) => std::env::var(name).map_err(|_| {
                format!("environment variable {name} named by mqtt.password_env is not set")
            })?,
            None => String::new(),
        };
        options.set_credentials(username, password);
    }
    if config.mqtt.tls {
        options.set_transport(Transport::tls_with_default_config());
    }
    let (client, mut connection) = Client::new(options, 16);
    let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let join = thread::spawn(move || {
        let mut announced = false;
        for event in connection.iter() {
            if worker_stop.load(Ordering::Relaxed) {
                break;
            }
            match event {
                Ok(Event::Incoming(Packet::ConnAck(_))) if !announced => {
                    announced = true;
                    let _ = ready_sender.send(Ok(()));
                }
                Err(error) if !announced => {
                    announced = true;
                    let _ = ready_sender.send(Err(error.to_string()));
                }
                Err(error) => {
                    eprintln!("syslens: MQTT connection stopped: {error}");
                    break;
                }
                _ => {}
            }
        }
    });
    match ready_receiver.recv_timeout(Duration::from_secs(10)) {
        Ok(Ok(())) => Ok((client, ConnectionControl { stop, join })),
        Ok(Err(error)) => {
            stop.store(true, Ordering::Relaxed);
            drop(client);
            let _ = join.join();
            Err(format!(
                "could not connect to MQTT broker {}:{}: {error}",
                config.mqtt.host, config.mqtt.port
            ))
        }
        Err(_) => {
            stop.store(true, Ordering::Relaxed);
            drop(client);
            let _ = join.join();
            Err(format!(
                "timed out connecting to MQTT broker {}:{}",
                config.mqtt.host, config.mqtt.port
            ))
        }
    }
}

fn publish(
    client: &Client,
    topic: String,
    payload: impl Into<Vec<u8>>,
    config: &RuntimeConfig,
    retain: bool,
) -> Result<(), String> {
    client
        .publish(topic, qos(config.mqtt.qos), retain, payload)
        .map_err(|error| format!("MQTT publish failed: {error}"))
}

fn metadata(config: &RuntimeConfig) -> Value {
    json!({"schema_version":1,"host_id":config.agent.host_id,"hostname":hostname::get().ok().and_then(|name|name.into_string().ok()).unwrap_or_else(||"unknown".into()),"platform":format!("{} {}",std::env::consts::OS,std::env::consts::ARCH),"publisher":"syslens-core","published_at":now_epoch()})
}

fn publish_snapshot(
    client: &Client,
    config: &RuntimeConfig,
    args: &SnapshotArgs,
    state: &mut CollectorState,
) -> Result<(), String> {
    let mut data = snapshot(args, state);
    data["source"] = json!({"host_id":config.agent.host_id,"hostname":hostname::get().ok().and_then(|name|name.into_string().ok()).unwrap_or_else(||"unknown".into()),"transport":"mqtt"});
    publish(
        client,
        format!("{}/state", topic_base(config)),
        serde_json::to_vec(&data).map_err(|error| error.to_string())?,
        config,
        config.mqtt.retain,
    )
}

fn run_agent(config: RuntimeConfig, once: bool) -> Result<(), String> {
    let (client, connection) = create_client(&config)?;
    let base = topic_base(&config);
    publish(
        &client,
        format!("{base}/meta"),
        serde_json::to_vec(&metadata(&config)).map_err(|error| error.to_string())?,
        &config,
        true,
    )?;
    publish(
        &client,
        format!("{base}/availability"),
        "online",
        &config,
        true,
    )?;
    let args = SnapshotArgs {
        sample_window: config.agent.sample_window_seconds,
        process_limit: config.collection.process_limit,
    };
    let mut state = load_state();
    let mut last_state_save = std::time::Instant::now() - Duration::from_secs(60);
    let mut next = std::time::Instant::now();
    let result = loop {
        if let Err(error) = publish_snapshot(&client, &config, &args, &mut state) {
            break Err(error);
        }
        if once || last_state_save.elapsed() >= Duration::from_secs(60) {
            save_state(&state);
            last_state_save = std::time::Instant::now();
        }
        if once {
            break Ok(());
        }
        next += Duration::from_secs_f64(config.agent.interval_seconds);
        thread::sleep(next.saturating_duration_since(std::time::Instant::now()));
    };
    // The synchronous client queues publishes for the connection thread.  Give
    // a one-shot diagnostic publish a chance to cross the socket before its
    // deliberately clean shutdown switches availability to offline.
    if once {
        thread::sleep(Duration::from_secs(1));
    }
    let _ = publish(
        &client,
        format!("{base}/availability"),
        "offline",
        &config,
        true,
    );
    let _ = client.disconnect();
    connection.stop.store(true, Ordering::Relaxed);
    let _ = connection.join.join();
    result
}

fn prompt(label: &str, default: Option<&str>) -> Result<String, String> {
    match default {
        Some(value) => print!("{label} [{value}]: "),
        None => print!("{label}: "),
    }
    io::stdout().flush().map_err(|error| error.to_string())?;
    let mut response = String::new();
    io::stdin()
        .read_line(&mut response)
        .map_err(|error| error.to_string())?;
    let response = response.trim();
    Ok(if response.is_empty() {
        default.unwrap_or_default().to_owned()
    } else {
        response.to_owned()
    })
}

fn prompt_yes_no(label: &str, default: bool) -> Result<bool, String> {
    loop {
        let answer = prompt(
            &format!("{label} ({})", if default { "Y/n" } else { "y/N" }),
            None,
        )?;
        if answer.is_empty() {
            return Ok(default);
        }
        match answer.to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => eprintln!("Please answer y or n."),
        }
    }
}

fn write_private(path: &Path, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|error| error.to_string())?;
        }
    }
    fs::write(path, content).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

const INVENTORY_EXECUTABLE: &str = "/usr/local/libexec/syslens/syslens-inventory";
const INVENTORY_CACHE: &str = "/var/cache/syslens/hardware-inventory.json";
const INVENTORY_SERVICE: &str = "[Unit]\nDescription=SysLens hardware inventory probe\n\n[Service]\nType=oneshot\nExecStart=/usr/local/libexec/syslens/syslens-inventory inventory probe --output /var/cache/syslens/hardware-inventory.json\nUMask=0022\nCacheDirectory=syslens\nNoNewPrivileges=true\nPrivateTmp=true\nProtectHome=true\nProtectSystem=strict\n\n";
const INVENTORY_TIMER: &str = "[Unit]\nDescription=Refresh SysLens hardware inventory\n\n[Timer]\nOnBootSec=90s\nOnUnitActiveSec=15min\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n";

fn root_nvme_health() -> Option<NvmeHealth> {
    let device = root_block_device()?;
    let name = device.file_name()?.to_str()?;
    nvme_health_for_block_device(name)
}

fn write_inventory_cache(output: &Path) -> Result<(), String> {
    let ram = collected_ram_inventory();
    let document = HardwareInventory {
        schema_version: 1,
        collected_at: now_epoch(),
        ram,
        disk_health: root_nvme_health(),
    };
    let rendered = serde_json::to_vec(&document).map_err(|error| error.to_string())?;
    let parent = output.parent().ok_or_else(|| {
        format!(
            "inventory output {} has no parent directory",
            output.display()
        )
    })?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o755))
            .map_err(|error| error.to_string())?;
    }
    let temporary = output.with_extension("tmp");
    fs::write(&temporary, rendered).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o644))
            .map_err(|error| error.to_string())?;
    }
    fs::rename(&temporary, output).map_err(|error| error.to_string())
}

fn run_sudo(arguments: &[String]) -> Result<(), String> {
    let status = ProcessCommand::new("sudo")
        .args(arguments)
        .status()
        .map_err(|error| format!("could not start sudo: {error}"))?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| format!("sudo {} failed", arguments.join(" ")))
}

fn run_inventory_enable() -> Result<(), String> {
    let has_dmi = Path::new("/sys/firmware/dmi/tables/DMI").exists();
    let has_root_nvme = root_block_device()
        .and_then(|device| {
            device
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned)
        })
        .is_some_and(|name| nvme_controller_for_block_device(&name).is_some());
    if !has_dmi && !has_root_nvme {
        println!(
            "This host exposes neither DMI RAM data nor an NVMe root disk for managed hardware inventory."
        );
        return Ok(());
    }
    if has_dmi && !Path::new("/usr/sbin/dmidecode").exists() && !has_root_nvme {
        return Err("dmidecode is required for detailed RAM inventory but is not installed".into());
    }
    println!(
        "SysLens will request your system password once to install its root-owned, read-only hardware inventory timer."
    );
    run_sudo(&["-v".into()])?;

    let staging = std::env::temp_dir().join(format!("syslens-inventory-{}", std::process::id()));
    fs::create_dir_all(&staging).map_err(|error| error.to_string())?;
    let service_path = staging.join("syslens-hardware-inventory.service");
    let timer_path = staging.join("syslens-hardware-inventory.timer");
    let preparation = (|| -> Result<(), String> {
        fs::write(&service_path, INVENTORY_SERVICE).map_err(|error| error.to_string())?;
        fs::write(&timer_path, INVENTORY_TIMER).map_err(|error| error.to_string())?;
        let executable = std::env::current_exe().map_err(|error| error.to_string())?;
        let install = |source: &Path, destination: &str, mode: &str| {
            run_sudo(&[
                "install".into(),
                "-D".into(),
                "-o".into(),
                "root".into(),
                "-g".into(),
                "root".into(),
                "-m".into(),
                mode.into(),
                source.display().to_string(),
                destination.into(),
            ])
        };
        install(&executable, INVENTORY_EXECUTABLE, "755")?;
        install(
            &service_path,
            "/etc/systemd/system/syslens-hardware-inventory.service",
            "644",
        )?;
        install(
            &timer_path,
            "/etc/systemd/system/syslens-hardware-inventory.timer",
            "644",
        )?;
        run_sudo(&["systemctl".into(), "daemon-reload".into()])?;
        run_sudo(&[
            "systemctl".into(),
            "enable".into(),
            "--now".into(),
            "syslens-hardware-inventory.timer".into(),
        ])?;
        run_sudo(&[
            "systemctl".into(),
            "start".into(),
            "syslens-hardware-inventory.service".into(),
        ])
    })();
    let _ = fs::remove_dir_all(staging);
    preparation?;
    println!(
        "Managed hardware inventory is enabled. SysLens refreshes RAM details and NVMe health every 15 minutes without further passwords."
    );
    Ok(())
}

fn run_inventory_disable() -> Result<(), String> {
    let timer_path = Path::new("/etc/systemd/system/syslens-hardware-inventory.timer");
    if !timer_path.exists() {
        println!("Managed hardware inventory is not enabled on this host.");
        return Ok(());
    }

    println!(
        "SysLens will request your system password once to stop managed hardware inventory and clear its cached data."
    );
    run_sudo(&["-v".into()])?;
    run_sudo(&[
        "systemctl".into(),
        "disable".into(),
        "--now".into(),
        "syslens-hardware-inventory.timer".into(),
    ])?;
    run_sudo(&["rm".into(), "-f".into(), INVENTORY_CACHE.into()])?;
    run_sudo(&[
        "systemctl".into(),
        "reset-failed".into(),
        "syslens-hardware-inventory.service".into(),
    ])?;
    println!("Managed hardware inventory is disabled and its cached data was removed.");
    Ok(())
}

fn run_inventory_status() -> Result<(), String> {
    match fs::read_to_string(hardware_inventory_path()) {
        Ok(raw) => {
            let inventory: HardwareInventory = serde_json::from_str(&raw)
                .map_err(|error| format!("invalid managed hardware inventory: {error}"))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&inventory).map_err(|error| error.to_string())?
            );
        }
        Err(_) => println!("No managed hardware inventory has been collected on this host."),
    }
    Ok(())
}

fn escape_toml(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn offer_hardware_inventory_setup() -> Result<(), String> {
    let has_dmi = Path::new("/sys/firmware/dmi/tables/DMI").exists();
    let has_root_nvme = root_block_device()
        .and_then(|device| {
            device
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned)
        })
        .is_some_and(|name| nvme_controller_for_block_device(&name).is_some());
    if (!has_dmi && !has_root_nvme)
        || !prompt_yes_no("Enable managed RAM and NVMe hardware inventory", true)?
    {
        return Ok(());
    }
    match run_inventory_enable() {
        Ok(()) => Ok(()),
        Err(error) => {
            eprintln!(
                "Hardware inventory was not enabled: {error}\nYou can retry later with `syslens inventory enable`."
            );
            Ok(())
        }
    }
}

fn run_setup(target: PathBuf) -> Result<(), String> {
    println!(
        "SysLens setup\n\nLocal Plasma monitoring needs no configuration. MQTT mode publishes snapshots for Home Assistant or other receivers."
    );
    if !prompt_yes_no("Configure MQTT publishing", true)? {
        offer_hardware_inventory_setup()?;
        println!("No configuration written. Use `syslens snapshot --json` for local telemetry.");
        return Ok(());
    }
    let host_id = prompt("Stable host ID", Some(&default_host_id()))?;
    if host_id.is_empty()
        || !host_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        return Err("Host ID may contain only letters, numbers, underscores, and hyphens.".into());
    }
    let broker = prompt("MQTT broker host or IP", None)?;
    if broker.is_empty() {
        return Err("MQTT broker host is required.".into());
    }
    let port = prompt("MQTT broker port", Some("1883"))?
        .parse::<u16>()
        .map_err(|_| "MQTT broker port must be between 1 and 65535.".to_owned())?;
    let interval = prompt("Publish interval in seconds", Some("5"))?
        .parse::<f64>()
        .map_err(|_| "Publish interval must be a number.".to_owned())?;
    if interval < 0.5 {
        return Err("Publish interval must be at least 0.5 seconds.".into());
    }
    let process_limit = prompt("Top-process entries per snapshot", Some("6"))?
        .parse::<usize>()
        .map_err(|_| "Process limit must be an integer.".to_owned())?;
    let username = prompt("MQTT username (leave blank for anonymous broker)", None)?;
    let password = if username.is_empty() {
        String::new()
    } else {
        rpassword::prompt_password("MQTT password (stored only in syslens.env): ")
            .map_err(|error| error.to_string())?
    };
    let tls = prompt_yes_no("Use TLS for this MQTT connection", false)?;
    let mut text = format!(
        "# Created by `syslens setup`. Passwords are kept in syslens.env.\n\n[agent]\nhost_id = \"{}\"\ninterval_seconds = {interval}\nsample_window_seconds = 0.35\n\n[collection]\nprocess_limit = {process_limit}\n\n[mqtt]\nhost = \"{}\"\nport = {port}\ntopic_prefix = \"syslens\"\ntls = {tls}\nkeepalive_seconds = 60\nqos = 1\nretain = true\n",
        escape_toml(&host_id),
        escape_toml(&broker)
    );
    if !username.is_empty() {
        text.push_str(&format!(
            "username = \"{}\"\npassword_env = \"SYSLENS_MQTT_PASSWORD\"\n",
            escape_toml(&username)
        ));
    }
    write_private(&target, &text)?;
    if !password.is_empty() {
        write_private(
            &target.with_file_name("syslens.env"),
            &format!("SYSLENS_MQTT_PASSWORD={}\n", password.replace('\n', "")),
        )?;
    }
    offer_hardware_inventory_setup()?;
    let config = load_config(&target)?;
    println!(
        "\nConfiguration written to {}\nTopics: {}/{{meta,state,availability}}\n\nNext steps:\n  syslens --config {} --validate-config\n  syslens --config {} --publish --once\n  syslens --config {} --publish",
        target.display(),
        topic_base(&config),
        target.display(),
        target.display(),
        target.display()
    );
    Ok(())
}

fn print_snapshot(args: &SnapshotArgs, pretty: bool) -> Result<(), String> {
    let mut state = load_state();
    let data = snapshot(args, &mut state);
    save_state(&state);
    let rendered = if pretty {
        serde_json::to_string_pretty(&data)
    } else {
        serde_json::to_string(&data)
    }
    .map_err(|error| error.to_string())?;
    println!("{rendered}");
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Some(Command::Snapshot(args)) => print_snapshot(&args, cli.pretty),
        Some(Command::Setup { config }) => run_setup(config.unwrap_or_else(default_config_path)),
        Some(Command::Agent(agent)) => {
            load_config(&agent.config).and_then(|config| run_agent(config, agent.once))
        }
        Some(Command::Inventory { command }) => match command {
            InventoryCommand::Enable => run_inventory_enable(),
            InventoryCommand::Disable => run_inventory_disable(),
            InventoryCommand::Probe { output } => write_inventory_cache(&output),
            InventoryCommand::Status => run_inventory_status(),
        },
        None if cli.setup => run_setup(cli.setup_config.unwrap_or_else(default_config_path)),
        None if cli.validate_config => match cli.config.as_deref() {
            Some(path) => load_config(path).and_then(|config| {
                serde_json::to_string_pretty(&redacted_config(path, &config))
                    .map_err(|error| error.to_string())
                    .map(|text| println!("{text}"))
            }),
            None => Err("--validate-config requires --config".into()),
        },
        None if cli.publish => match cli.config.as_deref() {
            Some(path) => load_config(path).and_then(|config| run_agent(config, cli.once)),
            None => Err("--publish requires --config".into()),
        },
        None => print_snapshot(&cli.snapshot, cli.pretty),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("syslens: {error}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MetricHistory, MetricSample, active_dpm_clock_mhz, cpu_list_count, dmi_memory_inventory,
        migrate_metric_history, parse_nvme_smart_log, weighted_bucket_average,
    };

    #[test]
    fn counts_sparse_cpu_lists() {
        assert_eq!(cpu_list_count("0-1,3-7"), Some(7));
        assert_eq!(cpu_list_count("0-7"), Some(8));
        assert_eq!(cpu_list_count("0,2,4"), Some(3));
    }

    #[test]
    fn reads_populated_dmi_memory_slots() {
        let inventory = dmi_memory_inventory(
            "Handle 0x0018, DMI type 17, 92 bytes\nMemory Device\n\tSize: 16 GB\n\tForm Factor: SODIMM\n\tLocator: DIMM 0\n\tBank Locator: P0 CHANNEL A\n\tManufacturer: Kingston\n\tPart Number: KVR56S46BS8-16\n\tType: DDR5\n\tSpeed: 5600 MT/s\n\tConfigured Memory Speed: 5600 MT/s\n\nHandle 0x0019, DMI type 17, 92 bytes\nMemory Device\n\tSize: No Module Installed\n\tForm Factor: SODIMM\n\tLocator: DIMM 1\n\tBank Locator: P0 CHANNEL B\n\tManufacturer: Not Specified\n\tType: Unknown\n\tSpeed: Unknown\n",
        )
        .expect("DMI memory inventory should parse");
        assert_eq!(inventory.manufacturer.as_deref(), Some("Kingston"));
        assert_eq!(inventory.ram_type.as_deref(), Some("DDR5"));
        assert_eq!(inventory.slots_populated, Some(1));
        assert_eq!(inventory.slots_total, Some(2));
        assert_eq!(inventory.nominal_data_rate.as_deref(), Some("5600 MT/s"));
        assert_eq!(inventory.model.as_deref(), Some("KVR56S46BS8-16"));
        assert_eq!(inventory.modules.len(), 1);
        assert_eq!(inventory.modules[0].slot, "DIMM 0");
        assert_eq!(
            inventory.modules[0].model.as_deref(),
            Some("KVR56S46BS8-16")
        );
    }

    #[test]
    fn summarizes_matching_and_mixed_dimm_models() {
        let matching = dmi_memory_inventory(
            "Memory Device\n\tSize: 16 GB\n\tLocator: DIMM A\n\tPart Number: M425R2GA3BB0-CWM\n\tType: DDR5\n\tSpeed: 5600 MT/s\n\nMemory Device\n\tSize: 16 GB\n\tLocator: DIMM B\n\tPart Number: M425R2GA3BB0-CWM\n\tType: DDR5\n\tSpeed: 5600 MT/s\n",
        )
        .expect("matching DIMMs should parse");
        assert_eq!(matching.model.as_deref(), Some("2 × M425R2GA3BB0-CWM"));

        let mixed = dmi_memory_inventory(
            "Memory Device\n\tSize: 16 GB\n\tLocator: DIMM A\n\tPart Number: M425R2GA3BB0-CWM\n\nMemory Device\n\tSize: 16 GB\n\tLocator: DIMM B\n\tPart Number: CT16G56C46S5\n",
        )
        .expect("mixed DIMMs should parse");
        assert_eq!(
            mixed.model.as_deref(),
            Some("DIMM A: M425R2GA3BB0-CWM · DIMM B: CT16G56C46S5")
        );
    }

    #[test]
    fn reads_standard_nvme_health_log() {
        let mut log = [0_u8; 512];
        log[5] = 7;
        log[48] = 2;
        log[128] = 42;
        let health = parse_nvme_smart_log(&log).expect("SMART log should parse");
        assert_eq!(health.remaining_percent, Some(93));
        assert_eq!(health.data_written_bytes, Some(1_024_000));
        assert_eq!(health.power_on_hours, Some(42));
        assert_eq!(health.critical_warning.as_deref(), Some("No warnings"));
    }

    #[test]
    fn reads_active_gpu_dpm_clock() {
        assert_eq!(
            active_dpm_clock_mhz("0: 200Mhz\n1: 400Mhz *\n2: 1800Mhz"),
            Some(400.0)
        );
    }

    #[test]
    fn migrates_legacy_metric_samples_to_weighted_buckets() {
        let mut history = MetricHistory {
            samples: vec![
                MetricSample {
                    t: 1_000.0,
                    v: 10.0,
                    n: 2,
                },
                MetricSample {
                    t: 1_100.0,
                    v: 20.0,
                    n: 1,
                },
            ],
            running_n: 10,
            running_mean: 12.5,
            ..Default::default()
        };
        migrate_metric_history(&mut history);
        assert!(history.samples.is_empty());
        assert_eq!(history.hourly.len(), 1);
        assert_eq!(history.daily.len(), 1);
        assert_eq!(history.all_time.n, 10);
        assert_eq!(history.all_time.mean, 12.5);
        assert_eq!(weighted_bucket_average(history.hourly.values()), Some(13.3));
    }
}
