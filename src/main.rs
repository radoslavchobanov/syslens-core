use clap::{Args, Parser, Subcommand};
use rumqttc::{Client, Event, LastWill, MqttOptions, Packet, QoS, Transport};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{self, Write};
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const PROC: &str = "/proc";
const SYS: &str = "/sys";
const SECTOR_BYTES: f64 = 512.0;

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

fn cpu_snapshot(before: &[Vec<u64>], after: &[Vec<u64>]) -> Value {
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
    let logical = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or_else(|_| per_core.len().max(1));
    let model = info
        .get("model name")
        .or_else(|| info.get("Hardware"))
        .or_else(|| info.get("Processor"))
        .cloned()
        .unwrap_or_else(|| "Unknown CPU".into());
    let vendor = info
        .get("vendor_id")
        .or_else(|| info.get("CPU implementer"))
        .cloned();
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
        "logical_cores": logical, "physical_cores": physical_core_count(&info).unwrap_or(logical), "flags": Vec::<String>::new(),
        "microcode": info.get("microcode"), "cache": info.get("cache size"), "usage_percent": usage,
        "per_core_percent": per_core, "current_mhz_avg": cpufreq["current_mhz_avg"],
        "current_mhz_min": cpufreq["current_mhz_min"], "current_mhz_max": cpufreq["current_mhz_max"],
        "cpufreq": cpufreq, "load_average": load_average(), "power_watts": Value::Null,
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
    json!({"available":!devices.is_empty(),"root":root_usage(),"total_read_bytes_per_sec":round(read_total,1),"total_write_bytes_per_sec":round(write_total,1),"devices":devices})
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
            devices.push(json!({"name":name,"vendor_id":read(device.join("vendor")),"device_id":read(device.join("device")),"label":label,"usage_percent":usage.map(|value|round(value,1)),"vram_used_bytes":used,"vram_total_bytes":total,"vram_usage_percent":match (used,total) {(Some(used),Some(total)) => pct(used as f64,total as f64), _ => None}}));
        }
    }
    json!({"available":!devices.is_empty(),"devices":devices,"usage_average_percent":{"period1":Value::Null,"period2":Value::Null,"overall":Value::Null},"vram_average_percent":{"period1":Value::Null,"period2":Value::Null,"overall":Value::Null}})
}

fn power_snapshot() -> Value {
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
    json!({"available":!supplies.is_empty(),"supplies":supplies,"rapl":[]})
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
        let Some(close) = stat.rfind(')') else {
            continue;
        };
        let process_name = stat.get(1..close).unwrap_or_default().to_owned();
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
        processes.insert(
            pid,
            ProcessCounters {
                ticks,
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
) -> Value {
    let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as f64;
    let mut top: Vec<Value> = after.iter().map(|(pid, current)| {
        let previous = before.get(pid).unwrap_or(current);
        let cpu = current.ticks.saturating_sub(previous.ticks) as f64 / ticks_per_second / elapsed * 100.0;
        json!({"pid":pid,"name":current.name,"cpu_percent":round(cpu,1),"rss_bytes":current.rss_bytes})
    }).collect();
    top.sort_by(|left, right| {
        right
            .get("cpu_percent")
            .and_then(Value::as_f64)
            .unwrap_or_default()
            .total_cmp(
                &left
                    .get("cpu_percent")
                    .and_then(Value::as_f64)
                    .unwrap_or_default(),
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
    json!({"seconds":round(seconds,1),"boot_time_epoch":round(now_epoch()-seconds,1),"kernel":read(format!("{PROC}/sys/kernel/osrelease")),"hostname":hostname,"os":std::env::consts::OS})
}

fn snapshot(args: &SnapshotArgs) -> Value {
    let window = args.sample_window.clamp(0.05, 2.0);
    let cpu_before = cpu_times();
    let disk_before = disk_counters();
    let net_before = net_counters();
    let process_before = process_counters();
    let started = std::time::Instant::now();
    thread::sleep(Duration::from_secs_f64(window));
    let elapsed = started.elapsed().as_secs_f64().max(0.001);
    let cpu_after = cpu_times();
    let disk_after = disk_counters();
    let net_after = net_counters();
    let process_after = process_counters();
    let power = power_snapshot();
    json!({
        "schema_version":1,"timestamp":now_epoch(),"sample_window_seconds":round(elapsed,3),"uptime":uptime_snapshot(),
        "cpu":cpu_snapshot(&cpu_before,&cpu_after),"memory":memory_snapshot(),"temperature":temperature_snapshot(),
        "power":power,"battery":battery_snapshot(&power),"gpu":gpu_snapshot(),"disk":disk_snapshot(&disk_before,&disk_after,elapsed),
        "network":network_snapshot(&net_before,&net_after,elapsed),"processes":process_snapshot(&process_before,&process_after,elapsed,args.process_limit)
    })
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
) -> Result<(), String> {
    let mut data = snapshot(args);
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
    let mut next = std::time::Instant::now();
    let result = loop {
        if let Err(error) = publish_snapshot(&client, &config, &args) {
            break Err(error);
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

fn escape_toml(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn run_setup(target: PathBuf) -> Result<(), String> {
    println!(
        "SysLens setup\n\nLocal Plasma monitoring needs no configuration. MQTT mode publishes snapshots for Home Assistant or other receivers."
    );
    if !prompt_yes_no("Configure MQTT publishing", true)? {
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
    let data = snapshot(args);
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
