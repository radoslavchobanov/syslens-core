//! Stateful counter sampling. Each source uses its own read midpoint; processes
//! use per-PID stat-read midpoints so scan order and scan duration do not bias CPU.
use crate::*;
use std::time::Instant;

pub(crate) fn validate_window(value: f64) -> Result<f64, String> {
    if value.is_finite() && (0.05..=2.0).contains(&value) {
        Ok(value)
    } else {
        Err("sample window must be finite and between 0.05 and 2 seconds".into())
    }
}

pub(crate) fn parse_window(value: &str) -> Result<f64, String> {
    validate_window(value.parse::<f64>().map_err(|error| error.to_string())?)
}

pub(crate) fn next_deadline(previous: Instant, now: Instant, interval: Duration) -> Instant {
    let next = previous + interval;
    if next <= now { now + interval } else { next }
}

struct Reading<T> {
    value: T,
    at: Instant,
}

impl<T> Reading<T> {
    fn read(read: impl FnOnce() -> T) -> Self {
        let start = Instant::now();
        let value = read();
        Self {
            value,
            at: start + start.elapsed() / 2,
        }
    }

    fn elapsed(&self, before: &Self) -> f64 {
        self.at
            .duration_since(before.at)
            .as_secs_f64()
            .max(0.000_001)
    }
}

struct Counters {
    cpu: Reading<Vec<Vec<u64>>>,
    rapl: Reading<Vec<RaplCounter>>,
    disk: Reading<HashMap<String, DiskCounters>>,
    net: Reading<HashMap<String, NetCounters>>,
    processes: HashMap<u32, ProcessCounters>,
}

impl Counters {
    fn read() -> Self {
        Self {
            cpu: Reading::read(cpu_times),
            rapl: Reading::read(rapl_counters),
            disk: Reading::read(disk_counters),
            net: Reading::read(net_counters),
            processes: process_counters(),
        }
    }
}

#[derive(Default)]
pub(crate) struct Collector {
    previous: Option<Counters>,
}

impl Collector {
    pub(crate) fn sample(&mut self, args: &SnapshotArgs, state: &mut CollectorState) -> Value {
        let before = self.previous.take().unwrap_or_else(|| {
            let before = Counters::read();
            thread::sleep(Duration::from_secs_f64(args.sample_window));
            before
        });
        let after = Counters::read();
        let elapsed = after.cpu.elapsed(&before.cpu);
        let cpu_power = rapl_power_watts(
            &before.rapl.value,
            &after.rapl.value,
            after.rapl.elapsed(&before.rapl),
        );
        let power = power_snapshot(cpu_power, &after.rapl.value);
        let mut data = json!({
            "schema_version":1,"timestamp":now_epoch(),"sample_window_seconds":round(elapsed,3),"uptime":uptime_snapshot(),
            "cpu":cpu_snapshot(&before.cpu.value,&after.cpu.value,cpu_power),"memory":memory_snapshot(),"temperature":temperature_snapshot(),
            "power":power,"battery":battery_snapshot(&power),"gpu":gpu_snapshot(),
            "disk":disk_snapshot(&before.disk.value,&after.disk.value,after.disk.elapsed(&before.disk)),
            "network":network_snapshot(&before.net.value,&after.net.value,after.net.elapsed(&before.net)),
            "processes":process_snapshot(&before.processes,&after.processes,elapsed,args.process_limit,state)
        });
        enrich_history(&mut data, state, &after.net.value);
        self.previous = Some(after);
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_all_sample_window_boundaries() {
        for invalid in [f64::NAN, f64::INFINITY, -1.0, 0.049, 2.001] {
            assert!(validate_window(invalid).is_err());
        }
        for valid in [0.05, 0.35, 2.0] {
            assert!(validate_window(valid).is_ok());
        }
    }

    #[test]
    fn slow_collection_skips_missed_deadlines() {
        let start = std::time::Instant::now();
        let interval = std::time::Duration::from_secs(2);
        assert_eq!(
            next_deadline(start, start + interval * 3, interval),
            start + interval * 4
        );
        assert_eq!(next_deadline(start, start, interval), start + interval);
    }

    #[test]
    fn per_source_elapsed_includes_time_between_readings() {
        let start = Instant::now();
        let before = Reading {
            value: (),
            at: start,
        };
        let after = Reading {
            value: (),
            at: start + Duration::from_millis(2350),
        };
        assert_eq!(after.elapsed(&before), 2.35);
    }

    #[test]
    fn process_rates_use_pid_timestamp_and_reused_pid_has_zero_delta() {
        let at = Instant::now();
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
        let mut before = HashMap::new();
        before.insert(
            1,
            ProcessCounters {
                sampled_at: Some(at),
                ticks: hz,
                start_ticks: 1,
                ..Default::default()
            },
        );
        let mut after = before.clone();
        let current = after.get_mut(&1).unwrap();
        current.ticks += hz;
        current.sampled_at = Some(at + Duration::from_secs(2));
        let data = process_snapshot(&before, &after, 0.35, 6, &mut CollectorState::default());
        assert_eq!(data["top"][0]["cpu_percent"], 50.0);
        after.get_mut(&1).unwrap().start_ticks = 2;
        let data = process_snapshot(&before, &after, 0.35, 6, &mut CollectorState::default());
        assert_eq!(data["top"][0]["cpu_percent"], 0.0);
    }

    #[test]
    fn typed_process_ranking_preserves_memory_and_pid_ties() {
        let after = HashMap::from([
            (
                3,
                ProcessCounters {
                    private_bytes: 100,
                    ..Default::default()
                },
            ),
            (
                2,
                ProcessCounters {
                    private_bytes: 100,
                    ..Default::default()
                },
            ),
            (
                1,
                ProcessCounters {
                    private_bytes: 1,
                    ..Default::default()
                },
            ),
        ]);
        let data = process_snapshot(&after, &after, 1.0, 2, &mut CollectorState::default());
        assert_eq!(data["count"], 3);
        assert_eq!(data["top"].as_array().unwrap().len(), 2);
        assert_eq!(data["top"][0]["pid"], 2);
        assert_eq!(data["top"][1]["pid"], 3);
    }
}
