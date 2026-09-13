use serde_json::Value;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

struct Fixture {
    root: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Self {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "syslens-cli-compat-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self { root }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_syslens"));
        command
            .env("HOME", self.root.join("home"))
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("XDG_STATE_HOME", self.root.join("state"));
        command
    }

    fn config(&self) -> std::path::PathBuf {
        self.root.join("agent.toml")
    }

    fn history_state(&self) -> std::path::PathBuf {
        self.root.join("state/syslens-core/state.json")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct RunningAgent(Child);

impl Drop for RunningAgent {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn snapshot_output(fixture: &Fixture, arguments: &[&str]) -> Value {
    let Output {
        status,
        stdout,
        stderr,
    } = fixture.command().args(arguments).output().unwrap();
    assert!(
        status.success(),
        "snapshot command failed: {}",
        String::from_utf8_lossy(&stderr)
    );
    serde_json::from_slice(&stdout).unwrap()
}

fn output_with_timeout(command: &mut Command, timeout: Duration) -> Output {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "subprocess did not finish within {} ms; stdout: {}; stderr: {}",
                timeout.as_millis(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn assert_legacy_snapshot_contract(snapshot: &Value) {
    for key in [
        "schema_version",
        "timestamp",
        "cpu",
        "memory",
        "disk",
        "network",
        "processes",
    ] {
        assert!(snapshot.get(key).is_some(), "missing legacy key {key}");
    }
    assert_eq!(snapshot["schema_version"], 1);
    let processes = snapshot["processes"]
        .as_object()
        .expect("processes must remain an object");
    let top = processes["top"]
        .as_array()
        .expect("processes.top must remain an array");
    assert!(!top.is_empty(), "the snapshot must include its own process");
    assert!(
        top.iter().all(|process| {
            process.get("rss_bytes").is_some() && process.get("private_bytes").is_some()
        }),
        "every top process must retain rss_bytes and private_bytes"
    );
}

#[test]
fn legacy_and_snapshot_json_spelling_preserve_the_contract() {
    let fixture = Fixture::new();
    assert_legacy_snapshot_contract(&snapshot_output(
        &fixture,
        &["--json", "--sample-window", "0.05"],
    ));
    assert_legacy_snapshot_contract(&snapshot_output(
        &fixture,
        &["snapshot", "--json", "--sample-window", "0.05"],
    ));
}

#[test]
fn a_running_agent_rejects_a_second_history_writer_process() {
    let fixture = Fixture::new();
    let config = fixture.config();
    fs::write(
        &config,
        r#"[agent]
host_id = "lock-smoke"
interval_seconds = 0.5
sample_window_seconds = 0.05

[collection]
process_limit = 1

[mqtt]
host = "127.0.0.1"
port = 1
topic_prefix = "syslens"
tls = false
keepalive_seconds = 1
qos = 0
retain = true
"#,
    )
    .unwrap();

    let mut first_command = fixture.command();
    first_command
        .args(["agent", "--config", config.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut first = RunningAgent(first_command.spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(3);
    // `state.json` is written only after `HistoryStore::open(Writer)` has
    // acquired its advisory flock. The first agent retains that writer store
    // for its whole lifetime, so a live process with persisted state proves
    // ownership before the competing subprocess starts.
    while !fixture.history_state().exists() {
        assert!(
            Instant::now() < deadline,
            "agent did not persist state after acquiring its history lock"
        );
        assert!(
            first.0.try_wait().unwrap().is_none(),
            "first agent exited early"
        );
        thread::sleep(Duration::from_millis(20));
    }
    assert!(
        first.0.try_wait().unwrap().is_none(),
        "first agent exited before the competing attempt"
    );

    let mut second_command = fixture.command();
    second_command.args(["agent", "--config", config.to_str().unwrap(), "--once"]);
    let second = output_with_timeout(&mut second_command, Duration::from_secs(2));
    assert!(
        !second.status.success(),
        "second writer unexpectedly started"
    );
    assert!(
        String::from_utf8_lossy(&second.stderr).contains("already has an active writer"),
        "second writer did not report the active owner: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(
        first.0.try_wait().unwrap().is_none(),
        "first agent did not retain the lock long enough for the second attempt"
    );
}

#[cfg(unix)]
#[test]
fn diagnosis_commands_delegate_to_a_sibling_addon_without_a_shell() {
    let fixture = Fixture::new();
    let bin_directory = fixture.root.join("bin");
    fs::create_dir(&bin_directory).unwrap();
    let core = bin_directory.join("syslens");
    fs::copy(env!("CARGO_BIN_EXE_syslens"), &core).unwrap();

    let capture = fixture.root.join("arguments");
    let addon = bin_directory.join("syslens-diagnosis");
    fs::write(
        &addon,
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$SYSLENS_TEST_CAPTURE\"\n",
    )
    .unwrap();
    fs::set_permissions(&addon, fs::Permissions::from_mode(0o755)).unwrap();

    let output = Command::new(&core)
        .env("SYSLENS_TEST_CAPTURE", &capture)
        .args(["diagnose", "memory", "--since", "today"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "delegation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(capture).unwrap(),
        "diagnose\nmemory\n--since\ntoday\n"
    );
}

#[cfg(unix)]
#[test]
fn diagnosis_commands_explain_when_the_addon_is_not_installed() {
    let fixture = Fixture::new();
    let bin_directory = fixture.root.join("bin");
    fs::create_dir(&bin_directory).unwrap();
    let core = bin_directory.join("syslens");
    fs::copy(env!("CARGO_BIN_EXE_syslens"), &core).unwrap();

    let output = Command::new(core)
        .env("PATH", fixture.root.join("empty-path"))
        .args(["chat"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("install syslens-diagnosis"),
        "missing installation advice: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn diagnosis_commands_use_path_when_a_sibling_addon_is_not_executable() {
    let fixture = Fixture::new();
    let bin_directory = fixture.root.join("bin");
    let path_directory = fixture.root.join("path");
    fs::create_dir(&bin_directory).unwrap();
    fs::create_dir(&path_directory).unwrap();
    let core = bin_directory.join("syslens");
    fs::copy(env!("CARGO_BIN_EXE_syslens"), &core).unwrap();

    let sibling = bin_directory.join("syslens-diagnosis");
    fs::write(&sibling, "not executable").unwrap();
    fs::set_permissions(&sibling, fs::Permissions::from_mode(0o644)).unwrap();

    let capture = fixture.root.join("path-arguments");
    let addon = path_directory.join("syslens-diagnosis");
    fs::write(
        &addon,
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$SYSLENS_TEST_CAPTURE\"\n",
    )
    .unwrap();
    fs::set_permissions(&addon, fs::Permissions::from_mode(0o755)).unwrap();

    let output = Command::new(core)
        .env("PATH", path_directory)
        .env("SYSLENS_TEST_CAPTURE", &capture)
        .args(["incidents", "list"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "PATH fallback failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(capture).unwrap(), "incidents\nlist\n");
}
