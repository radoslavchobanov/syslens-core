use std::io::BufRead;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use syslens_diagnosis::{Config, database_sidecar_paths, open_db};
use tempfile::tempdir;

fn incident_database() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempdir().unwrap();
    let config = dir.path().join("diagnosis.toml");
    let db = config.with_extension("sqlite");
    let c = open_db(&db).unwrap();
    c.execute("INSERT INTO incidents(id,detector,subject,severity,status,opened_at,updated_at,evidence_json) VALUES('i','d','s','warning','open',1,1,'{}')", []).unwrap();
    c.execute("INSERT INTO notification_events(id,incident_id,kind,severity,created_at,detector_version,evidence_json) VALUES('e','i','opened','warning',1,'v1','{}')", []).unwrap();
    (dir, config)
}

#[test]
fn status_reports_unsafe_evidence_permissions_without_repairing_files() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("diagnosis.toml");
    std::fs::write(&config, toml::to_string_pretty(&Config::default()).unwrap()).unwrap();
    let db = config.with_extension("sqlite");
    let _conn = open_db(&db).unwrap();
    let files: Vec<_> = std::iter::once(db.clone())
        .chain(database_sidecar_paths(&db))
        .collect();
    for file in &files {
        std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    let output = Command::new(env!("CARGO_BIN_EXE_syslens-diagnosis"))
        .args(["status", "--config", config.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("unsafe evidence permissions"));
    for file in files {
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }
}

#[test]
fn help_lists_local_memory_diagnosis() {
    let output = Command::new(env!("CARGO_BIN_EXE_syslens-diagnosis"))
        .args(["diagnose", "memory", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("previous-week"));
}

#[test]
fn help_lists_local_storage_diagnosis() {
    let output = Command::new(env!("CARGO_BIN_EXE_syslens-diagnosis"))
        .args(["diagnose", "storage", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("previous-week"));
}

#[test]
fn acknowledgement_json_has_stable_v1_fields() {
    let (_dir, config) = incident_database();
    let output = Command::new(env!("CARGO_BIN_EXE_syslens-diagnosis"))
        .args([
            "incidents",
            "--config",
            config.to_str().unwrap(),
            "acknowledge",
            "i",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["version"], 1);
    assert_eq!(value["type"], "incident_acknowledgement");
    assert_eq!(value["id"], "i");
    assert_eq!(value["status"], "acknowledged");
}

#[test]
fn watch_json_emits_one_v1_object_per_event() {
    let (_dir, config) = incident_database();
    let mut child = Command::new(env!("CARGO_BIN_EXE_syslens-diagnosis"))
        .args([
            "incidents",
            "--config",
            config.to_str().unwrap(),
            "watch",
            "--json",
        ])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    std::io::BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    child.kill().unwrap();
    let _ = child.wait();
    let value: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(value["version"], 1);
    assert_eq!(value["type"], "notification_event");
    assert_eq!(value["event"]["cursor"], 1);
    assert_eq!(value["event"]["id"], "e");
}

#[test]
fn incident_json_commands_use_versioned_envelopes() {
    let (_dir, config) = incident_database();
    let binary = env!("CARGO_BIN_EXE_syslens-diagnosis");
    for (command, member) in [
        (vec!["list", "--json"], "incidents"),
        (vec!["show", "i", "--json"], "incident"),
        (vec!["events", "--json"], "events"),
    ] {
        let mut args = vec!["incidents", "--config", config.to_str().unwrap()];
        args.extend(command);
        let output = Command::new(binary).args(args).output().unwrap();
        assert!(output.status.success());
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["version"], 1);
        assert!(value[member].is_array() || value[member].is_object());
    }
}
