use std::process::Command;

#[test]
fn help_lists_local_memory_diagnosis() {
    let output = Command::new(env!("CARGO_BIN_EXE_syslens-diagnosis"))
        .args(["diagnose", "memory", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("previous-week"));
}
