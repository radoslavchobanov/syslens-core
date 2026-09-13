use std::process::Command;

#[test]
fn scaffold_commands_are_successful_and_clear() {
    for command in ["status", "enable", "disable"] {
        let output = Command::new(env!("CARGO_BIN_EXE_syslens-diagnosis"))
            .arg(command)
            .output()
            .unwrap();
        assert!(output.status.success(), "{command} should succeed");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("unavailable in this scaffold build"),
            "{command} should state its scaffold status"
        );
    }
}
