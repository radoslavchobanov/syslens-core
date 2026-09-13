use std::process::ExitCode;

const UNAVAILABLE: &str = "diagnosis recording is unavailable in this scaffold build";

fn usage() {
    eprintln!("Usage: syslens-diagnosis <status|enable|disable>");
}

fn main() -> ExitCode {
    let command = std::env::args().nth(1);
    match command.as_deref() {
        Some("status") => {
            println!("syslens-diagnosis: {UNAVAILABLE}");
            ExitCode::SUCCESS
        }
        Some("enable") => {
            println!("syslens-diagnosis: enable requested; {UNAVAILABLE}");
            ExitCode::SUCCESS
        }
        Some("disable") => {
            println!("syslens-diagnosis: disable requested; {UNAVAILABLE}");
            ExitCode::SUCCESS
        }
        _ => {
            usage();
            ExitCode::from(2)
        }
    }
}
