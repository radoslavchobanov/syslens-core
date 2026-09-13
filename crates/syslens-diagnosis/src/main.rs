use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::thread;
use std::time::Duration;
use syslens_diagnosis as diagnosis;

#[derive(Parser)]
#[command(
    name = "syslens-diagnosis",
    about = "Optional local SysLens diagnosis recorder"
)]
struct Cli {
    #[command(subcommand)]
    command: CommandLine,
}
#[derive(Subcommand)]
enum CommandLine {
    Enable {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Disable,
    Status {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Daemon {
        #[arg(long)]
        config: PathBuf,
    },
    Diagnose {
        #[command(subcommand)]
        resource: Diagnose,
    },
    Chat,
    Incidents,
}
#[derive(Subcommand)]
enum Diagnose {
    Memory {
        #[arg(long, default_value = "today")]
        since: String,
        #[arg(long, default_value = "previous-week")]
        compare: String,
        #[arg(long)]
        json: bool,
    },
}
fn service(args: &[&str]) -> Result<(), String> {
    let status = Command::new("systemctl")
        .arg("--user")
        .args(args)
        .status()
        .map_err(|e| format!("systemctl --user unavailable: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "systemctl --user {} failed ({status}); run `syslens-diagnosis daemon --config {}` manually",
            args.join(" "),
            diagnosis::config_path().display()
        ))
    }
}
fn main() -> ExitCode {
    let cli = Cli::parse();
    let r = match cli.command {
        CommandLine::Enable { config } => {
            let p = config.unwrap_or_else(diagnosis::config_path);
            match diagnosis::ensure_config(&p)
                .and_then(|_| diagnosis::open_db(&diagnosis::database_path()).map(|_| ()))
                .and_then(|_| service(&["enable", "--now", "syslens-diagnosis.service"]))
            {
                Ok(()) => {
                    println!(
                        "syslens-diagnosis enabled; recording uses {}",
                        diagnosis::database_path().display()
                    );
                    Ok(())
                }
                Err(e) => Err(format!(
                    "evidence was initialized but service was not enabled: {e}"
                )),
            }
        }
        CommandLine::Disable => service(&["disable", "--now", "syslens-diagnosis.service"]),
        CommandLine::Status { config } => status(config.unwrap_or_else(diagnosis::config_path)),
        CommandLine::Daemon { config } => daemon(config),
        CommandLine::Diagnose {
            resource:
                Diagnose::Memory {
                    since,
                    compare,
                    json,
                },
        } => match diagnosis::diagnose_memory(&diagnosis::database_path(), &since, &compare) {
            Ok(d) => {
                if json {
                    println!("{}", serde_json::to_string_pretty(&d).unwrap())
                } else {
                    print!("{}", diagnosis::render_diagnosis(&d))
                };
                Ok(())
            }
            Err(e) => Err(e),
        },
        CommandLine::Chat => Err("chat is not available yet; use `syslens diagnose memory`".into()),
        CommandLine::Incidents => Err("incidents are not available yet".into()),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("syslens-diagnosis: {e}");
            ExitCode::from(1)
        }
    }
}
fn status(config: PathBuf) -> Result<(), String> {
    if !config.exists() {
        println!(
            "syslens-diagnosis: not enabled; expected config at {}",
            config.display()
        );
        return Ok(());
    }
    let cfg = diagnosis::load_config(&config)?;
    let db = diagnosis::database_path();
    if !db.exists() {
        println!(
            "syslens-diagnosis: configured; no evidence database at {}",
            db.display()
        );
        return Ok(());
    }
    let conn =
        rusqlite::Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| e.to_string())?;
    let (first, last, count): (Option<i64>, Option<i64>, i64) = conn
        .query_row(
            "SELECT min(timestamp),max(timestamp),count(*) FROM host_samples",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .map_err(|e| e.to_string())?;
    let active = Command::new("systemctl")
        .args(["--user", "is-active", "syslens-diagnosis.service"])
        .output()
        .ok()
        .map(|x| String::from_utf8_lossy(&x.stdout).trim() == "active")
        .unwrap_or(false);
    println!(
        "syslens-diagnosis: service={}\nconfig={}\ndatabase={} ({} bytes)\ninterval={}s retention={}d budget={} bytes\nhost samples={} earliest={:?} latest={:?}",
        if active {
            "active"
        } else {
            "inactive or unavailable"
        },
        config.display(),
        db.display(),
        diagnosis::database_size(&db),
        cfg.interval_seconds,
        cfg.retention_days,
        cfg.database_budget_bytes,
        count,
        first,
        last
    );
    Ok(())
}
fn daemon(config: PathBuf) -> Result<(), String> {
    let cfg = diagnosis::load_config(&config)?;
    let db = diagnosis::database_path();
    let _lock = diagnosis::acquire_writer_lock(&diagnosis::state_dir())?;
    let mut conn = diagnosis::open_db(&db)?;
    let collector = diagnosis::Collector::new(PathBuf::from("/proc"));
    loop {
        if diagnosis::budget_allows(&db, cfg.database_budget_bytes)
            && diagnosis::filesystem_has_reserve(&db)
        {
            let snap = collector.collect(diagnosis::unix_now());
            if let Err(e) = diagnosis::insert_snapshot(&mut conn, &snap) {
                eprintln!("syslens-diagnosis: collection write failed: {e}")
            }
            let cutoff = diagnosis::unix_now() - i64::from(cfg.retention_days) * 86400;
            if let Err(e) = diagnosis::cleanup(&conn, cutoff) {
                eprintln!("syslens-diagnosis: retention cleanup failed: {e}")
            }
        } else {
            eprintln!(
                "syslens-diagnosis: database budget or filesystem reserve reached; telemetry recording paused"
            )
        };
        thread::sleep(Duration::from_secs(cfg.interval_seconds));
    }
}
