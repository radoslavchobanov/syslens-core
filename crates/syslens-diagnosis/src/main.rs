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
        #[arg(long)]
        database: Option<PathBuf>,
    },
    Diagnose {
        #[arg(long)]
        config: Option<PathBuf>,
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
            let db = diagnosis::database_path_for_config(&p);
            match diagnosis::ensure_config(&p)
                .and_then(|config| diagnosis::initialize_db(&db, &config).map(|_| ()))
                .and_then(|_| std::env::current_exe().map_err(|e| e.to_string()))
                .and_then(|binary| diagnosis::install_user_service(&binary, &p, &db))
                .and_then(|_| service(&["daemon-reload"]))
                .and_then(|_| service(&["enable", "--now", "syslens-diagnosis.service"]))
            {
                Ok(()) => {
                    println!("syslens-diagnosis enabled; recording uses {}", db.display());
                    warn_if_linger_disabled();
                    Ok(())
                }
                Err(e) => Err(format!(
                    "evidence was initialized but service was not enabled: {e}"
                )),
            }
        }
        CommandLine::Disable => service(&["disable", "--now", "syslens-diagnosis.service"]),
        CommandLine::Status { config } => status(config.unwrap_or_else(diagnosis::config_path)),
        CommandLine::Daemon { config, database } => daemon(config, database),
        CommandLine::Diagnose {
            config,
            resource:
                Diagnose::Memory {
                    since,
                    compare,
                    json,
                },
        } => {
            let config = config.unwrap_or_else(diagnosis::config_path);
            match diagnosis::diagnose_memory(
                &diagnosis::database_path_for_config(&config),
                &since,
                &compare,
            ) {
                Ok(d) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&d).unwrap())
                    } else {
                        print!("{}", diagnosis::render_diagnosis(&d))
                    };
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
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
fn warn_if_linger_disabled() {
    let uid = unsafe { libc::geteuid() }.to_string();
    let linger = Command::new("loginctl")
        .args(["show-user", &uid, "-p", "Linger", "--value"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .to_ascii_lowercase()
        });
    let user = std::env::var("USER").unwrap_or_else(|_| "<your-user>".into());
    if let Some(message) =
        diagnosis::linger_warning_message(&user, linger.as_deref() == Some("yes"))
    {
        eprintln!("{message}");
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
    let db = diagnosis::database_path_for_config(&config);
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
    let paused = !diagnosis::budget_allows(&db, cfg.database_budget_bytes)
        || !diagnosis::filesystem_has_reserve(&db);
    println!(
        "syslens-diagnosis: service={} recording={}\nconfig={}\ndatabase={} ({} bytes)\ninterval={}s retention={}d budget={} bytes\nhost samples={} earliest={:?} latest={:?}",
        if active {
            "active"
        } else {
            "inactive or unavailable"
        },
        if paused {
            "paused: budget or filesystem reserve"
        } else {
            "ready"
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
fn daemon(config: PathBuf, database: Option<PathBuf>) -> Result<(), String> {
    let cfg = diagnosis::load_config(&config)?;
    let db = database.unwrap_or_else(|| diagnosis::database_path_for_config(&config));
    let _lock = diagnosis::acquire_writer_lock(&diagnosis::state_dir())?;
    let mut conn = diagnosis::initialize_db(&db, &cfg)?;
    let collector = diagnosis::Collector::new(PathBuf::from("/proc"));
    loop {
        let cutoff = diagnosis::unix_now() - i64::from(cfg.retention_days) * 86400;
        let now = diagnosis::unix_now();
        let deleted = match diagnosis::housekeeping(&mut conn, cutoff, now) {
            Ok(count) => count,
            Err(e) => {
                eprintln!("syslens-diagnosis: retention housekeeping failed: {e}");
                0
            }
        };
        let recovered = match diagnosis::recover_budget_after_cleanup(
            &mut conn,
            &db,
            cfg.database_budget_bytes,
            now,
            deleted,
        ) {
            Ok(value) => value,
            Err(e) => {
                eprintln!("syslens-diagnosis: budget compaction failed: {e}");
                false
            }
        };
        if (recovered || diagnosis::budget_allows(&db, cfg.database_budget_bytes))
            && diagnosis::filesystem_has_reserve(&db)
        {
            let snap = collector.collect(diagnosis::unix_now());
            if let Err(e) = diagnosis::insert_snapshot(&mut conn, &snap) {
                eprintln!("syslens-diagnosis: collection write failed: {e}")
            }
        } else {
            eprintln!(
                "syslens-diagnosis: database budget or filesystem reserve reached; telemetry recording paused"
            )
        };
        thread::sleep(Duration::from_secs(cfg.interval_seconds));
    }
}
