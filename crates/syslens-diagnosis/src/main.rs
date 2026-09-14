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
    Storage {
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
        CommandLine::Diagnose {
            config,
            resource:
                Diagnose::Storage {
                    since,
                    compare,
                    json,
                },
        } => {
            let config = config.unwrap_or_else(diagnosis::config_path);
            match diagnosis::diagnose_storage(
                &diagnosis::database_path_for_config(&config),
                &since,
                &compare,
            ) {
                Ok(d) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&d).unwrap())
                    } else {
                        print!("{}", diagnosis::render_storage_diagnosis(&d))
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
    let (mount_count, scan_count, last_scan, partial_scans, unavailable_mounts): (i64, i64, Option<i64>, i64, i64) = conn.query_row("SELECT (SELECT count(DISTINCT mount_id) FROM mount_samples), (SELECT count(*) FROM storage_scans), (SELECT max(ended_at) FROM storage_scans), (SELECT count(*) FROM storage_scans WHERE status!='complete'), (SELECT count(*) FROM mount_samples WHERE timestamp=(SELECT max(timestamp) FROM mount_samples) AND capability='unavailable')", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).map_err(|e| e.to_string())?;
    let active = Command::new("systemctl")
        .args(["--user", "is-active", "syslens-diagnosis.service"])
        .output()
        .ok()
        .map(|x| String::from_utf8_lossy(&x.stdout).trim() == "active")
        .unwrap_or(false);
    let paused = !diagnosis::budget_allows(&db, cfg.database_budget_bytes)
        || !diagnosis::filesystem_has_reserve(&db);
    println!(
        "syslens-diagnosis: service={} recording={}\nconfig={}\ndatabase={} ({} bytes)\ninterval={}s retention={}d budget={} bytes\nhost samples={} earliest={:?} latest={:?}\nmounts={} scans={} last_scan={:?} incomplete_scans={} unavailable_mounts={}",
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
        last,
        mount_count,
        scan_count,
        last_scan,
        partial_scans,
        unavailable_mounts
    );
    Ok(())
}
fn daemon(config: PathBuf, database: Option<PathBuf>) -> Result<(), String> {
    let cfg = diagnosis::load_config(&config)?;
    let db = database.unwrap_or_else(|| diagnosis::database_path_for_config(&config));
    let _lock = diagnosis::acquire_writer_lock(&diagnosis::state_dir())?;
    let mut conn = diagnosis::initialize_db(&db, &cfg)?;
    let collector = diagnosis::Collector::new(PathBuf::from("/proc"));
    let mut scan_worker: Option<thread::JoinHandle<()>> = None;
    loop {
        if scan_worker
            .as_ref()
            .is_some_and(thread::JoinHandle::is_finished)
            && let Some(worker) = scan_worker.take()
        {
            let _ = worker.join();
        }
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
            let (mounts, mount_gaps) =
                diagnosis::collect_mounts(&diagnosis::LinuxFilesystemReader, diagnosis::unix_now());
            if let Err(e) = diagnosis::insert_mounts(&mut conn, &mounts) {
                eprintln!("syslens-diagnosis: mount collection write failed: {e}")
            }
            if !mount_gaps.is_empty() {
                eprintln!("syslens-diagnosis: {}", mount_gaps.join("; "));
                if let Err(e) =
                    diagnosis::insert_collection_gaps(&mut conn, diagnosis::unix_now(), &mount_gaps)
                {
                    eprintln!("syslens-diagnosis: mount gap write failed: {e}")
                }
            }
            let next_scan: i64 = conn
                .query_row(
                    "SELECT value FROM metadata WHERE key='next_storage_scan'",
                    [],
                    |r| r.get::<_, String>(0),
                )
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            if diagnosis::unix_now() >= next_scan && scan_worker.is_none() {
                let roots = cfg.storage.roots.clone().unwrap_or_else(|| {
                    mounts
                        .iter()
                        .filter(|m| m.capability == "available" && !m.read_only)
                        .map(|m| PathBuf::from(&m.mount_point))
                        .collect()
                });
                let planned: Vec<_> = roots
                    .into_iter()
                    .map(|root| {
                        let mount_id = mounts
                            .iter()
                            .find(|m| std::path::Path::new(&m.mount_point) == root)
                            .map(|m| m.mount_id.clone());
                        (root, mount_id)
                    })
                    .collect();
                let scan_db = db.clone();
                let scan_config = cfg.storage.clone();
                scan_worker = Some(thread::spawn(move || {
                    for (root, mount_id) in planned {
                        let scan = diagnosis::scan_directory(
                            &root,
                            mount_id,
                            &scan_config,
                            diagnosis::unix_now(),
                        );
                        match diagnosis::open_db(&scan_db)
                            .and_then(|mut c| diagnosis::insert_scan(&mut c, &scan))
                        {
                            Ok(()) => {}
                            Err(e) => {
                                eprintln!("syslens-diagnosis: storage scan write failed: {e}")
                            }
                        }
                    }
                }));
                let _=conn.execute("INSERT INTO metadata(key,value) VALUES('next_storage_scan',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[(diagnosis::unix_now()+cfg.storage.scan_interval_seconds as i64).to_string()]);
            }
        } else {
            eprintln!(
                "syslens-diagnosis: database budget or filesystem reserve reached; telemetry recording paused"
            )
        };
        thread::sleep(Duration::from_secs(cfg.interval_seconds));
    }
}
