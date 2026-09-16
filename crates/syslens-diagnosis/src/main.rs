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
    /// Install and enable the privileged system collector (requires root).
    EnableSystem {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        database: Option<PathBuf>,
        /// Root-owned executable to run from the system unit.
        #[arg(long)]
        binary: Option<PathBuf>,
    },
    /// Disable only the privileged system collector (requires root).
    DisableSystem,
    EnableApi {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    DisableApi,
    /// Install and enable the privileged system mTLS API (requires root).
    EnableSystemApi {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        database: Option<PathBuf>,
        /// Root-owned executable to run from the system unit.
        #[arg(long)]
        binary: Option<PathBuf>,
    },
    /// Disable only the privileged system mTLS API (requires root).
    DisableSystemApi,
    /// Copy user diagnosis evidence into system paths without overwriting.
    MigrateSystem {
        #[arg(long)]
        from_config: Option<PathBuf>,
        #[arg(long)]
        from_database: Option<PathBuf>,
    },
    Status {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Daemon {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        database: Option<PathBuf>,
        #[arg(long, hide = true)]
        system: bool,
    },
    /// Run the opt-in mutually authenticated evidence API.
    Serve {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        database: Option<PathBuf>,
        #[arg(long, hide = true)]
        system: bool,
    },
    Diagnose {
        #[arg(long)]
        config: Option<PathBuf>,
        #[command(subcommand)]
        resource: Diagnose,
    },
    /// Ask the configured optional AI endpoint about bounded local evidence.
    Chat {
        /// The question to ask. A question is required so automated callers
        /// cannot accidentally start an interactive session.
        #[arg(required = true, num_args = 1..)]
        question: Vec<String>,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Incidents {
        #[arg(long)]
        config: Option<PathBuf>,
        #[command(subcommand)]
        command: Option<IncidentCommand>,
    },
}
#[derive(Subcommand)]
enum Diagnose {
    Memory {
        #[arg(long, default_value = "today")]
        since: String,
        #[arg(long, default_value = "previous-week")]
        compare: String,
        /// Explicit comparison interval start as an RFC3339 timestamp.
        #[arg(long, requires = "comparison_end", conflicts_with = "compare")]
        comparison_start: Option<String>,
        /// Explicit comparison interval end as an RFC3339 timestamp.
        #[arg(long, requires = "comparison_start", conflicts_with = "compare")]
        comparison_end: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Storage {
        #[arg(long, default_value = "today")]
        since: String,
        #[arg(long, default_value = "previous-week")]
        compare: String,
        /// Explicit comparison interval start as an RFC3339 timestamp.
        #[arg(long, requires = "comparison_end", conflicts_with = "compare")]
        comparison_start: Option<String>,
        /// Explicit comparison interval end as an RFC3339 timestamp.
        #[arg(long, requires = "comparison_start", conflicts_with = "compare")]
        comparison_end: Option<String>,
        #[arg(long)]
        json: bool,
    },
}
#[derive(Subcommand)]
enum IncidentCommand {
    List {
        #[arg(long)]
        json: bool,
    },
    Show {
        id: String,
        #[arg(long)]
        json: bool,
    },
    Acknowledge {
        id: String,
        #[arg(long)]
        json: bool,
    },
    Events {
        #[arg(long, default_value_t = 0)]
        after: i64,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    Watch {
        #[arg(long, default_value_t = 0)]
        after: i64,
        #[arg(long)]
        json: bool,
    },
}

fn explicit_comparison(
    legacy: String,
    start: Option<String>,
    end: Option<String>,
) -> Result<String, String> {
    match (start, end) {
        (None, None) => Ok(legacy),
        (Some(start), Some(end)) => Ok(format!("{start}..{end}")),
        _ => Err("comparison_start and comparison_end must be provided together".into()),
    }
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
fn require_root(operation: &str) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(format!(
            "{operation} requires root; run `sudo syslens-diagnosis {}` (user services are unchanged)",
            operation.replace('_', "-")
        ));
    }
    Ok(())
}
fn system_service(args: &[&str]) -> Result<(), String> {
    let status = Command::new("systemctl")
        .args(args)
        .status()
        .map_err(|e| format!("systemctl unavailable: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("systemctl {} failed ({status})", args.join(" ")))
    }
}
fn system_paths(config: Option<PathBuf>, database: Option<PathBuf>) -> (PathBuf, PathBuf) {
    let config = config.unwrap_or_else(diagnosis::system_config_path);
    let database = database.unwrap_or_else(|| diagnosis::database_path_for_config(&config));
    (config, database)
}
fn system_binary(binary: Option<PathBuf>) -> Result<PathBuf, String> {
    let path = binary.unwrap_or_else(|| PathBuf::from("/usr/bin/syslens-diagnosis"));
    diagnosis::validate_system_binary(&path).map(|_| path)
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
        CommandLine::EnableSystem {
            config,
            database,
            binary,
        } => {
            require_root("enable-system").and_then(|_| {
                let (p, db) = system_paths(config, database);
                system_binary(binary)
                    .and_then(|binary| {
                        diagnosis::ensure_config(&p)
                            .and_then(|cfg| diagnosis::initialize_db(&db, &cfg).map(|_| ()))
                            .map(|_| binary)
                    })
                    .and_then(|binary| diagnosis::install_system_service(&binary, &p, &db))
                    .and_then(|_| system_service(&["daemon-reload"]))
                    .and_then(|_| system_service(&["enable", "--now", "syslens-diagnosis.service"]))
                    .map(|_| println!("system diagnosis collector enabled; recording uses {}", db.display()))
            })
        }
        CommandLine::DisableSystem => {
            require_root("disable-system")
                .and_then(|_| system_service(&["disable", "--now", "syslens-diagnosis.service"]))
        }
        CommandLine::EnableApi { config } => {
            let p = config.unwrap_or_else(diagnosis::config_path);
            let db = diagnosis::database_path_for_config(&p);
            diagnosis::secure_config(&p)
                .and_then(|_| diagnosis::load_config(&p))
                .and_then(|c| {
                    if !c.api.enabled {
                        return Err(
                            "API is disabled; configure [api] with mTLS paths before enabling"
                                .into(),
                        );
                    }
                    std::env::current_exe()
                        .map_err(|e| e.to_string())
                        .and_then(|b| diagnosis::install_api_user_service(&b, &p, &db).map(|_| ()))
                })
                .and_then(|_| service(&["daemon-reload"]))
                .and_then(|_| service(&["enable", "--now", "syslens-diagnosis-api.service"]))
        }
        CommandLine::DisableApi => service(&["disable", "--now", "syslens-diagnosis-api.service"]),
        CommandLine::EnableSystemApi {
            config,
            database,
            binary,
        } => {
            require_root("enable-system-api").and_then(|_| {
                let (p, db) = system_paths(config, database);
                system_binary(binary)
                    .and_then(|binary| {
                        diagnosis::ensure_config(&p)
                            .and_then(|cfg| {
                                if !cfg.api.enabled {
                                    return Err(
                                        "API is disabled; configure [api] with mTLS paths before enabling"
                                            .into(),
                                    );
                                }
                                diagnosis::initialize_db(&db, &cfg).map(|_| ())
                            })
                            .map(|_| binary)
                    })
                    .and_then(|binary| diagnosis::install_system_api_service(&binary, &p, &db))
                    .and_then(|_| system_service(&["daemon-reload"]))
                    .and_then(|_| {
                        system_service(&["enable", "--now", "syslens-diagnosis-api.service"])
                    })
                    .map(|_| println!("system diagnosis API enabled; bind and mTLS remain configured in {}", p.display()))
            })
        }
        CommandLine::DisableSystemApi => require_root("disable-system-api")
            .and_then(|_| system_service(&["disable", "--now", "syslens-diagnosis-api.service"])),
        CommandLine::MigrateSystem {
            from_config,
            from_database,
        } => require_root("migrate-system").and_then(|_| {
            let source_config = from_config.unwrap_or_else(diagnosis::config_path);
            let source_database = from_database
                .unwrap_or_else(|| diagnosis::database_path_for_config(&source_config));
            diagnosis::migrate_to_system(&source_config, &source_database).map(|(config, db)| {
                println!(
                    "migrated diagnosis config and evidence to system paths without deleting user data:\nconfig={}\ndatabase={}",
                    config.display(),
                    db.display()
                )
            })
        }),
        CommandLine::Status { config } => status(config.unwrap_or_else(diagnosis::config_path)),
        CommandLine::Daemon {
            config,
            database,
            system,
        } => daemon(config, database, system),
        CommandLine::Serve {
            config,
            database,
            system,
        } => {
            let db = database.unwrap_or_else(|| diagnosis::database_path_for_config(&config));
            if system {
                diagnosis::serve_api_system(&config, &db)
            } else {
                diagnosis::serve_api(&config, &db)
            }
        }
        CommandLine::Diagnose {
            config,
            resource:
                Diagnose::Memory {
                    since,
                    compare,
                    comparison_start,
                    comparison_end,
                    json,
                },
        } => {
            let config = config.unwrap_or_else(diagnosis::config_path);
            (|| {
                let compare = explicit_comparison(compare, comparison_start, comparison_end)?;
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
            })()
        }
        CommandLine::Diagnose {
            config,
            resource:
                Diagnose::Storage {
                    since,
                    compare,
                    comparison_start,
                    comparison_end,
                    json,
                },
        } => {
            let config = config.unwrap_or_else(diagnosis::config_path);
            (|| {
                let compare = explicit_comparison(compare, comparison_start, comparison_end)?;
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
            })()
        }
        CommandLine::Chat { question, config } => (|| {
            let config = config.unwrap_or_else(diagnosis::config_path);
            if !config.exists() {
                return Err(format!(
                    "AI chat is disabled: diagnosis configuration is not enabled at {}; run `syslens-diagnosis enable` first",
                    config.display()
                ));
            }
            diagnosis::secure_config(&config)?;
            let configured = diagnosis::load_config(&config)?;
            diagnosis::run_chat(
                &configured,
                &diagnosis::database_path_for_config(&config),
                &question.join(" "),
            )
            .map(|answer| println!("{answer}"))
        })(),
        CommandLine::Incidents { config, command } => {
            incidents(config.unwrap_or_else(diagnosis::config_path), command)
        }
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("syslens-diagnosis: {e}");
            ExitCode::from(1)
        }
    }
}
fn incidents(config: PathBuf, command: Option<IncidentCommand>) -> Result<(), String> {
    let db = diagnosis::database_path_for_config(&config);
    match command.unwrap_or(IncidentCommand::List { json: false }) {
        IncidentCommand::List { json } => {
            let x = diagnosis::list_incidents(&db)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "version": 1,
                        "type": "incident_list",
                        "incidents": x,
                    }))
                    .unwrap()
                )
            } else {
                for i in x {
                    println!(
                        "{} {} {} {} {}",
                        i.id, i.status, i.severity, i.detector, i.subject
                    );
                }
            }
            Ok(())
        }
        IncidentCommand::Show { id, json } => {
            let x = diagnosis::list_incidents(&db)?
                .into_iter()
                .find(|x| x.id == id)
                .ok_or("incident not found")?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "version": 1,
                        "type": "incident",
                        "incident": x,
                    }))
                    .unwrap()
                )
            } else {
                println!(
                    "{} {} {} {}\n{}",
                    x.id,
                    x.status,
                    x.severity,
                    x.detector,
                    serde_json::to_string_pretty(&x.evidence).unwrap()
                )
            };
            Ok(())
        }
        IncidentCommand::Acknowledge { id, json } => {
            let now = diagnosis::unix_now();
            diagnosis::acknowledge_incident(&db, &id, now)?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "version": 1,
                        "type": "incident_acknowledgement",
                        "id": id,
                        "acknowledged_at": now,
                        "status": "acknowledged",
                    })
                );
            }
            Ok(())
        }
        IncidentCommand::Events { after, limit, json } => {
            let page = diagnosis::list_events(&db, after, limit)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "version": 1,
                        "type": "notification_event_list",
                        "events": page.events,
                        "next_cursor": page.next_cursor,
                        "has_more": page.has_more,
                    }))
                    .unwrap()
                )
            } else {
                for e in page.events {
                    println!("{} {} {} {}", e.cursor, e.kind, e.severity, e.incident_id)
                }
            };
            Ok(())
        }
        IncidentCommand::Watch { mut after, json } => loop {
            loop {
                let page = diagnosis::list_events(&db, after, diagnosis::MAX_EVENT_PAGE_SIZE)?;
                for e in page.events {
                    after = e.cursor;
                    if json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "version": 1,
                                "type": "notification_event",
                                "event": e,
                            })
                        );
                    } else {
                        println!("{} {} {} {}", e.cursor, e.kind, e.severity, e.incident_id);
                    }
                }
                if !page.has_more {
                    break;
                }
            }
            thread::sleep(Duration::from_secs(2));
        },
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
    if let Some(warning) = diagnosis::database_permissions_warning(&db) {
        println!("syslens-diagnosis: warning: unsafe evidence permissions: {warning}");
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
    let (open_incidents, event_count, last_detection): (i64, i64, Option<String>) = conn.query_row("SELECT (SELECT count(*) FROM incidents WHERE status='open'), (SELECT count(*) FROM notification_events), (SELECT value FROM metadata WHERE key='last_detection_run')", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).map_err(|e| e.to_string())?;
    let system_mode = config == diagnosis::system_config_path();
    let active = if system_mode {
        Command::new("systemctl")
            .args(["is-active", "syslens-diagnosis.service"])
            .output()
    } else {
        Command::new("systemctl")
            .args(["--user", "is-active", "syslens-diagnosis.service"])
            .output()
    }
    .ok()
    .map(|x| String::from_utf8_lossy(&x.stdout).trim() == "active")
    .unwrap_or(false);
    let paused = !diagnosis::budget_allows(&db, cfg.database_budget_bytes)
        || !diagnosis::filesystem_has_reserve(&db);
    println!(
        "syslens-diagnosis: service={} recording={}\nconfig={}\ndatabase={} ({} bytes)\ninterval={}s retention={}d budget={} bytes\nhost samples={} earliest={:?} latest={:?}\nmounts={} scans={} last_scan={:?} incomplete_scans={} unavailable_mounts={}\nopen_incidents={} notification_events={} detection_last_run={:?}",
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
        unavailable_mounts,
        open_incidents,
        event_count,
        last_detection
    );
    Ok(())
}
fn daemon(config: PathBuf, database: Option<PathBuf>, system: bool) -> Result<(), String> {
    let db = database.unwrap_or_else(|| diagnosis::database_path_for_config(&config));
    if system
        || config == diagnosis::system_config_path()
        || db == diagnosis::system_database_path()
    {
        diagnosis::validate_config_permissions(&config)?;
    } else {
        diagnosis::secure_config(&config)?;
    }
    let cfg = diagnosis::load_config(&config)?;
    let _lock = diagnosis::acquire_writer_lock(&diagnosis::state_dir_for_database(&config, &db))?;
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
                if diagnosis::is_evidence_permission_error(&e) {
                    return Err(e);
                }
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
                if diagnosis::is_evidence_permission_error(&e) {
                    return Err(e);
                }
                eprintln!("syslens-diagnosis: budget compaction failed: {e}");
                false
            }
        };
        if (recovered || diagnosis::budget_allows(&db, cfg.database_budget_bytes))
            && diagnosis::filesystem_has_reserve(&db)
        {
            let snap = collector.collect(diagnosis::unix_now());
            let ram_ok = if let Err(e) = diagnosis::insert_snapshot(&mut conn, &snap) {
                if diagnosis::is_evidence_permission_error(&e) {
                    return Err(e);
                }
                eprintln!("syslens-diagnosis: collection write failed: {e}");
                false
            } else {
                true
            };
            let (mounts, mount_gaps) =
                diagnosis::collect_mounts(&diagnosis::LinuxFilesystemReader, diagnosis::unix_now());
            let mounts_ok = if let Err(e) = diagnosis::insert_mounts(&mut conn, &mounts) {
                if diagnosis::is_evidence_permission_error(&e) {
                    return Err(e);
                }
                eprintln!("syslens-diagnosis: mount collection write failed: {e}");
                false
            } else {
                true
            };
            if ram_ok
                && mounts_ok
                && let Err(e) =
                    diagnosis::run_detection(&mut conn, &cfg.detection, diagnosis::unix_now())
            {
                if diagnosis::is_evidence_permission_error(&e) {
                    return Err(e);
                }
                eprintln!("syslens-diagnosis: detection failed: {e}");
            }
            if !mount_gaps.is_empty() {
                eprintln!("syslens-diagnosis: {}", mount_gaps.join("; "));
                if let Err(e) =
                    diagnosis::insert_collection_gaps(&mut conn, diagnosis::unix_now(), &mount_gaps)
                {
                    if diagnosis::is_evidence_permission_error(&e) {
                        return Err(e);
                    }
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
                let planned: Vec<_> = if let Some(roots) = cfg.storage.roots.clone() {
                    roots
                        .into_iter()
                        .map(|root| {
                            let mount = diagnosis::containing_mount(&root, &mounts);
                            (
                                root,
                                mount
                                    .filter(|m| m.capability == "available")
                                    .map(|m| m.mount_id.clone()),
                            )
                        })
                        .collect()
                } else {
                    diagnosis::default_scan_roots(&mounts)
                        .into_iter()
                        .map(|(root, id)| (root, Some(id)))
                        .collect()
                };
                let scan_db = db.clone();
                let scan_config = cfg.storage.clone();
                scan_worker = Some(thread::spawn(move || {
                    // Best effort: scans are scheduled separately and should yield CPU
                    // to interactive monitoring and normal server work.
                    // SAFETY: affects only this process/thread's scheduler nice value;
                    // failure is harmless and intentionally ignored.
                    unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, 10) };
                    for (root, mount_id) in planned {
                        let scan = match mount_id {
                            Some(id) => diagnosis::scan_directory(
                                &root,
                                Some(id),
                                &scan_config,
                                diagnosis::unix_now(),
                            ),
                            None => {
                                let now = diagnosis::unix_now();
                                diagnosis::ScanResult {
                                    root: root.display().to_string(),
                                    mount_id: None,
                                    started_at: now,
                                    ended_at: now,
                                    status: "partial".into(),
                                    reason: Some(
                                        "root has no eligible local physical mount".into(),
                                    ),
                                    entries_seen: 0,
                                    directories: vec![],
                                }
                            }
                        };
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
                conn.execute("INSERT INTO metadata(key,value) VALUES('next_storage_scan',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[(diagnosis::unix_now()+cfg.storage.scan_interval_seconds as i64).to_string()]).map_err(|e| e.to_string())?;
                diagnosis::secure_database_files(&db)?;
            }
        } else {
            eprintln!(
                "syslens-diagnosis: database budget or filesystem reserve reached; telemetry recording paused"
            )
        };
        thread::sleep(Duration::from_secs(cfg.interval_seconds));
    }
}
