use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};
use syslens_gateway::{Result, config, daemon};

#[derive(Parser)]
#[command(about = "Independent SysLens gateway and terminal client")]
struct Cli {
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[arg(long, global = true)]
    socket: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    Init,
    Enable,
    Disable,
    Status,
    Daemon,
    Health,
    Hosts {
        #[command(subcommand)]
        command: Hosts,
    },
    Chat {
        #[arg(long, conflicts_with = "session")]
        host: Option<String>,
        #[arg(long)]
        session: Option<String>,
        #[arg(num_args=0..)]
        question: Vec<String>,
    },
    Sessions {
        #[command(subcommand)]
        command: Sessions,
    },
    Diagnose {
        #[arg(long)]
        host: String,
        #[arg(value_parser=["memory","storage"])]
        resource: String,
        #[arg(long, default_value = "today")]
        since: String,
        #[arg(long, default_value = "previous-week")]
        compare: String,
        /// Explicit current UTC interval start (use with all four explicit bounds).
        #[arg(long)]
        current_start: Option<String>,
        /// Explicit current UTC interval end (use with all four explicit bounds).
        #[arg(long)]
        current_end: Option<String>,
        /// Explicit comparison UTC interval start (use with all four explicit bounds).
        #[arg(long)]
        comparison_start: Option<String>,
        /// Explicit comparison UTC interval end (use with all four explicit bounds).
        #[arg(long)]
        comparison_end: Option<String>,
    },
    Incidents {
        #[command(subcommand)]
        command: Incidents,
    },
    Models {
        #[command(subcommand)]
        command: Models,
    },
    MigrateAi {
        #[arg(long)]
        from: PathBuf,
    },
}
#[derive(Subcommand)]
enum Hosts {
    List,
    Status {
        host: String,
    },
    /// Explicitly accept a configured host identity, ending old session continuity.
    Enroll {
        host: String,
    },
}
#[derive(Subcommand)]
enum Sessions {
    List,
    Show { id: String },
}
#[derive(Subcommand)]
enum Incidents {
    List {
        #[arg(long, default_value = "0")]
        after: i64,
    },
    Watch {
        #[arg(long, default_value = "0")]
        after: i64,
    },
}
#[derive(Subcommand)]
enum Models {
    List,
    Set { model: String },
}
#[derive(Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
struct LegacyAi {
    enabled: bool,
    endpoint_url: Option<String>,
    model: Option<String>,
    api_key_env: Option<String>,
    allow_insecure_http: bool,
    request_timeout_seconds: Option<u64>,
}
fn migrate_legacy_ai(legacy: &toml::Value) -> Result<config::Ai> {
    let legacy_ai: LegacyAi = legacy
        .get("ai")
        .cloned()
        .ok_or("legacy configuration has no AI section")?
        .try_into()
        .map_err(|_| "legacy AI configuration needs manual migration")?;
    let mut ai = config::Ai {
        enabled: legacy_ai.enabled,
        endpoint_url: legacy_ai.endpoint_url.unwrap_or_default(),
        model: legacy_ai.model.unwrap_or_default(),
        api_key_env: legacy_ai.api_key_env,
        allow_insecure_http: legacy_ai.allow_insecure_http,
        ..config::Ai::default()
    };
    if let Some(timeout) = legacy_ai.request_timeout_seconds {
        ai.request_timeout_seconds = timeout;
    }
    Ok(ai)
}
fn print(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap());
}
fn service(action: &str) -> Result<()> {
    if !Command::new("systemctl")
        .args(["--user", action, "syslens-gateway.service"])
        .status()
        .map_err(|_| "systemd user services are unavailable")?
        .success()
    {
        return Err("gateway service operation failed".into());
    }
    Ok(())
}
fn quote(path: &Path) -> Result<String> {
    let text = path.to_str().ok_or("service path must be UTF-8")?;
    if text.contains(['\n', '\r']) {
        return Err("invalid service path".into());
    }
    Ok(format!(
        "\"{}\"",
        text.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$")
    ))
}
fn replace_config(path: &Path, c: &config::Config) -> Result<()> {
    c.validate()?;
    let bytes = toml::to_string_pretty(c).map_err(|_| "cannot serialize configuration")?;
    let tmp = path.with_file_name(format!("config-{}.tmp", syslens_gateway::id()));
    config::write_new(&tmp, bytes.as_bytes())?;
    std::fs::rename(tmp, path).map_err(|_| "cannot replace gateway configuration".into())
}
#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
async fn run(cli: Cli) -> Result<()> {
    let path = cli.config.unwrap_or_else(config::default_path);
    let mut c = config::load(&path)?;
    let socket = cli.socket.unwrap_or_else(|| c.socket.clone());
    match cli.command {
        Commands::Init => {
            config::write_new(
                &path,
                toml::to_string_pretty(&c)
                    .map_err(|_| "cannot serialize configuration")?
                    .as_bytes(),
            )?;
            println!("Created disabled gateway configuration");
        }
        Commands::Enable => {
            c.enabled = true;
            replace_config(&path, &c)?;
            let directory = config::base("config")
                .parent()
                .ok_or("invalid config base")?
                .join("systemd/user");
            std::fs::create_dir_all(&directory).map_err(|_| "cannot create service directory")?;
            let unit = directory.join("syslens-gateway.service");
            if unit.exists() {
                let content =
                    std::fs::read_to_string(&unit).map_err(|_| "cannot inspect service file")?;
                if !content.starts_with("# Generated by syslens-gateway\n") {
                    return Err("existing service unit is not managed by SysLens".into());
                }
            }
            let content = format!(
                "# Generated by syslens-gateway\n[Unit]\nDescription=SysLens Gateway\nAfter=network.target\n\n[Service]\nType=simple\nExecStart={} --config {} daemon\nRestart=on-failure\nUMask=0077\nNoNewPrivileges=true\n\n[Install]\nWantedBy=default.target\n",
                quote(&std::env::current_exe().map_err(|_| "cannot locate gateway executable")?)?,
                quote(&path)?
            );
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&unit)
                .map_err(|_| "cannot write service unit")?;
            f.write_all(content.as_bytes())
                .map_err(|_| "cannot write service unit")?;
            if !Command::new("systemctl")
                .args(["--user", "daemon-reload"])
                .status()
                .map_err(|_| "systemd is unavailable")?
                .success()
            {
                return Err("systemd reload failed".into());
            }
            service("enable")?;
            service("restart")?;
            println!(
                "Gateway enabled. For persistence after logout, enable user lingering with loginctl."
            );
        }
        Commands::Disable => {
            service("stop")?;
            service("disable")?;
            c.enabled = false;
            replace_config(&path, &c)?;
            println!("Gateway disabled; recorded state retained");
        }
        Commands::Status => {
            print(
                &json!({"enabled":c.enabled,"daemon":daemon::request(&socket,"health",json!({})).await.ok()}),
            );
        }
        Commands::Daemon => daemon::run(c).await?,
        Commands::Health => {
            daemon::request(&socket, "health", json!({})).await?;
        }
        Commands::Hosts { command } => match command {
            Hosts::List => print(&daemon::request(&socket, "hosts", json!({})).await?),
            Hosts::Status { host } => {
                print(&daemon::request(&socket, "host-status", json!({"host":host})).await?)
            }
            Hosts::Enroll { host } => {
                print(&daemon::request(&socket, "host-enroll", json!({"host":host})).await?)
            }
        },
        Commands::Chat {
            host,
            mut session,
            question,
        } => {
            if !question.is_empty() {
                let v = daemon::request(
                    &socket,
                    "chat",
                    json!({"host":host,"session":session,"question":question.join(" ")}),
                )
                .await?;
                print_chat(&v);
            } else {
                loop {
                    print!("syslens> ");
                    io::stdout().flush().map_err(|_| "terminal output failed")?;
                    let mut question = String::new();
                    if io::stdin()
                        .read_line(&mut question)
                        .map_err(|_| "terminal input failed")?
                        == 0
                    {
                        break;
                    }
                    if question.trim().is_empty() {
                        continue;
                    }
                    let v=daemon::request(&socket,"chat",json!({"host":if session.is_some(){None}else{host.clone()},"session":session,"question":question.trim()})).await?;
                    session = v["session"].as_str().map(String::from);
                    print_chat(&v);
                }
            }
        }
        Commands::Sessions { command } => print(
            &daemon::request(
                &socket,
                "sessions",
                match command {
                    Sessions::List => json!({}),
                    Sessions::Show { id } => json!({"id":id}),
                },
            )
            .await?,
        ),
        Commands::Diagnose {
            host,
            resource,
            since,
            compare,
            current_start,
            current_end,
            comparison_start,
            comparison_end,
        } => print(
            &daemon::request(
                &socket,
                "diagnose",
                json!({
                    "host":host,
                    "resource":resource,
                    "since":since,
                    "compare":compare,
                    "current_start":current_start,
                    "current_end":current_end,
                    "comparison_start":comparison_start,
                    "comparison_end":comparison_end,
                }),
            )
            .await?,
        ),
        Commands::Incidents { command } => {
            let (watch, mut after) = match command {
                Incidents::List { after } => (false, after),
                Incidents::Watch { after } => (true, after),
            };
            loop {
                let v = daemon::request(&socket, "incidents", json!({"after":after})).await?;
                print(&v);
                after = v["next_cursor"].as_i64().ok_or("invalid replay cursor")?;
                if !watch {
                    break;
                }
                if v["has_more"] != true {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
        Commands::Models { command } => print(&match command {
            Models::List => daemon::request(&socket, "models", json!({})).await?,
            Models::Set { model } => {
                daemon::request(&socket, "model-set", json!({"model":model})).await?
            }
        }),
        Commands::MigrateAi { from } => {
            if path.exists() {
                return Err("migration requires a new gateway configuration destination; existing settings are never overwritten".into());
            }
            config::private(&from, false)?;
            let raw =
                std::fs::read_to_string(from).map_err(|_| "cannot read legacy configuration")?;
            let legacy: toml::Value =
                toml::from_str(&raw).map_err(|_| "invalid legacy configuration")?;
            c.ai = migrate_legacy_ai(&legacy)?;
            c.enabled = false;
            c.validate()?;
            config::write_new(
                &path,
                toml::to_string_pretty(&c)
                    .map_err(|_| "cannot serialize migration")?
                    .as_bytes(),
            )?;
            println!("Imported AI settings into a disabled gateway configuration");
        }
    }
    Ok(())
}
fn print_chat(v: &Value) {
    println!("{}", v["answer"].as_str().unwrap_or("No answer"));
    if let Some(items) = v["limitations"].as_array() {
        for item in items {
            if let Some(text) = item.as_str() {
                println!("Evidence limitation: {text}");
            }
        }
    }
    println!(
        "Session: {} | Host: {} | Model: {}",
        v["session"].as_str().unwrap_or_default(),
        v["target"].as_str().unwrap_or_default(),
        v["model"].as_str().unwrap_or_default()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_keeps_an_incomplete_disabled_legacy_section_disabled() {
        let legacy: toml::Value = toml::from_str("[ai]\nenabled = false\n").unwrap();
        let ai = migrate_legacy_ai(&legacy).unwrap();
        assert!(!ai.enabled);
        assert!(ai.endpoint_url.is_empty());
        assert!(ai.model.is_empty());
    }

    #[test]
    fn migration_copies_a_configured_legacy_endpoint_without_a_secret() {
        let legacy: toml::Value = toml::from_str(
            "[ai]\nenabled = true\nendpoint_url = 'https://ai.example.test/v1/chat/completions'\nmodel = 'model-a'\napi_key_env = 'AI_TOKEN'\nrequest_timeout_seconds = 20\n",
        )
        .unwrap();
        let ai = migrate_legacy_ai(&legacy).unwrap();
        assert!(ai.enabled);
        assert_eq!(ai.model, "model-a");
        assert_eq!(ai.api_key_env.as_deref(), Some("AI_TOKEN"));
        assert_eq!(ai.request_timeout_seconds, 20);
    }
}
