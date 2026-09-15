use crate::Result;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    net::IpAddr,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub enabled: bool,
    pub socket: PathBuf,
    pub database: PathBuf,
    pub hosts: BTreeMap<String, Host>,
    pub ai: Ai,
    pub session_retention_days: u32,
    pub event_retention_days: u32,
    pub poll_seconds: u64,
    pub host_timeout_seconds: u64,
    pub queue_limit: usize,
    pub chat_deadline_seconds: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Host {
    pub url: String,
    pub ca: PathBuf,
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
    pub host_id: Option<String>,
    pub evidence_store_id: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ai {
    pub enabled: bool,
    pub endpoint_url: String,
    pub model: String,
    pub api_key_env: Option<String>,
    pub allow_insecure_http: bool,
    pub ca: Option<PathBuf>,
    pub client_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
    pub request_timeout_seconds: u64,
    pub max_rounds: usize,
    pub max_calls: usize,
}
impl Default for Ai {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint_url: String::new(),
            model: String::new(),
            api_key_env: None,
            allow_insecure_http: false,
            ca: None,
            client_cert: None,
            client_key: None,
            request_timeout_seconds: 120,
            max_rounds: 3,
            max_calls: 4,
        }
    }
}
pub fn base(kind: &str) -> PathBuf {
    let var = if kind == "config" {
        "XDG_CONFIG_HOME"
    } else {
        "XDG_STATE_HOME"
    };
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(if kind == "config" {
                ".config"
            } else {
                ".local/state"
            })
        })
        .join("syslens-gateway")
}
pub fn default_path() -> PathBuf {
    base("config").join("config.toml")
}
impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            socket: base("state").join("run/gateway.sock"),
            database: base("state").join("gateway.sqlite"),
            hosts: BTreeMap::new(),
            ai: Ai::default(),
            session_retention_days: 30,
            event_retention_days: 185,
            poll_seconds: 30,
            host_timeout_seconds: 15,
            queue_limit: 8,
            chat_deadline_seconds: 300,
        }
    }
}
pub fn private(path: &Path, directory: bool) -> Result<()> {
    let m = fs::symlink_metadata(path).map_err(|_| "required private file is unavailable")?;
    if m.file_type().is_symlink()
        || m.uid() != unsafe { libc::geteuid() }
        || (directory && !m.is_dir())
        || (!directory && !m.is_file())
        || m.mode() & 0o077 != 0
    {
        return Err("gateway requires owner-only files and directories".into());
    }
    Ok(())
}
pub fn private_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(|_| "cannot create gateway directory")?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| "cannot secure gateway directory")?;
    }
    private(path, true)
}
pub fn write_new(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;
    private_dir(path.parent().ok_or("invalid file location")?)?;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "cannot create private file; destination may already exist")?;
    f.write_all(contents)
        .and_then(|_| f.sync_all())
        .map_err(|_| "cannot write private file".into())
}
pub fn load(path: &Path) -> Result<Config> {
    if !path.exists() {
        return Ok(Config::default());
    }
    private(path, false)?;
    private(path.parent().ok_or("invalid configuration location")?, true)?;
    let raw = fs::read_to_string(path).map_err(|_| "cannot read gateway configuration")?;
    if raw.len() > 131_072 {
        return Err("configuration is too large".into());
    }
    let c: Config = toml::from_str(&raw).map_err(|_| "invalid gateway configuration")?;
    c.validate()?;
    Ok(c)
}
pub fn endpoint(value: &str, allow_http: bool) -> Result<reqwest::Url> {
    let u = reqwest::Url::parse(value).map_err(|_| "invalid endpoint")?;
    if !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
        || u.host_str().is_none()
    {
        return Err("endpoint cannot contain credentials, queries, or fragments".into());
    }
    if u.scheme() == "https" {
        return Ok(u);
    }
    let ip = u
        .host_str()
        .unwrap_or_default()
        .trim_matches(['[', ']'])
        .parse::<IpAddr>();
    let private_ip = match ip {
        Ok(IpAddr::V4(ip)) => ip.is_loopback() || ip.is_private(),
        Ok(IpAddr::V6(ip)) => ip.is_loopback() || ip.is_unique_local(),
        _ => false,
    };
    if u.scheme() != "http" || !allow_http || !private_ip {
        return Err("endpoint requires HTTPS; explicit HTTP opt-in permits only private or loopback IP addresses".into());
    }
    Ok(u)
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        if !self.socket.is_absolute()
            || !self.database.is_absolute()
            || self.socket == self.database
            || !(1..=365).contains(&self.session_retention_days)
            || !(1..=366).contains(&self.event_retention_days)
            || !(5..=3600).contains(&self.poll_seconds)
            || !(1..=60).contains(&self.host_timeout_seconds)
            || !(1..=32).contains(&self.queue_limit)
            || !(10..=600).contains(&self.chat_deadline_seconds)
            || self.hosts.len() > 64
        {
            return Err("invalid gateway limits or paths".into());
        }
        for (name, h) in &self.hosts {
            if name.is_empty()
                || name.len() > 64
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err("invalid host name".into());
            }
            let u = endpoint(&h.url, false)?;
            if u.path() != "/" {
                return Err("host endpoint must be an HTTPS origin".into());
            }
            for path in [&h.ca, &h.client_cert, &h.client_key] {
                if !path.is_absolute() {
                    return Err("host trust and client credential paths must be absolute".into());
                }
            }
            for identity in [&h.host_id, &h.evidence_store_id].into_iter().flatten() {
                if identity.is_empty() || identity.len() > 128 {
                    return Err("invalid expected identity".into());
                }
            }
        }
        if self.ai.enabled {
            endpoint(&self.ai.endpoint_url, self.ai.allow_insecure_http)?;
            if self.ai.model.is_empty() || self.ai.model.len() > 256 {
                return Err("AI model is required".into());
            }
        }
        if self.ai.client_cert.is_some() != self.ai.client_key.is_some()
            || !(1..=120).contains(&self.ai.request_timeout_seconds)
            || !(1..=3).contains(&self.ai.max_rounds)
            || !(1..=4).contains(&self.ai.max_calls)
        {
            return Err("invalid AI configuration".into());
        }
        if self.ai.api_key_env.as_ref().is_some_and(|v| {
            v.is_empty()
                || v.len() > 128
                || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        }) {
            return Err("invalid credential environment name".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disabled_default_and_strict_fields() {
        assert!(!Config::default().enabled);
        assert!(toml::from_str::<Config>("unexpected = true").is_err());
    }
    #[test]
    fn endpoint_policy() {
        for url in [
            "http://example.com",
            "http://8.8.8.8",
            "https://user:secret@example.com",
            "https://example.com/?key=x",
            "https://example.com/#x",
        ] {
            assert!(endpoint(url, true).is_err(), "{url}");
        }
        assert!(endpoint("http://127.0.0.1:11434/v1/chat/completions", true).is_ok());
        assert!(endpoint("http://192.168.0.144", false).is_err());
    }
    #[test]
    fn private_config() {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let p = d.path().join("config");
        write_new(&p, b"enabled = false").unwrap();
        assert!(load(&p).is_ok());
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(&p).is_err());
    }
}
