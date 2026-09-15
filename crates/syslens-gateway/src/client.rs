use crate::{
    MAX_BODY, Result,
    config::{self, Host},
};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::{fs, path::Path, time::Duration};
use syslens_protocol::{Envelope, ErrorEnvelope};

pub fn tls_client(
    ca: Option<&Path>,
    cert: Option<&Path>,
    key: Option<&Path>,
    seconds: u64,
) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(seconds))
        .connect_timeout(Duration::from_secs(seconds.min(10)));
    if let Some(path) = ca {
        config::private(path, false)?;
        let pem = fs::read(path).map_err(|_| "cannot read trust configuration")?;
        let certificates = reqwest::Certificate::from_pem_bundle(&pem)
            .map_err(|_| "invalid trust configuration")?;
        if certificates.is_empty() {
            return Err("empty trust configuration".into());
        }
        b = b.tls_built_in_root_certs(false);
        for cert in certificates {
            b = b.add_root_certificate(cert);
        }
    }
    if let (Some(cert), Some(key)) = (cert, key) {
        config::private(cert, false)?;
        config::private(key, false)?;
        let mut pem = fs::read(cert).map_err(|_| "cannot read client credentials")?;
        pem.extend_from_slice(b"\n");
        pem.extend(fs::read(key).map_err(|_| "cannot read client credentials")?);
        b = b
            .identity(reqwest::Identity::from_pem(&pem).map_err(|_| "invalid client credentials")?);
    }
    b.build().map_err(|_| "cannot initialize transport".into())
}
pub async fn bounded_json(mut response: reqwest::Response) -> Result<Value> {
    if response
        .content_length()
        .is_some_and(|n| n > MAX_BODY as u64)
    {
        return Err("response exceeds size limit".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "response could not be read")?
    {
        if bytes.len() + chunk.len() > MAX_BODY {
            return Err("response exceeds size limit".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| "malformed response".into())
}
#[derive(Clone)]
pub struct HostClient {
    client: reqwest::Client,
    host: Host,
}
impl HostClient {
    pub fn new(host: &Host, seconds: u64) -> Result<Self> {
        config::endpoint(&host.url, false)?;
        Ok(Self {
            client: tls_client(
                Some(&host.ca),
                Some(&host.client_cert),
                Some(&host.client_key),
                seconds,
            )?,
            host: host.clone(),
        })
    }
    pub async fn request<T: DeserializeOwned>(
        &self,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Envelope<T>> {
        if !path.starts_with("/v1/") {
            return Err("unsupported evidence action".into());
        }
        let url = format!("{}{}", self.host.url.trim_end_matches('/'), path);
        let r = match body {
            Some(body) => self.client.post(url).json(body),
            None => self.client.get(url),
        }
        .header("x-request-id", crate::id())
        .send()
        .await
        .map_err(|_| "host connection failed")?;
        let success = r.status().is_success();
        let v = bounded_json(r).await?;
        if !success {
            let e: ErrorEnvelope = serde_json::from_value(v).map_err(|_| "malformed host error")?;
            if e.version != 1 {
                return Err("unsupported host protocol".into());
            }
            if e.error.code == syslens_protocol::ErrorCode::HistoryGap {
                let floor = e
                    .replay_floor
                    .filter(|n| *n >= 0)
                    .ok_or("invalid history gap response")?;
                return Err(format!("history gap; replay floor: {floor}"));
            }
            return Err(format!("host request failed: {:?}", e.error.code));
        }
        validate_envelope(&v, &self.host)?;
        serde_json::from_value(v).map_err(|_| "malformed host evidence".into())
    }
}
pub fn validate_envelope(v: &Value, h: &Host) -> Result<()> {
    let o = v.as_object().ok_or("malformed host envelope")?;
    let keys = [
        "version",
        "request_id",
        "host_id",
        "evidence_store_id",
        "observed_at",
        "responded_at",
        "data",
    ];
    if o.len() != keys.len() || o.keys().any(|k| !keys.contains(&k.as_str())) || v["version"] != 1 {
        return Err("unsupported host envelope".into());
    }
    for k in ["request_id", "host_id", "evidence_store_id"] {
        if v[k].as_str().is_none_or(|s| s.is_empty() || s.len() > 128) {
            return Err("invalid host identity envelope".into());
        }
    }
    for (key, expected) in [
        ("host_id", &h.host_id),
        ("evidence_store_id", &h.evidence_store_id),
    ] {
        if expected
            .as_ref()
            .is_some_and(|e| v[key].as_str() != Some(e.as_str()))
        {
            return Err("host identity mismatch; enrollment must be reviewed".into());
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_identity_and_unknown_envelope() {
        let h = Host {
            url: "https://localhost".into(),
            ca: "x".into(),
            client_cert: "x".into(),
            client_key: "x".into(),
            host_id: Some("correct".into()),
            evidence_store_id: None,
        };
        let mut v = serde_json::json!({"version":1,"request_id":"r","host_id":"wrong","evidence_store_id":"store","observed_at":"2026-01-01T00:00:00Z","responded_at":"2026-01-01T00:00:00Z","data":{}});
        assert!(validate_envelope(&v, &h).is_err());
        v["host_id"] = "correct".into();
        assert!(validate_envelope(&v, &h).is_ok());
        v["secret"] = "x".into();
        assert!(validate_envelope(&v, &h).is_err());
    }
}
