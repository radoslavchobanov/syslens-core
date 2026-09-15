//! Wire types shared by the host-local evidence server and a future gateway.
//! Types here contain no transport or database code.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const V1: u16 = 1;
pub const MAX_RANGE_SECONDS: i64 = 366 * 24 * 60 * 60;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ComparisonMode {
    PreviousWeek,
    PrecedingWeekAverage,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceWindow {
    #[serde(default)]
    pub relative: Option<RelativeRange>,
    #[serde(default)]
    pub start: Option<DateTime<Utc>>,
    #[serde(default)]
    pub end: Option<DateTime<Utc>>,
    #[serde(default = "default_comparison")]
    pub comparison: ComparisonMode,
}
fn default_comparison() -> ComparisonMode {
    ComparisonMode::PreviousWeek
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelativeRange {
    pub value: u32,
    pub unit: RelativeUnit,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RelativeUnit {
    Hours,
    Days,
    Today,
}

impl EvidenceWindow {
    pub fn validate(&self, retention_days: u32) -> Result<(), ProtocolError> {
        let relative = self.relative.is_some();
        let absolute = self.start.is_some() || self.end.is_some();
        if relative == absolute {
            return Err(ProtocolError::invalid("provide exactly one window form"));
        }
        if let Some(r) = &self.relative {
            let seconds = match r.unit {
                RelativeUnit::Hours => i64::from(r.value) * 3600,
                RelativeUnit::Days => i64::from(r.value) * 86400,
                RelativeUnit::Today => 86400,
            };
            if r.value == 0
                || seconds > i64::from(retention_days) * 86400
                || seconds > MAX_RANGE_SECONDS
            {
                return Err(ProtocolError::invalid("window exceeds retained evidence"));
            }
        }
        if let (Some(start), Some(end)) = (self.start, self.end) {
            let seconds = (end - start).num_seconds();
            if seconds <= 0
                || seconds > i64::from(retention_days) * 86400
                || seconds > MAX_RANGE_SECONDS
            {
                return Err(ProtocolError::invalid("window exceeds retained evidence"));
            }
            let now = Utc::now();
            if start < now - chrono::Duration::days(i64::from(retention_days))
                || end > now + chrono::Duration::minutes(5)
            {
                return Err(ProtocolError::invalid(
                    "window is outside retained evidence",
                ));
            }
        } else if absolute {
            return Err(ProtocolError::invalid(
                "absolute window requires start and end",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRequest {
    pub window: EvidenceWindow,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Envelope<T> {
    pub version: u16,
    pub request_id: String,
    pub host_id: String,
    pub evidence_store_id: String,
    pub observed_at: DateTime<Utc>,
    pub responded_at: DateTime<Utc>,
    pub data: T,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    pub version: u16,
    pub request_id: String,
    pub error: ProtocolError,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtocolError {
    pub code: ErrorCode,
    pub message: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    UnsupportedVersion,
    Unauthorized,
    NotFound,
    EvidenceUnavailable,
    QueryTimeout,
    Internal,
}
impl ProtocolError {
    pub fn invalid(message: &str) -> Self {
        Self {
            code: ErrorCode::InvalidRequest,
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Capabilities {
    pub timezone: String,
    pub resources: Vec<String>,
    pub earliest_observation: Option<DateTime<Utc>>,
    pub latest_observation: Option<DateTime<Utc>>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Status {
    pub recording: String,
    pub samples: u64,
    pub latest_observation: Option<DateTime<Utc>>,
    pub freshness_seconds: Option<i64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IncidentPage {
    pub incidents: Vec<serde_json::Value>,
    pub next_cursor: Option<IncidentCursor>,
    pub has_more: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IncidentCursor {
    pub updated_at: i64,
    pub id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventPage {
    pub events: Vec<serde_json::Value>,
    pub next_cursor: i64,
    pub has_more: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_ambiguous_windows() {
        assert!(
            EvidenceWindow {
                relative: None,
                start: None,
                end: None,
                comparison: ComparisonMode::PreviousWeek
            }
            .validate(185)
            .is_err()
        );
    }
}
