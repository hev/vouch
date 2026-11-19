//! The approval log: one JSON line per request a Mac agent decides.
//!
//! The agent appends a line before it releases any signature, so every
//! approval a host can verify has a line here first. A line names the request
//! by id and by the SHA-256 of the exact request bytes the signature covers,
//! plus the signing device's fingerprint, so it can be matched to the host's
//! own verification record.
//!
//! This is a local record, not a wire format: nothing here is signed or sent.
//! Environment values never appear in it, only the variable names.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Version of the line format below.
pub const APPROVAL_LOG_VERSION: u8 = 1;

/// Which kind of request a line records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalLane {
    /// An exact sudo command signed through the sudo approval plugin.
    SudoExact,
    /// Contextual PAM authentication: Touch ID authenticates the sudo session,
    /// and the command shown is advisory.
    ContextualPam,
    /// A browser login ceremony relayed to the Mac.
    BrowserRelay,
    /// A coding-agent tool permission.
    Tool,
}

impl ApprovalLane {
    pub fn label(self) -> &'static str {
        match self {
            Self::SudoExact => "sudo",
            Self::ContextualPam => "pam",
            Self::BrowserRelay => "relay",
            Self::Tool => "tool",
        }
    }
}

/// How a request ended on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalOutcome {
    /// Signed and released.
    Approved,
    /// Refused with a signed denial.
    Denied,
    /// The deadline passed with no answer.
    Expired,
    /// The sheet was dismissed or the attempt was called off. Nothing signed.
    Canceled,
    /// Something broke: an unusable key, a request that would not open, or an
    /// approval log that could not be written. Nothing released.
    Failed,
}

impl ApprovalOutcome {
    pub fn label(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Canceled => "canceled",
            Self::Failed => "failed",
        }
    }
}

/// One line of the approval log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRecordV1 {
    /// Always [`APPROVAL_LOG_VERSION`].
    pub v: u8,
    /// When the line was written, RFC 3339 UTC.
    pub ts: String,
    pub request_id: String,
    pub lane: ApprovalLane,
    pub host: String,
    pub user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// The agent's own words. Display text, never verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// The full argv as the request carried it.
    #[serde(default)]
    pub argv: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tty: Option<String>,
    /// Names of the environment variables in the request, in order. Values
    /// are never logged.
    #[serde(default)]
    pub env_names: Vec<String>,
    pub outcome: ApprovalOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// When the prompt was raised, RFC 3339 UTC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown_at: Option<String>,
    /// When the outcome was known, RFC 3339 UTC.
    pub decided_at: String,
    /// Lowercase hex SHA-256 of the exact request bytes the signature covers.
    pub request_sha256: String,
    /// Fingerprint of the device that would sign.
    pub device_id: String,
}

/// Environment variable that moves the log. It can move it; nothing turns
/// it off.
pub const APPROVAL_LOG_ENV: &str = "VOUCH_APPROVAL_LOG";

/// Where the log lives: the explicit path if given, else
/// `~/Library/Logs/Vouch/approvals.jsonl` on a Mac and
/// `$XDG_STATE_HOME/vouch/approvals.jsonl` (default `~/.local/state`)
/// elsewhere. `None` when there is no home directory to put it in.
pub fn default_log_path(
    explicit: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
    xdg_state: Option<std::ffi::OsString>,
) -> Option<std::path::PathBuf> {
    use std::path::PathBuf;
    if let Some(path) = explicit.filter(|path| !path.is_empty()) {
        return Some(PathBuf::from(path));
    }
    let home = PathBuf::from(home.filter(|home| !home.is_empty())?);
    if cfg!(target_os = "macos") {
        return Some(home.join("Library/Logs/Vouch/approvals.jsonl"));
    }
    let state = xdg_state
        .filter(|path| !path.is_empty())
        .map_or_else(|| home.join(".local/state"), PathBuf::from);
    Some(state.join("vouch/approvals.jsonl"))
}

/// [`default_log_path`] from this process's environment.
pub fn log_path_from_env() -> Option<std::path::PathBuf> {
    default_log_path(
        std::env::var_os(APPROVAL_LOG_ENV),
        std::env::var_os("HOME"),
        std::env::var_os("XDG_STATE_HOME"),
    )
}

/// Formats a time the way the log stores it.
pub fn log_timestamp(at: OffsetDateTime) -> String {
    at.to_offset(time::UtcOffset::UTC)
        .replace_nanosecond(0)
        .unwrap_or(at)
        .format(&Rfc3339)
        .unwrap_or_else(|_| at.unix_timestamp().to_string())
}

/// Reads a time back from a log line.
pub fn parse_log_timestamp(text: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(text, &Rfc3339).ok()
}

/// Lowercase hex, for the request digest.
pub fn hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_round_trip_in_utc() {
        let at = OffsetDateTime::from_unix_timestamp(1_795_087_329).unwrap();
        let text = log_timestamp(at);
        assert!(text.ends_with('Z'), "{text}");
        assert_eq!(parse_log_timestamp(&text), Some(at));
    }

    #[test]
    fn lanes_and_outcomes_use_snake_case() {
        assert_eq!(
            serde_json::to_string(&ApprovalLane::ContextualPam).unwrap(),
            "\"contextual_pam\""
        );
        assert_eq!(
            serde_json::to_string(&ApprovalOutcome::Canceled).unwrap(),
            "\"canceled\""
        );
    }

    #[test]
    fn hex_digest_is_lowercase_and_padded() {
        assert_eq!(hex_digest(&[0x00, 0x0f, 0xab]), "000fab");
    }

    #[test]
    fn default_path_follows_the_platform() {
        let explicit = default_log_path(Some("/tmp/x.jsonl".into()), None, None).unwrap();
        assert_eq!(explicit, std::path::PathBuf::from("/tmp/x.jsonl"));
        let home = default_log_path(None, Some("/Users/a".into()), None).unwrap();
        if cfg!(target_os = "macos") {
            assert_eq!(
                home,
                std::path::PathBuf::from("/Users/a/Library/Logs/Vouch/approvals.jsonl")
            );
        } else {
            assert_eq!(
                home,
                std::path::PathBuf::from("/Users/a/.local/state/vouch/approvals.jsonl")
            );
        }
        assert!(default_log_path(None, None, None).is_none());
    }
}
