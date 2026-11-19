//! Writes the approval log: one JSON line per request this agent decides.
//!
//! The rule that matters is the order. A signed decision is released (sent
//! on the socket, published on NATS, or relayed to a waiting transport) only
//! after its line has been appended and synced. If the line cannot be
//! written, the signature is dropped and the request is treated as
//! unanswered, so the host fails closed. Outcomes that carry no signature
//! (expired, canceled, failed) are logged on a best-effort basis.
//!
//! The file is created mode 0600 in a 0700 directory, opened append-only and
//! never through a symlink, and only ever appended to. Environment values are
//! never written: a line carries the variable names alone.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use vouch_protocol::approval_log::{
    APPROVAL_LOG_VERSION, ApprovalLane, ApprovalOutcome, ApprovalRecordV1, hex_digest,
    log_path_from_env, log_timestamp,
};
use vouch_protocol::{AuthInvocationV1, AuthRequestV1, OpenedAuthRequestV1, RequestV1};

use crate::OpenedRequest;
use crate::touchid::Outcome;

pub use vouch_protocol::approval_log::APPROVAL_LOG_ENV;

/// The append-only approval log at one path.
#[derive(Debug, Clone)]
pub struct ApprovalLog {
    path: PathBuf,
}

impl ApprovalLog {
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// `$VOUCH_APPROVAL_LOG`, else `~/Library/Logs/Vouch/approvals.jsonl` on a
    /// Mac and `$XDG_STATE_HOME/vouch/approvals.jsonl` (or
    /// `~/.local/state/vouch/approvals.jsonl`) elsewhere.
    pub fn from_env() -> Result<Self> {
        Ok(Self::at(log_path_from_env().context(
            "HOME is not set, so the approval log has no place to go",
        )?))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends one line and syncs it to disk. An error means the line may
    /// not be there, and the caller must not release a signature.
    pub fn append(&self, record: &ApprovalRecordV1) -> Result<()> {
        let mut line = serde_json::to_vec(record).context("encode approval log line")?;
        line.push(b'\n');
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&self.path)
            .with_context(|| format!("open {}", self.path.display()))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("stat {}", self.path.display()))?;
        if !metadata.file_type().is_file() {
            bail!("{} is not a regular file", self.path.display());
        }
        if metadata.uid() != nix::unistd::geteuid().as_raw() {
            bail!("{} belongs to another user", self.path.display());
        }
        if metadata.mode() & 0o077 != 0 {
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .with_context(|| format!("restrict {}", self.path.display()))?;
        }
        // One write per line: with O_APPEND each line lands whole at the end,
        // even with two agents writing.
        file.write_all(&line)
            .with_context(|| format!("write {}", self.path.display()))?;
        file.sync_data()
            .with_context(|| format!("sync {}", self.path.display()))?;
        Ok(())
    }
}

/// What deciding one request produced: the decision to release, if any, and
/// how it ended for the log.
#[derive(Debug)]
pub struct Decided<D> {
    pub decision: Option<D>,
    pub outcome: ApprovalOutcome,
    pub error: Option<String>,
}

impl<D> Decided<D> {
    pub fn signed(decision: D, outcome: ApprovalOutcome) -> Self {
        Self {
            decision: Some(decision),
            outcome,
            error: None,
        }
    }

    pub fn unsigned(outcome: ApprovalOutcome, error: Option<String>) -> Self {
        Self {
            decision: None,
            outcome,
            error,
        }
    }

    /// A decider error: expired if the deadline has passed, failed otherwise.
    pub fn from_error(error: &anyhow::Error, expires_at: i64, now: i64) -> Self {
        let outcome = if expires_at <= now {
            ApprovalOutcome::Expired
        } else {
            ApprovalOutcome::Failed
        };
        Self::unsigned(outcome, Some(format!("{error:#}")))
    }

    /// The Touch ID sheet's answer. A dismissed sheet signs nothing, so it is
    /// a cancellation rather than a denial; an enclave that would not sign is
    /// a failure.
    pub fn from_touch_id(asked: Result<Outcome<D>, anyhow::Error>) -> Self {
        match asked {
            Ok(Outcome::Approved(decision)) => Self::signed(decision, ApprovalOutcome::Approved),
            Ok(Outcome::Denied) => Self::unsigned(
                ApprovalOutcome::Canceled,
                Some("Touch ID sheet dismissed".to_owned()),
            ),
            Ok(Outcome::Expired) => Self::unsigned(ApprovalOutcome::Expired, None),
            Err(error) => Self::unsigned(ApprovalOutcome::Failed, Some(format!("{error:#}"))),
        }
    }
}

/// Logs one decided request, then says what may be released.
///
/// A decision comes back only if its line was written first. When the write
/// fails for a signed decision, the signature is dropped (the host fails
/// closed at its deadline) and the error is returned for agent.log. For an
/// unsigned outcome the write is best effort and its error is returned the
/// same way.
pub fn record_then_release<D>(
    log: &ApprovalLog,
    mut record: ApprovalRecordV1,
    decided: Decided<D>,
) -> (Option<D>, Option<anyhow::Error>) {
    record.outcome = decided.outcome;
    record.error = decided.error;
    let now = OffsetDateTime::now_utc();
    record.ts = log_timestamp(now);
    record.decided_at = log_timestamp(now);
    match log.append(&record) {
        Ok(()) => (decided.decision, None),
        Err(error) => {
            let error = error.context(if decided.decision.is_some() {
                "approval log unwritable; the signature was withheld and the request is denied"
            } else {
                "approval log unwritable; an unsigned outcome went unrecorded"
            });
            (None, Some(error))
        }
    }
}

/// The digest a host can recompute over the request bytes it sealed.
pub fn request_digest(raw: &[u8]) -> String {
    hex_digest(&Sha256::digest(raw))
}

/// A record for an exact sudo command, outcome still to be filled in.
pub fn command_record(
    opened: &OpenedRequest,
    device_id: &str,
    run_as: String,
    shown_at: OffsetDateTime,
) -> ApprovalRecordV1 {
    let request: &RequestV1 = &opened.request;
    ApprovalRecordV1 {
        v: APPROVAL_LOG_VERSION,
        ts: String::new(),
        request_id: request.request_id.clone(),
        lane: ApprovalLane::SudoExact,
        host: request.host.clone(),
        user: request.user.clone(),
        run_as: Some(run_as),
        session: request.session.clone(),
        reason: request.reason.clone(),
        command: Some(request.command.clone()),
        argv: request.argv.clone(),
        cwd: Some(request.cwd.clone()),
        tty: request.tty.clone(),
        env_names: request.env.iter().map(|entry| entry.name.clone()).collect(),
        outcome: ApprovalOutcome::Failed,
        error: None,
        shown_at: Some(log_timestamp(shown_at)),
        decided_at: String::new(),
        request_sha256: request_digest(&opened.raw),
        device_id: device_id.to_owned(),
    }
}

/// A record for a contextual PAM authentication. The invocation is what the
/// host submitted as display context; PAM does not sign it.
pub fn authentication_record(
    opened: &OpenedAuthRequestV1,
    device_id: &str,
    shown_at: OffsetDateTime,
) -> ApprovalRecordV1 {
    let request: &AuthRequestV1 = &opened.request;
    let trusted = &request.trusted;
    let (command, argv, cwd) = match &request.submitted.invocation {
        AuthInvocationV1::Available { command, argv, cwd } => {
            (Some(command.clone()), argv.clone(), Some(cwd.clone()))
        }
        AuthInvocationV1::Truncated {
            command, argv, cwd, ..
        } => (command.clone(), argv.clone(), cwd.clone()),
        AuthInvocationV1::Unavailable => (None, Vec::new(), None),
    };
    ApprovalRecordV1 {
        v: APPROVAL_LOG_VERSION,
        ts: String::new(),
        request_id: request.request_id.clone(),
        lane: ApprovalLane::ContextualPam,
        host: trusted.host.clone(),
        user: trusted
            .invoking_user
            .clone()
            .unwrap_or_else(|| format!("uid {}", trusted.invoking_uid)),
        run_as: Some(trusted.pam_user.clone()),
        session: request.submitted.session.clone(),
        reason: request.submitted.reason.clone(),
        command,
        argv,
        cwd,
        tty: trusted.tty.clone(),
        env_names: Vec::new(),
        outcome: ApprovalOutcome::Failed,
        error: None,
        shown_at: Some(log_timestamp(shown_at)),
        decided_at: String::new(),
        request_sha256: request_digest(&opened.raw),
        device_id: device_id.to_owned(),
    }
}

/// A record for a browser login ceremony the relay asks this Mac to approve.
/// There is no argv: the approval covers one Google login for `account`,
/// relayed from `destination`. The digest is over the challenge the
/// signature covers, and the device is named by its signing key's
/// credential id.
pub fn relay_record(
    attempt_id: &str,
    account: &str,
    destination: &str,
    challenge: &[u8],
    key_id: &str,
) -> ApprovalRecordV1 {
    ApprovalRecordV1 {
        v: APPROVAL_LOG_VERSION,
        ts: String::new(),
        request_id: attempt_id.to_owned(),
        lane: ApprovalLane::BrowserRelay,
        host: destination.to_owned(),
        user: account.to_owned(),
        run_as: None,
        session: None,
        reason: None,
        command: Some("gcloud auth login".to_owned()),
        argv: Vec::new(),
        cwd: None,
        tty: None,
        env_names: Vec::new(),
        outcome: ApprovalOutcome::Failed,
        error: None,
        shown_at: Some(log_timestamp(OffsetDateTime::now_utc())),
        decided_at: String::new(),
        request_sha256: request_digest(challenge),
        device_id: key_id.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(request_id: &str) -> ApprovalRecordV1 {
        ApprovalRecordV1 {
            v: APPROVAL_LOG_VERSION,
            ts: String::new(),
            request_id: request_id.to_owned(),
            lane: ApprovalLane::SudoExact,
            host: "laptop".to_owned(),
            user: "adam".to_owned(),
            run_as: Some("root (uid 0)".to_owned()),
            session: Some("shell".to_owned()),
            reason: Some("restart hevd".to_owned()),
            command: Some("/bin/launchctl".to_owned()),
            argv: vec!["launchctl".to_owned(), "kickstart".to_owned()],
            cwd: Some("/".to_owned()),
            tty: None,
            env_names: vec!["PATH".to_owned()],
            outcome: ApprovalOutcome::Failed,
            error: None,
            shown_at: None,
            decided_at: String::new(),
            request_sha256: "00".repeat(32),
            device_id: "fp".to_owned(),
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vouch-approval-log-{name}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn creates_a_private_file_in_a_private_directory() {
        let dir = temp_dir("create");
        let log = ApprovalLog::at(dir.join("Logs/Vouch/approvals.jsonl"));
        log.append(&sample("r1")).unwrap();
        log.append(&sample("r2")).unwrap();
        let mode = fs::metadata(log.path()).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dir_mode = fs::metadata(log.path().parent().unwrap()).unwrap().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        let text = fs::read_to_string(log.path()).unwrap();
        let ids: Vec<String> = text
            .lines()
            .map(|line| {
                serde_json::from_str::<ApprovalRecordV1>(line)
                    .unwrap()
                    .request_id
            })
            .collect();
        assert_eq!(ids, ["r1", "r2"]);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn appends_to_an_existing_log_and_tightens_its_mode() {
        let dir = temp_dir("existing");
        let path = dir.join("approvals.jsonl");
        fs::write(&path, "{\"earlier\":true}\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        ApprovalLog::at(&path).append(&sample("r1")).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("{\"earlier\":true}\n"), "{text}");
        assert_eq!(text.lines().count(), 2);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn refuses_a_symlinked_log() {
        let dir = temp_dir("symlink");
        let target = dir.join("elsewhere");
        fs::write(&target, "").unwrap();
        let path = dir.join("approvals.jsonl");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(ApprovalLog::at(&path).append(&sample("r1")).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_signed_decision_is_withheld_when_the_log_cannot_be_written() {
        let dir = temp_dir("unwritable");
        // The log's parent is a regular file, so nothing can be created there.
        fs::write(dir.join("not-a-dir"), "").unwrap();
        let log = ApprovalLog::at(dir.join("not-a-dir/approvals.jsonl"));
        let (released, error) = record_then_release(
            &log,
            sample("r1"),
            Decided::signed("signature", ApprovalOutcome::Approved),
        );
        assert_eq!(released, None);
        let error = format!(
            "{:#}",
            error.expect("the failure is reported for agent.log")
        );
        assert!(error.contains("signature was withheld"), "{error}");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_read_only_log_fails_closed() {
        let dir = temp_dir("readonly");
        let path = dir.join("approvals.jsonl");
        fs::write(&path, "").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        let (released, error) = record_then_release(
            &ApprovalLog::at(&path),
            sample("r1"),
            Decided::signed("signature", ApprovalOutcome::Approved),
        );
        // root can write a 0400 file; only check the outcome where the mode
        // is enforced.
        if nix::unistd::geteuid().is_root() {
            assert_eq!(released, Some("signature"));
        } else {
            assert_eq!(released, None);
            assert!(error.is_some());
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_line_is_on_disk_when_the_decision_comes_back() {
        let dir = temp_dir("order");
        let log = ApprovalLog::at(dir.join("approvals.jsonl"));
        let (released, error) = record_then_release(
            &log,
            sample("r1"),
            Decided::signed("signature", ApprovalOutcome::Approved),
        );
        assert!(error.is_none());
        assert_eq!(released, Some("signature"));
        let line: ApprovalRecordV1 =
            serde_json::from_str(fs::read_to_string(log.path()).unwrap().trim()).unwrap();
        assert_eq!(line.outcome, ApprovalOutcome::Approved);
        assert!(!line.decided_at.is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn writes_one_line_per_outcome() {
        let dir = temp_dir("outcomes");
        let log = ApprovalLog::at(dir.join("approvals.jsonl"));
        let cases: [(&str, Decided<&str>); 5] = [
            (
                "approved",
                Decided::signed("sig", ApprovalOutcome::Approved),
            ),
            (
                "denied",
                Decided::signed("deny-sig", ApprovalOutcome::Denied),
            ),
            ("expired", Decided::from_touch_id(Ok(Outcome::Expired))),
            ("canceled", Decided::from_touch_id(Ok(Outcome::Denied))),
            (
                "failed",
                Decided::from_touch_id(Err(anyhow::anyhow!("enclave refused"))),
            ),
        ];
        for (id, decided) in cases {
            let (_, error) = record_then_release(&log, sample(id), decided);
            assert!(error.is_none());
        }
        let lines: Vec<ApprovalRecordV1> = fs::read_to_string(log.path())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let seen: Vec<(&str, &str)> = lines
            .iter()
            .map(|line| (line.request_id.as_str(), line.outcome.label()))
            .collect();
        assert_eq!(
            seen,
            [
                ("approved", "approved"),
                ("denied", "denied"),
                ("expired", "expired"),
                ("canceled", "canceled"),
                ("failed", "failed"),
            ]
        );
        assert_eq!(lines[4].error.as_deref(), Some("enclave refused"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn decider_errors_are_expired_past_the_deadline_and_failed_before_it() {
        let error = anyhow::anyhow!("request already expired");
        assert_eq!(
            Decided::<()>::from_error(&error, 100, 100).outcome,
            ApprovalOutcome::Expired
        );
        assert_eq!(
            Decided::<()>::from_error(&error, 200, 100).outcome,
            ApprovalOutcome::Failed
        );
    }
}
