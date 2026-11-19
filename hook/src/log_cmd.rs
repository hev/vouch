//! `vouch log`: reads the approval log the Mac agent writes and prints it as
//! a table, or as JSON lines with `--json`.

use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use clap::Args;
use time::{Duration, OffsetDateTime};
use vouch_protocol::approval_log::{ApprovalRecordV1, log_path_from_env, parse_log_timestamp};
use vouch_protocol::escape_for_terminal;

#[derive(Debug, Args)]
pub struct LogArgs {
    /// Only requests decided since then: a duration back from now (`30m`,
    /// `2h`, `7d`) or an RFC 3339 time.
    #[arg(long, value_name = "WHEN")]
    since: Option<String>,
    /// Only requests from this session name.
    #[arg(long, value_name = "NAME")]
    session: Option<String>,
    /// Print the matching lines as JSON, one per line.
    #[arg(long)]
    json: bool,
    /// Read this log instead of the default
    /// (~/Library/Logs/Vouch/approvals.jsonl on a Mac).
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,
}

pub fn run(args: &LogArgs) -> Result<()> {
    let path = match &args.file {
        Some(path) => path.clone(),
        None => log_path_from_env().context("HOME is not set; pass --file")?,
    };
    let since = args
        .since
        .as_deref()
        .map(|since| parse_since(since, OffsetDateTime::now_utc()))
        .transpose()?;
    let Some((records, skipped)) = read(&path)? else {
        eprintln!("no approvals logged yet at {}", path.display());
        return Ok(());
    };
    let matching: Vec<ApprovalRecordV1> = records
        .into_iter()
        .filter(|record| keep(record, since, args.session.as_deref()))
        .collect();
    let mut out = std::io::stdout().lock();
    if args.json {
        for record in &matching {
            serde_json::to_writer(&mut out, record)?;
            out.write_all(b"\n")?;
        }
    } else {
        out.write_all(table(&matching).as_bytes())?;
    }
    if skipped > 0 {
        eprintln!("skipped {skipped} unreadable line(s) in {}", path.display());
    }
    Ok(())
}

/// Every readable record in the file, and how many lines were not. `None`
/// when there is no log yet.
fn read(path: &Path) -> Result<Option<(Vec<ApprovalRecordV1>, usize)>> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
    };
    let mut records = Vec::new();
    let mut skipped = 0;
    for line in BufReader::new(file).lines() {
        let line = line.with_context(|| format!("read {}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<ApprovalRecordV1>(&line) {
            Ok(record) => records.push(record),
            Err(_) => skipped += 1,
        }
    }
    Ok(Some((records, skipped)))
}

fn keep(record: &ApprovalRecordV1, since: Option<OffsetDateTime>, session: Option<&str>) -> bool {
    if let Some(since) = since {
        match parse_log_timestamp(&record.decided_at).or_else(|| parse_log_timestamp(&record.ts)) {
            Some(at) if at >= since => {}
            _ => return false,
        }
    }
    session.is_none_or(|session| record.session.as_deref() == Some(session))
}

/// `30s`, `30m`, `2h`, `7d`, `1w` back from `now`, or an RFC 3339 time.
fn parse_since(text: &str, now: OffsetDateTime) -> Result<OffsetDateTime> {
    if let Some(at) = parse_log_timestamp(text) {
        return Ok(at);
    }
    let text = text.trim();
    let split = text
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let Ok(number) = number.parse::<i64>() else {
        bail!("--since takes a duration such as 30m, 2h or 7d, or an RFC 3339 time");
    };
    let span = match unit {
        "s" => Duration::seconds(number),
        "m" => Duration::minutes(number),
        "h" => Duration::hours(number),
        "d" => Duration::days(number),
        "w" => Duration::weeks(number),
        _ => bail!("--since takes a duration such as 30m, 2h or 7d, or an RFC 3339 time"),
    };
    Ok(now - span)
}

const COMMAND_WIDTH: usize = 60;
const REASON_WIDTH: usize = 40;

/// The readable table. Every field is escaped: the log holds text that came
/// from the requesting host and the agent asking.
fn table(records: &[ApprovalRecordV1]) -> String {
    let header = [
        "TIME (UTC)",
        "OUTCOME",
        "LANE",
        "SESSION",
        "HOST",
        "COMMAND",
        "WHY",
    ];
    let rows: Vec<[String; 7]> = records
        .iter()
        .map(|record| {
            [
                display_time(&record.decided_at),
                record.outcome.label().to_owned(),
                record.lane.label().to_owned(),
                cell(record.session.as_deref().unwrap_or("-"), 24),
                cell(&record.host, 24),
                cell(&command_text(record), COMMAND_WIDTH),
                cell(record.reason.as_deref().unwrap_or("-"), REASON_WIDTH),
            ]
        })
        .collect();
    let mut widths = header.map(str::len);
    for row in &rows {
        for (width, value) in widths.iter_mut().zip(row) {
            *width = (*width).max(value.chars().count());
        }
    }
    let mut out = String::new();
    push_row(&mut out, &header.map(str::to_owned), &widths);
    for row in &rows {
        push_row(&mut out, row, &widths);
    }
    if rows.is_empty() {
        out.push_str("(no matching approvals)\n");
    }
    out
}

fn push_row(out: &mut String, row: &[String; 7], widths: &[usize; 7]) {
    let last = row.len() - 1;
    for (index, (value, width)) in row.iter().zip(widths).enumerate() {
        out.push_str(value);
        if index < last {
            let pad = width.saturating_sub(value.chars().count()) + 2;
            out.extend(std::iter::repeat_n(' ', pad));
        }
    }
    out.push('\n');
}

fn command_text(record: &ApprovalRecordV1) -> String {
    if record.argv.is_empty() {
        return record.command.clone().unwrap_or_else(|| "-".to_owned());
    }
    record
        .argv
        .iter()
        .map(|argument| {
            if !argument.is_empty()
                && argument
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "@%+=:,./-_".contains(c))
            {
                argument.clone()
            } else {
                format!("'{}'", argument.replace('\'', r"'\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn display_time(text: &str) -> String {
    match parse_log_timestamp(text) {
        Some(at) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            at.year(),
            u8::from(at.month()),
            at.day(),
            at.hour(),
            at.minute(),
            at.second()
        ),
        None => cell(text, 20),
    }
}

/// One escaped cell, cut to `width` characters with an ellipsis.
fn cell(text: &str, width: usize) -> String {
    let escaped = escape_for_terminal(text);
    if escaped.chars().count() <= width {
        return escaped;
    }
    let mut cut: String = escaped.chars().take(width.saturating_sub(1)).collect();
    cut.push('…');
    cut
}

#[cfg(test)]
mod tests {
    use super::*;
    use vouch_protocol::approval_log::{
        APPROVAL_LOG_VERSION, ApprovalLane, ApprovalOutcome, log_timestamp,
    };

    fn record(id: &str, session: Option<&str>, at: OffsetDateTime) -> ApprovalRecordV1 {
        ApprovalRecordV1 {
            v: APPROVAL_LOG_VERSION,
            ts: log_timestamp(at),
            request_id: id.to_owned(),
            lane: ApprovalLane::SudoExact,
            host: "laptop".to_owned(),
            user: "adam".to_owned(),
            run_as: Some("root (uid 0)".to_owned()),
            session: session.map(str::to_owned),
            reason: Some("restart hevd".to_owned()),
            command: Some("/bin/launchctl".to_owned()),
            argv: vec![
                "launchctl".to_owned(),
                "kickstart".to_owned(),
                "a b".to_owned(),
            ],
            cwd: Some("/".to_owned()),
            tty: None,
            env_names: vec!["PATH".to_owned()],
            outcome: ApprovalOutcome::Approved,
            error: None,
            shown_at: Some(log_timestamp(at)),
            decided_at: log_timestamp(at),
            request_sha256: "00".repeat(32),
            device_id: "fp".to_owned(),
        }
    }

    #[test]
    fn since_takes_durations_and_times() {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        assert_eq!(parse_since("2h", now).unwrap(), now - Duration::hours(2));
        assert_eq!(parse_since("7d", now).unwrap(), now - Duration::days(7));
        assert_eq!(
            parse_since("30m", now).unwrap(),
            now - Duration::minutes(30)
        );
        let at = log_timestamp(now - Duration::days(1));
        assert_eq!(parse_since(&at, now).unwrap(), now - Duration::days(1));
        assert!(parse_since("soon", now).is_err());
        assert!(parse_since("5y", now).is_err());
    }

    #[test]
    fn filters_by_time_and_session() {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let old = record("old", Some("shell"), now - Duration::days(2));
        let new = record("new", Some("shell"), now - Duration::minutes(5));
        let other = record("other", Some("worker"), now - Duration::minutes(5));
        let since = Some(now - Duration::hours(1));
        assert!(!keep(&old, since, None));
        assert!(keep(&new, since, Some("shell")));
        assert!(!keep(&other, since, Some("shell")));
        assert!(keep(&other, None, None));
    }

    #[test]
    fn reads_the_log_and_skips_unreadable_lines() {
        let dir = std::env::temp_dir().join(format!(
            "vouch-log-cmd-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("approvals.jsonl");
        assert!(read(&path).unwrap().is_none());
        let now = OffsetDateTime::now_utc();
        let line = serde_json::to_string(&record("r1", None, now)).unwrap();
        std::fs::write(&path, format!("{line}\nnot json\n\n{line}\n")).unwrap();
        let (records, skipped) = read(&path).unwrap().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(skipped, 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_table_is_readable_and_escaped() {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let mut hostile = record("r2", Some("evil\u{1b}[2J"), now);
        hostile.reason = Some("x".repeat(100));
        let text = table(&[record("r1", Some("shell"), now), hostile]);
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[0].starts_with("TIME (UTC)"), "{text}");
        assert!(lines[1].contains("2027-01-15 08:00:00"), "{text}");
        assert!(
            lines[1].contains("approved") && lines[1].contains("sudo"),
            "{text}"
        );
        assert!(lines[1].contains("launchctl kickstart 'a b'"), "{text}");
        assert!(
            !text.contains('\u{1b}'),
            "terminal escapes reached the table"
        );
        assert!(lines[2].ends_with('…'), "long reasons are cut: {text}");
        assert_eq!(table(&[]).lines().nth(1), Some("(no matching approvals)"));
    }
}
