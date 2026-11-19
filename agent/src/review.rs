//! What the operator reads before touching the sensor.
//!
//! Two surfaces, both built only from the request the agent already holds:
//!
//! * the Touch ID sheet's one-line reason, `<session> wants sudo <argv…>`,
//!   which macOS caps and owns; and
//! * the review panel beside it ([`vouch_panel::PanelView`]): who is asking,
//!   why they say they are asking, and what will run.
//!
//! Nothing here is verified or executed. The signature covers the exact
//! request bytes regardless of what is shown, so a label that is wrong, cut
//! short or missing can mislead a reader but cannot change what is approved.
//! That is also why every string is escaped with `escape_for_terminal` before
//! it is shown: a request field must never be able to draw its own UI.

use serde_json::Value;
use vouch_panel::{Chip, ChipTone, CodeKind, CodeLine, CommandLine, PanelView, What, Who};
use vouch_protocol::{
    AuthInvocationV1, AuthRequestV1, RequestV1, ToolApprovalRequestV1, ToolHarnessV1,
    escape_for_terminal,
};

/// The reason's cap for the system-owned biometric sheet. `LocalAuthentication`
/// wraps a long reason across lines rather than truncating it, so this leaves
/// room for a session, a host and a short command.
pub const MAX_APPROVAL_REASON_CHARS: usize = 160;

/// Longest cwd shown in a chip before its middle is elided.
const MAX_CHIP_CHARS: usize = 40;
/// Most code lines the "What" block shows for a tool request.
const MAX_CODE_LINES: usize = 16;
/// `pid_chain` holds at most this many entries (see `pid_chain_darwin` in the
/// hook); a shorter chain reached the top of the process tree.
const PID_CHAIN_LIMIT: usize = 5;

const HARNESSES: &[&str] = &[
    "claude",
    "codex",
    "pi",
    "opencode",
    "aider",
    "cursor-agent",
    "gemini",
];
const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "fish", "ksh", "tcsh", "nu"];

/// Quotes an argv for display so argument boundaries survive. Plain
/// arguments are shown as they are; anything else is single-quoted the way
/// a shell would.
pub fn quote_argv(argv: &[String]) -> String {
    argv.iter()
        .map(|argument| quote_argument(argument))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Single-quotes one argument unless every byte of it is unambiguous.
pub fn quote_argument(argument: &str) -> String {
    let plain = !argument.is_empty()
        && argument
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "@%+=:,./-_".contains(character));
    if plain {
        argument.to_owned()
    } else {
        format!("'{}'", argument.replace('\'', r"'\''"))
    }
}

/// Shrinks `value` to at most `max_chars` characters, replacing a dropped
/// tail with "…" so a reader can tell the text was cut.
pub fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_owned();
    }
    if max_chars == 0 {
        return String::new();
    }
    let mut truncated: String = value.chars().take(max_chars - 1).collect();
    truncated.push('…');
    truncated
}

/// The process name of one `pid_chain` entry (`"pid:comm"`), without a path
/// or a login shell's leading dash.
fn comm_name(entry: &str) -> Option<(&str, &str)> {
    let (pid, comm) = entry.split_once(':')?;
    let base = comm.rsplit('/').next().unwrap_or(comm);
    Some((pid, base.trim_start_matches('-')))
}

/// Names the session a request came from, using only fields carried on the
/// request — the agent never reads the requesting host's process table.
/// First match wins:
///
/// 1. The request's `session` field, which the hook resolves from
///    `VOUCH_SESSION` (or, for one release, `OSHIOKI_SESSION`) in the
///    caller's original environment.
/// 2. A `VOUCH_SESSION` or `OSHIOKI_SESSION` entry in the bound environment,
///    for an old hook that bound the environment but never resolved
///    `session` itself.
/// 3. The nearest interesting `pid_chain` ancestor, as `comm[pid]`.
/// 4. The tty's basename.
pub fn session_name_for(request: &RequestV1) -> Option<String> {
    if let Some(session) = request.session.as_ref().filter(|value| !value.is_empty()) {
        return Some(escape_for_terminal(session));
    }
    for name in ["VOUCH_SESSION", "OSHIOKI_SESSION"] {
        if let Some(entry) = request
            .env
            .iter()
            .rev()
            .find(|entry| entry.name == name && !entry.value.is_empty())
        {
            return Some(escape_for_terminal(&entry.value));
        }
    }
    if let Some((pid, comm)) = request.pid_chain.iter().find_map(|entry| {
        let (pid, comm) = comm_name(entry)?;
        is_interesting_session_process(comm).then_some((pid, comm))
    }) {
        return Some(escape_for_terminal(&format!("{comm}[{pid}]")));
    }
    if let Some(tty) = &request.tty
        && let Some(basename) = tty.rsplit('/').next().filter(|value| !value.is_empty())
    {
        return Some(escape_for_terminal(basename));
    }
    None
}

/// Whether a `pid_chain` process name is worth naming a session after.
pub fn is_interesting_session_process(comm: &str) -> bool {
    !(SHELLS.contains(&comm)
        || matches!(
            comm,
            "sudo" | "vouch" | "oshioki" | "login" | "sshd" | "systemd" | "launchd" | "init"
        ))
}

/// Whether `host` names this machine. Hostnames are compared by their first
/// label, case-insensitively, so `Adams-MacBook.local` matches
/// `adams-macbook`.
pub fn is_local_host(host: &str, local_host: &str) -> bool {
    let first = |name: &str| name.split('.').next().unwrap_or(name).to_ascii_lowercase();
    !local_host.is_empty() && first(host) == first(local_host)
}

fn runas_name(runas_uid: u32) -> String {
    if runas_uid == 0 {
        "root".to_owned()
    } else {
        format!("uid {runas_uid}")
    }
}

/// The argv a reader expects after `sudo`: without a leading `sudo`, quoted.
fn command_after_sudo(argv: &[String], command: &str) -> String {
    let argv = match argv.first() {
        Some(first) if first == "sudo" || first.ends_with("/sudo") => &argv[1..],
        _ => argv,
    };
    if argv.is_empty() {
        escape_for_terminal(command)
    } else {
        escape_for_terminal(&quote_argv(argv))
    }
}

/// Shortens absolute paths to `…/basename`, so the end of a long command
/// survives the sheet's character budget.
fn shorten_paths(argv: &[String]) -> Vec<String> {
    argv.iter()
        .map(|argument| match argument.rsplit_once('/') {
            Some((head, tail)) if head.contains('/') && !tail.is_empty() => format!("…/{tail}"),
            _ => argument.clone(),
        })
        .collect()
}

/// The Touch ID sheet's reason: `<session> wants sudo <argv…>`, with
/// ` on <host>` after `sudo` when the request comes from another machine.
///
/// Without a session the reader still learns who: `<user>@<host> wants sudo
/// …`. When the command does not fit, absolute paths shrink to `…/name`
/// first, then the tail is cut with "…". The session is never cut: it is the
/// one thing the sheet adds that the command alone does not say.
pub fn sheet_reason(request: &RequestV1, local_host: &str) -> String {
    let local = is_local_host(&request.host, local_host);
    let who = session_name_for(request).unwrap_or_else(|| {
        format!(
            "{}@{}",
            escape_for_terminal(&request.user),
            escape_for_terminal(&request.host)
        )
    });
    let who = truncate_chars(&who, 64);
    let verb = if local {
        "wants sudo".to_owned()
    } else {
        format!("wants sudo on {}", escape_for_terminal(&request.host))
    };
    let head = format!("{who} {verb}");
    let room = MAX_APPROVAL_REASON_CHARS.saturating_sub(head.chars().count() + 1);
    if room == 0 {
        return truncate_chars(&head, MAX_APPROVAL_REASON_CHARS);
    }
    let full = command_after_sudo(&request.argv, &request.command);
    if full.chars().count() <= room {
        return format!("{head} {full}");
    }
    let short = command_after_sudo(&shorten_paths(&request.argv), &request.command);
    format!("{head} {}", truncate_chars(&short, room))
}

/// The sheet's reason for a contextual PAM authentication, in the same
/// shape: `<session> wants sudo on <host> <invocation…>`.
pub fn sheet_authentication_reason(request: &AuthRequestV1, local_host: &str) -> String {
    let trusted = &request.trusted;
    let who = auth_session(request);
    let verb = if is_local_host(&trusted.host, local_host) {
        "wants sudo".to_owned()
    } else {
        format!("wants sudo on {}", escape_for_terminal(&trusted.host))
    };
    let head = format!("{} {verb}", truncate_chars(&who, 64));
    let room = MAX_APPROVAL_REASON_CHARS.saturating_sub(head.chars().count() + 1);
    if room == 0 {
        return truncate_chars(&head, MAX_APPROVAL_REASON_CHARS);
    }
    format!(
        "{head} {}",
        truncate_chars(&auth_invocation(&request.submitted.invocation), room)
    )
}

fn home_relative(path: &str, user: &str) -> String {
    for home in [format!("/Users/{user}"), format!("/home/{user}")] {
        if path == home {
            return "~".to_owned();
        }
        if let Some(rest) = path.strip_prefix(&format!("{home}/")) {
            return format!("~/{rest}");
        }
    }
    path.to_owned()
}

fn elide_middle(value: &str, max_chars: usize) -> String {
    let count = value.chars().count();
    if count <= max_chars || max_chars < 5 {
        return value.to_owned();
    }
    let keep_end = (max_chars - 1) * 2 / 3;
    let keep_start = max_chars - 1 - keep_end;
    let start: String = value.chars().take(keep_start).collect();
    let end: String = value.chars().skip(count - keep_end).collect();
    format!("{start}…{end}")
}

fn chip(text: impl Into<String>, tone: ChipTone) -> Chip {
    Chip {
        text: text.into(),
        tone,
    }
}

fn host_chip(host: &str, local_host: &str) -> Chip {
    if is_local_host(host, local_host) {
        chip("this Mac", ChipTone::Plain)
    } else {
        chip(
            format!("remote · {}", escape_for_terminal(host)),
            ChipTone::Remote,
        )
    }
}

/// The chips for a sudo request: how the session runs, the harness or shell
/// that asked, the host and the folder.
fn sudo_chips(request: &RequestV1, local_host: &str) -> Vec<Chip> {
    let comms: Vec<&str> = request
        .pid_chain
        .iter()
        .filter_map(|entry| comm_name(entry).map(|(_, comm)| comm))
        .collect();
    let mut chips = Vec::new();
    if comms.contains(&"tmux") {
        chips.push(chip("tmux", ChipTone::Context));
    } else if request.tty.is_none() {
        chips.push(chip("headless", ChipTone::Context));
    }
    if let Some(harness) = comms.iter().find(|comm| HARNESSES.contains(comm)) {
        chips.push(chip(escape_for_terminal(harness), ChipTone::Plain));
    } else if let Some(shell) = comms.iter().find(|comm| SHELLS.contains(comm)) {
        // A chain that ended before the limit reached the top of the tree, so
        // no agent sits above the shell. A full chain might hide one.
        let shell = escape_for_terminal(shell);
        if comms.len() < PID_CHAIN_LIMIT {
            chips.push(chip(format!("{shell} · typed by you"), ChipTone::Plain));
        } else {
            chips.push(chip(shell, ChipTone::Plain));
        }
    }
    chips.push(host_chip(&request.host, local_host));
    if !request.cwd.is_empty() {
        let cwd = home_relative(&request.cwd, &request.user);
        chips.push(chip(
            elide_middle(&escape_for_terminal(&cwd), MAX_CHIP_CHARS),
            ChipTone::Plain,
        ));
    }
    chips
}

/// The panel for a sudo command request. Everything in "What will run" is
/// in the signed bytes: argv, run-as user, host, cwd, tty and the complete
/// bound environment.
pub fn sudo_view(request: &RequestV1, local_host: &str) -> PanelView {
    let session = session_name_for(request).unwrap_or_else(|| {
        format!(
            "{}@{}",
            escape_for_terminal(&request.user),
            escape_for_terminal(&request.host)
        )
    });
    let runas = runas_name(request.runas_uid);
    let mut rows = vec![(
        "as".to_owned(),
        format!("{runas} (from {})", escape_for_terminal(&request.user)),
    )];
    rows.push(("cwd".to_owned(), escape_for_terminal(&request.cwd)));
    if let Some(tty) = &request.tty {
        rows.push(("tty".to_owned(), escape_for_terminal(tty)));
    }
    PanelView {
        kind: "sudo request".to_owned(),
        issued_at: request.issued_at,
        expires_at: request.expires_at,
        who: Who {
            session,
            chips: sudo_chips(request, local_host),
        },
        why: request.reason.as_deref().map(escape_for_terminal),
        what: What {
            heading: "What will run".to_owned(),
            badge: Some("verified, signed exactly".to_owned()),
            command: Some(CommandLine {
                prompt: format!("{runas}@{} $ ", escape_for_terminal(&request.host)),
                verb: "sudo".to_owned(),
                rest: command_after_sudo(&request.argv, &request.command),
            }),
            code: vec![],
            rows,
            env: request
                .env
                .iter()
                .map(|entry| {
                    format!(
                        "{}={}",
                        escape_for_terminal(&entry.name),
                        escape_for_terminal(&entry.value)
                    )
                })
                .collect(),
            note: None,
        },
    }
}

fn auth_session(request: &AuthRequestV1) -> String {
    let submitted = &request.submitted;
    if let Some(session) = submitted
        .session
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        return escape_for_terminal(session);
    }
    let invoking = request
        .trusted
        .invoking_user
        .clone()
        .unwrap_or_else(|| format!("uid {}", request.trusted.invoking_uid));
    format!(
        "{}@{}",
        escape_for_terminal(&invoking),
        escape_for_terminal(&request.trusted.host)
    )
}

fn auth_invocation(invocation: &AuthInvocationV1) -> String {
    match invocation {
        AuthInvocationV1::Available { command, argv, .. } => command_after_sudo(argv, command),
        AuthInvocationV1::Truncated {
            command,
            argv,
            omitted_args,
            ..
        } => {
            let shown = if argv.is_empty() {
                escape_for_terminal(command.as_deref().unwrap_or("(none)"))
            } else {
                command_after_sudo(argv, "")
            };
            match omitted_args {
                Some(count) => format!("{shown} … (+{count} more arguments, truncated)"),
                None => format!("{shown} … (truncated)"),
            }
        }
        AuthInvocationV1::Unavailable => "(command not reported)".to_owned(),
    }
}

/// The panel for a contextual PAM authentication (sudo-rs on a remote host).
/// Touch ID here authenticates the sudo session, not one exact command, and
/// the panel says so.
pub fn authentication_view(request: &AuthRequestV1, local_host: &str) -> PanelView {
    let trusted = &request.trusted;
    let submitted = &request.submitted;
    let mut chips = Vec::new();
    if trusted.tty.is_none() {
        chips.push(chip("headless", ChipTone::Context));
    }
    if let Some(label) = submitted.agent_label.as_deref() {
        chips.push(chip(escape_for_terminal(label), ChipTone::Plain));
    }
    chips.push(host_chip(&trusted.host, local_host));
    let cwd = match &submitted.invocation {
        AuthInvocationV1::Available { cwd, .. } => Some(cwd.as_str()),
        AuthInvocationV1::Truncated { cwd, .. } => cwd.as_deref(),
        AuthInvocationV1::Unavailable => None,
    };
    let invoking_name = trusted.invoking_user.as_deref().unwrap_or("");
    if let Some(cwd) = cwd {
        chips.push(chip(
            elide_middle(
                &escape_for_terminal(&home_relative(cwd, invoking_name)),
                MAX_CHIP_CHARS,
            ),
            ChipTone::Plain,
        ));
    }
    let invoking = trusted
        .invoking_user
        .clone()
        .unwrap_or_else(|| format!("uid {}", trusted.invoking_uid));
    let mut rows = vec![(
        "as".to_owned(),
        format!(
            "{} (from {})",
            escape_for_terminal(&trusted.pam_user),
            escape_for_terminal(&invoking)
        ),
    )];
    if let Some(cwd) = cwd {
        rows.push(("cwd".to_owned(), escape_for_terminal(cwd)));
    }
    rows.push((
        "tty".to_owned(),
        trusted
            .tty
            .as_deref()
            .map_or_else(|| "none".to_owned(), escape_for_terminal),
    ));
    PanelView {
        kind: "sudo authentication".to_owned(),
        issued_at: request.issued_at,
        expires_at: request.expires_at,
        who: Who {
            session: auth_session(request),
            chips,
        },
        why: submitted.reason.as_deref().map(escape_for_terminal),
        what: What {
            heading: "What will run".to_owned(),
            badge: Some(format!(
                "contextual PAM, {}",
                escape_for_terminal(&trusted.service)
            )),
            command: Some(CommandLine {
                prompt: format!(
                    "{}@{} $ ",
                    escape_for_terminal(&trusted.pam_user),
                    escape_for_terminal(&trusted.host)
                ),
                verb: "sudo".to_owned(),
                rest: auth_invocation(&submitted.invocation),
            }),
            code: vec![],
            rows,
            env: vec![],
            note: Some(format!(
                "On {}, Touch ID authenticates the sudo session rather than signing this exact command.",
                escape_for_terminal(&trusted.host)
            )),
        },
    }
}

fn input_str<'a>(input: &'a Value, key: &str) -> Option<&'a str> {
    input.get(key).and_then(Value::as_str)
}

fn code_lines(text: &str, kind: CodeKind, prefix: &str, budget: &mut usize) -> Vec<CodeLine> {
    let mut lines = Vec::new();
    let all: Vec<&str> = text.lines().collect();
    for (index, line) in all.iter().enumerate() {
        if *budget == 0 {
            lines.push(CodeLine {
                text: format!("… {} more lines", all.len() - index),
                kind: CodeKind::Context,
            });
            break;
        }
        *budget -= 1;
        lines.push(CodeLine {
            text: format!("{prefix}{}", escape_for_terminal(line)),
            kind,
        });
    }
    lines
}

/// The "What it wants" block for a harness tool request: the command for
/// Bash, the file and a diff for Edit and Write, the URL for `WebFetch`, and
/// the raw input otherwise.
fn tool_what(request: &ToolApprovalRequestV1) -> What {
    let tool = escape_for_terminal(&request.tool_name);
    let input = &request.tool_input;
    let mut budget = MAX_CODE_LINES;
    let (badge, code) = match request.tool_name.as_str() {
        "Bash" | "shell" | "exec_command" => {
            let command = input_str(input, "command")
                .or_else(|| input_str(input, "cmd"))
                .unwrap_or("");
            (
                tool.clone(),
                code_lines(command, CodeKind::Plain, "$ ", &mut budget),
            )
        }
        "Edit" | "MultiEdit" => {
            let path = input_str(input, "file_path").unwrap_or("");
            let mut code = vec![CodeLine {
                text: "@@ replace @@".to_owned(),
                kind: CodeKind::Context,
            }];
            let edits: Vec<&Value> = match input.get("edits").and_then(Value::as_array) {
                Some(edits) => edits.iter().collect(),
                None => vec![input],
            };
            for edit in edits {
                code.extend(code_lines(
                    input_str(edit, "old_string").unwrap_or(""),
                    CodeKind::Removed,
                    "-",
                    &mut budget,
                ));
                code.extend(code_lines(
                    input_str(edit, "new_string").unwrap_or(""),
                    CodeKind::Added,
                    "+",
                    &mut budget,
                ));
            }
            (format!("{tool} · {}", escape_for_terminal(path)), code)
        }
        "Write" => {
            let path = input_str(input, "file_path").unwrap_or("");
            let content = input_str(input, "content").unwrap_or("");
            (
                format!("{tool} · {}", escape_for_terminal(path)),
                code_lines(content, CodeKind::Added, "+", &mut budget),
            )
        }
        "WebFetch" => (
            tool.clone(),
            code_lines(
                input_str(input, "url").unwrap_or(""),
                CodeKind::Plain,
                "",
                &mut budget,
            ),
        ),
        _ => {
            let pretty = serde_json::to_string_pretty(input).unwrap_or_default();
            (
                tool.clone(),
                code_lines(&pretty, CodeKind::Plain, "", &mut budget),
            )
        }
    };
    What {
        heading: "What it wants".to_owned(),
        badge: Some(badge),
        command: None,
        code,
        rows: vec![],
        env: vec![],
        note: None,
    }
}

/// The panel for a Claude Code or Codex permission request. `session` is
/// the label the caller resolved for it (a tmux session name), when it has
/// one; the reason is the event's own `description`.
pub fn tool_view(request: &ToolApprovalRequestV1, session: Option<&str>) -> PanelView {
    let harness = match request.harness {
        ToolHarnessV1::Claude => "claude",
        ToolHarnessV1::Codex => "codex",
    };
    let session = session.map_or_else(
        || {
            let id = request.context.session_id.as_deref().unwrap_or("session");
            format!("{harness} {}", escape_for_terminal(&truncate_chars(id, 8)))
        },
        escape_for_terminal,
    );
    let mut chips = vec![chip(harness, ChipTone::Plain)];
    let cwd = request
        .cwd
        .strip_prefix("/Users/")
        .or_else(|| request.cwd.strip_prefix("/home/"))
        .and_then(|rest| rest.split_once('/').map(|(_, path)| format!("~/{path}")))
        .unwrap_or_else(|| request.cwd.clone());
    chips.push(chip(
        elide_middle(&escape_for_terminal(&cwd), MAX_CHIP_CHARS),
        ChipTone::Plain,
    ));
    PanelView {
        kind: "tool permission".to_owned(),
        issued_at: request.issued_at,
        expires_at: request.expires_at,
        who: Who { session, chips },
        why: request.description.as_deref().map(escape_for_terminal),
        what: tool_what(request),
    }
}

/// Panels with no request in flight, for `vouch-agent preview-panel`. Each
/// one is built from a real request type through the same functions the
/// agent uses, so a preview is what that request would show.
pub mod fixtures {
    use serde_json::json;
    use vouch_panel::PanelView;
    use vouch_protocol::{
        AUTH_REQUEST_TYPE, AUTH_WIRE_VERSION, AuthInvocationV1, AuthRequestV1, EnvEntryV1,
        RequestV1, SubmittedAuthContextV1, TOOL_REQUEST_TYPE, TOOL_WIRE_VERSION,
        ToolApprovalRequestV1, ToolContextV1, ToolHarnessV1, TrustedAuthContextV1, VERSION_V1,
        encode_base64url,
    };

    /// The fixture names, in mockup order (sections 3 to 6).
    pub const NAMES: &[&str] = &["local-sudo", "oven-headless", "claude-edit", "no-reason"];

    /// The hostname the local fixtures use for "this Mac".
    pub const LOCAL_HOST: &str = "adams-macbook";

    fn sudo_request(now: i64) -> RequestV1 {
        RequestV1 {
            version: VERSION_V1,
            request_id: "preview-local-sudo".into(),
            nonce: encode_base64url(&[7; 16]),
            host: LOCAL_HOST.into(),
            user: "hev".into(),
            uid: 501,
            runas_uid: 0,
            cwd: "/Users/hev/workspace/kit".into(),
            tty: Some("/dev/ttys004".into()),
            command: "/bin/launchctl".into(),
            argv: vec![
                "launchctl".into(),
                "bootstrap".into(),
                "system".into(),
                "/Library/LaunchDaemons/com.hev.hevd.plist".into(),
            ],
            pid_chain: vec![
                "61204:vouch".into(),
                "61203:sudo".into(),
                "61190:-zsh".into(),
                "58817:claude".into(),
                "1022:tmux".into(),
            ],
            env: vec![
                EnvEntryV1 {
                    name: "PATH".into(),
                    value: "/usr/bin:/bin:/usr/sbin:/sbin".into(),
                },
                EnvEntryV1 {
                    name: "HOME".into(),
                    value: "/var/root".into(),
                },
                EnvEntryV1 {
                    name: "TERM".into(),
                    value: "xterm-ghostty".into(),
                },
            ],
            session: Some("foh-hev-4".into()),
            reason: Some(
                "Reload the hevd launch daemon so the new cluster gossip port takes effect. \
                 The plist changed in the last commit; nothing else is touched."
                    .into(),
            ),
            issued_at: now - 47,
            expires_at: now + 43,
        }
    }

    fn oven_request(now: i64) -> AuthRequestV1 {
        AuthRequestV1 {
            message_type: AUTH_REQUEST_TYPE.into(),
            version: AUTH_WIRE_VERSION,
            request_id: "preview-oven-headless".into(),
            nonce: encode_base64url(&[8; 16]),
            issued_at: now - 8,
            expires_at: now + 112,
            trusted: TrustedAuthContextV1 {
                host: "oven".into(),
                service: "sudo-rs".into(),
                pam_user: "root".into(),
                pam_uid: 0,
                invoking_uid: 1000,
                invoking_user: Some("ubuntu".into()),
                tty: None,
            },
            submitted: SubmittedAuthContextV1 {
                session: Some("d-kit-subscriptions-edge-20261118".into()),
                agent_label: Some("codex".into()),
                reason: Some(
                    "Install the libssl headers the edge test build needs. The order's \
                     acceptance step requires a clean cargo test on Oven."
                        .into(),
                ),
                invocation: AuthInvocationV1::Available {
                    command: "/usr/bin/apt-get".into(),
                    argv: vec![
                        "sudo".into(),
                        "apt-get".into(),
                        "install".into(),
                        "-y".into(),
                        "libssl-dev".into(),
                        "pkg-config".into(),
                    ],
                    cwd: "/home/ubuntu/runs/kit".into(),
                },
            },
        }
    }

    fn edit_request(now: i64) -> ToolApprovalRequestV1 {
        let tool_input = json!({
            "file_path": "claude/hooks/slack-notify.py",
            "old_string": "SECRETS = Path.home() / \".claude/secrets\"",
            "new_string": "SECRETS = Path.home() / \"shell/op-env.sh\"",
        });
        ToolApprovalRequestV1 {
            message_type: TOOL_REQUEST_TYPE.into(),
            version: TOOL_WIRE_VERSION,
            request_id: "preview-claude-edit".into(),
            nonce: encode_base64url(&[9; 16]),
            harness: ToolHarnessV1::Claude,
            event: "PermissionRequest".into(),
            tool_name: "Edit".into(),
            native_event_json: json!({
                "hook_event_name": "PermissionRequest",
                "tool_name": "Edit",
                "tool_input": tool_input,
                "cwd": "/Users/hev/shell",
                "session_id": "1a9091a3-671b-4141-b4cf-93b62c3cea1c",
            })
            .to_string(),
            tool_input,
            cwd: "/Users/hev/shell".into(),
            context: ToolContextV1 {
                session_id: Some("1a9091a3-671b-4141-b4cf-93b62c3cea1c".into()),
                ..ToolContextV1::default()
            },
            description: Some(
                "Point the Slack hook at op-env.sh instead of the retired secrets file, \
                 as the README asks."
                    .into(),
            ),
            issued_at: now - 20,
            expires_at: now + 70,
        }
    }

    fn typed_request(now: i64) -> RequestV1 {
        RequestV1 {
            request_id: "preview-no-reason".into(),
            cwd: "/Users/hev".into(),
            command: "/usr/bin/dscacheutil".into(),
            argv: vec!["dscacheutil".into(), "-flushcache".into()],
            pid_chain: vec![
                "70411:vouch".into(),
                "70410:sudo".into(),
                "70388:-zsh".into(),
                "1022:tmux".into(),
            ],
            env: vec![],
            session: Some("shell".into()),
            reason: None,
            issued_at: now - 32,
            expires_at: now + 58,
            ..sudo_request(now)
        }
    }

    /// The fixture `name` as it would look at `now`, or `None` for an
    /// unknown name.
    pub fn view(name: &str, now: i64) -> Option<PanelView> {
        Some(match name {
            "local-sudo" => super::sudo_view(&sudo_request(now), LOCAL_HOST),
            "oven-headless" => super::authentication_view(&oven_request(now), LOCAL_HOST),
            "claude-edit" => super::tool_view(&edit_request(now), Some("shell")),
            "no-reason" => super::sudo_view(&typed_request(now), LOCAL_HOST),
            _ => return None,
        })
    }

    /// The sheet text the same fixture would put on the Touch ID sheet, for
    /// the requests that have one.
    pub fn sheet(name: &str, now: i64) -> Option<String> {
        match name {
            "local-sudo" => Some(super::sheet_reason(&sudo_request(now), LOCAL_HOST)),
            "oven-headless" => Some(super::sheet_authentication_reason(
                &oven_request(now),
                LOCAL_HOST,
            )),
            "no-reason" => Some(super::sheet_reason(&typed_request(now), LOCAL_HOST)),
            _ => None,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Every fixture is a request that validates, so a preview never
        /// shows something the agent would have refused.
        #[test]
        fn fixtures_are_valid_requests() {
            let now = 2_000_000_000;
            sudo_request(now).validate().unwrap();
            typed_request(now).validate().unwrap();
            oven_request(now).validate().unwrap();
            edit_request(now).validate().unwrap();
            for name in NAMES {
                assert!(view(name, now).is_some(), "{name}");
            }
            assert!(view("nope", now).is_none());
        }

        #[test]
        fn fixtures_match_the_mockup_text() {
            let now = 2_000_000_000;
            let local = view("local-sudo", now).unwrap().text(now);
            assert!(local.contains("0:43"), "{local}");
            assert!(
                local.contains("[tmux] [claude] [this Mac] [~/workspace/kit]"),
                "{local}"
            );
            let oven = view("oven-headless", now).unwrap().text(now);
            assert!(oven.contains("d-kit-subscriptions-edge-20261118"), "{oven}");
            assert!(
                oven.contains("[headless] [codex] [remote · oven] [~/runs/kit]"),
                "{oven}"
            );
            assert!(
                oven.contains("root@oven $ sudo apt-get install -y libssl-dev pkg-config"),
                "{oven}"
            );
            assert!(
                oven.contains("rather than signing this exact command"),
                "{oven}"
            );
            let edit = view("claude-edit", now).unwrap().text(now);
            assert!(
                edit.contains("WHAT IT WANTS (Edit · claude/hooks/slack-notify.py)"),
                "{edit}"
            );
            assert!(
                edit.contains("-SECRETS = Path.home() / \".claude/secrets\""),
                "{edit}"
            );
            let typed = view("no-reason", now).unwrap().text(now);
            assert!(typed.contains("No reason given."), "{typed}");
            assert!(
                typed.contains("[tmux] [zsh · typed by you] [this Mac]"),
                "{typed}"
            );
            assert_eq!(
                sheet("local-sudo", now).unwrap(),
                "foh-hev-4 wants sudo launchctl bootstrap system /Library/LaunchDaemons/com.hev.hevd.plist"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vouch_protocol::{EnvEntryV1, VERSION_V1, encode_base64url};

    fn request() -> RequestV1 {
        RequestV1 {
            version: VERSION_V1,
            request_id: "req-1".into(),
            nonce: encode_base64url(&[1; 16]),
            host: "adams-macbook".into(),
            user: "hev".into(),
            uid: 501,
            runas_uid: 0,
            cwd: "/Users/hev/workspace/kit".into(),
            tty: Some("/dev/ttys004".into()),
            command: "/bin/launchctl".into(),
            argv: vec![
                "launchctl".into(),
                "bootstrap".into(),
                "system".into(),
                "/Library/LaunchDaemons/com.hev.hevd.plist".into(),
            ],
            pid_chain: vec![
                "900:vouch".into(),
                "899:sudo".into(),
                "898:-zsh".into(),
                "897:/usr/local/bin/claude".into(),
                "896:tmux".into(),
            ],
            env: vec![EnvEntryV1 {
                name: "PATH".into(),
                value: "/usr/bin".into(),
            }],
            session: Some("foh-hev-4".into()),
            reason: Some("Reload hevd".into()),
            issued_at: 1_000,
            expires_at: 1_090,
        }
    }

    #[test]
    fn the_sheet_reads_session_wants_sudo_argv() {
        assert_eq!(
            sheet_reason(&request(), "Adams-MacBook.local"),
            "foh-hev-4 wants sudo launchctl bootstrap system /Library/LaunchDaemons/com.hev.hevd.plist"
        );
    }

    #[test]
    fn the_sheet_names_a_remote_host() {
        let mut request = request();
        request.host = "oven".into();
        assert!(
            sheet_reason(&request, "adams-macbook")
                .starts_with("foh-hev-4 wants sudo on oven launchctl"),
            "{}",
            sheet_reason(&request, "adams-macbook")
        );
    }

    #[test]
    fn the_sheet_shortens_paths_before_cutting_the_tail() {
        let mut request = request();
        request.argv.push(format!("/very/long/{}", "x".repeat(80)));
        let reason = sheet_reason(&request, "adams-macbook");
        assert!(
            reason.chars().count() <= MAX_APPROVAL_REASON_CHARS,
            "{reason}"
        );
        assert!(reason.contains("…/com.hev.hevd.plist"), "{reason}");
        assert!(
            reason.starts_with("foh-hev-4 wants sudo launchctl"),
            "{reason}"
        );
    }

    #[test]
    fn the_sheet_without_a_session_names_user_and_host() {
        let mut request = request();
        request.session = None;
        request.pid_chain.clear();
        request.tty = None;
        assert!(
            sheet_reason(&request, "adams-macbook").starts_with("hev@adams-macbook wants sudo "),
            "{}",
            sheet_reason(&request, "adams-macbook")
        );
    }

    #[test]
    fn the_sheet_does_not_double_sudo_and_escapes() {
        let mut request = request();
        request.argv = vec!["sudo".into(), "echo".into(), "\u{1b}[2J".into()];
        let reason = sheet_reason(&request, "adams-macbook");
        assert!(reason.starts_with("foh-hev-4 wants sudo echo "), "{reason}");
        assert!(!reason.contains('\u{1b}'), "{reason}");
    }

    #[test]
    fn the_panel_answers_who_why_and_what_in_order() {
        let view = sudo_view(&request(), "adams-macbook");
        let text = view.text(1_047);
        let who = text.find("WHO'S ASKING").unwrap();
        let why = text
            .find("WHY (the agent's own words, not verified)")
            .unwrap();
        let what = text
            .find("WHAT WILL RUN (verified, signed exactly)")
            .unwrap();
        assert!(who < why && why < what, "{text}");
        assert!(text.contains("  foh-hev-4\n"), "{text}");
        assert!(
            text.contains("[tmux] [claude] [this Mac] [~/workspace/kit]"),
            "{text}"
        );
        assert!(
            text.contains("root@adams-macbook $ sudo launchctl bootstrap system"),
            "{text}"
        );
        assert!(text.contains("as   root (from hev)"), "{text}");
        assert!(text.contains("env  1 variable (collapsed)"), "{text}");
        assert!(text.contains("0:43"), "{text}");
    }

    #[test]
    fn a_remote_host_gets_a_remote_chip() {
        let mut request = request();
        request.host = "oven".into();
        let view = sudo_view(&request, "adams-macbook");
        assert!(
            view.who
                .chips
                .iter()
                .any(|chip| chip.tone == ChipTone::Remote && chip.text == "remote · oven")
        );
    }

    #[test]
    fn a_missing_reason_is_stated_and_a_hostile_one_is_escaped() {
        let mut request = request();
        request.reason = None;
        assert!(
            sudo_view(&request, "h")
                .text(1_000)
                .contains("No reason given.")
        );
        request.reason = Some("ok \u{1b}]52;c;Zm9v\u{7}".into());
        let why = sudo_view(&request, "h").why.unwrap();
        assert!(!why.contains('\u{1b}') && !why.contains('\u{7}'), "{why:?}");
    }

    #[test]
    fn a_shell_at_the_top_of_a_short_chain_was_typed_by_you() {
        let mut request = request();
        request.session = Some("shell".into());
        request.pid_chain = vec![
            "900:vouch".into(),
            "899:sudo".into(),
            "898:-zsh".into(),
            "897:tmux".into(),
        ];
        let chips: Vec<_> = sudo_view(&request, "adams-macbook")
            .who
            .chips
            .into_iter()
            .map(|chip| chip.text)
            .collect();
        assert_eq!(chips[..3], ["tmux", "zsh · typed by you", "this Mac"]);
    }

    #[test]
    fn session_falls_back_through_env_pid_chain_and_tty() {
        let mut request = request();
        request.session = None;
        request.env.push(EnvEntryV1 {
            name: "VOUCH_SESSION".into(),
            value: "from-env".into(),
        });
        assert_eq!(session_name_for(&request).as_deref(), Some("from-env"));
        request.env.clear();
        assert_eq!(session_name_for(&request).as_deref(), Some("claude[897]"));
        request.pid_chain.clear();
        assert_eq!(session_name_for(&request).as_deref(), Some("ttys004"));
    }
}
