# Mac approvals

A Secure Enclave signature requires Touch ID. The Touch ID sheet belongs to
macOS: one line of text, capped at 160 characters. Vouch puts a short form
there, `<session> wants sudo <argv…>` (with `on <host>` for a remote host),
and shows the rest in a review panel beside the sheet. The complete command
and environment remain bound to the signature whatever either one displays.

Contextual PAM approvals authenticate a sudo session; their command context
is advisory. See [the mode comparison](local-sudo.md#sudo-authentication-through-pam).

## The review panel

The panel opens when the agent takes the one-sheet-at-a-time permit, just
before the sheet appears, and closes when the sheet is answered, dismissed,
cancelled or expires. It answers three questions in order:

| Section | Shows | Comes from |
| --- | --- | --- |
| Who's asking | The session as the headline; chips for tmux or headless, the harness or shell, the host (`remote · <host>` when it is not this Mac), and the cwd | `session` (from `VOUCH_SESSION`), `pid_chain`, `host`, `cwd`, `tty` |
| Why | The agent's own words, labelled "not verified", or "No reason given." | `reason` (from `VOUCH_REASON`) |
| What will run | `user@host $ sudo argv…`, run-as user, cwd, tty, and the bound environment (collapsed) | The signed request |

For a contextual PAM request (sudo-rs on a remote host) the "What" block says
that Touch ID authenticates the sudo session rather than signing the exact
command. For a Claude Code or Codex permission request it shows the tool: the
Bash command, the file and diff for Edit or Write, the URL for WebFetch.

There is no Approve button: Touch ID on the sheet approves. Esc or Deny in the
panel cancels the attempt, which is a denial like dismissing the sheet. A
countdown runs to the request's deadline. All text is escaped before it is
drawn.

Try it with nothing in flight:

```sh
vouch-agent preview-panel --fixture local-sudo      # also: oven-headless, claude-edit, no-reason
vouch-agent preview-panel --fixture no-reason --print
```

Set `VOUCH_PANEL=0` in the agent's environment (the LaunchAgent plist) to
turn the panel off.

| Local tmux sudo | Headless on Oven | Claude Edit | No reason |
| --- | --- | --- | --- |
| ![](images/panel-local-sudo.png) | ![](images/panel-oven-headless.png) | ![](images/panel-claude-edit.png) | ![](images/panel-no-reason.png) |

### Session and reason variables

`VOUCH_SESSION` names the session. Export it once per shell, for example from
tmux: `export VOUCH_SESSION="$(tmux display -p '#S')"`. `OSHIOKI_SESSION` is
still read for one release when `VOUCH_SESSION` is unset.

`VOUCH_REASON` carries the agent's reason for one command, for example from
a Claude Code PreToolUse hook that copies the Bash tool's `description`.
Both are read by the sudo plugin from the invoking environment before
`env_reset`, never from the environment the command runs with. A reason is
at most 500 characters with no control characters; anything else is dropped.
It is display text only and never affects what is verified or executed.

## Approval log

The agent appends one JSON line for every request it decides to
`~/Library/Logs/Vouch/approvals.jsonl` (set `VOUCH_APPROVAL_LOG` in the
agent's environment to move it; nothing turns it off). The file is created
mode 0600 in a 0700 directory, opened append-only and never through a
symlink, and only ever appended to.

Each line has:

| Field | What it holds |
| --- | --- |
| `ts`, `shown_at`, `decided_at` | When the line was written, the prompt raised, and the outcome known (RFC 3339, UTC) |
| `request_id`, `lane` | The request, and `sudo_exact`, `contextual_pam`, `browser_relay` or `tool` |
| `host`, `user`, `run_as` | Where the request came from, who asked and who it runs as |
| `session`, `reason` | `VOUCH_SESSION` and `VOUCH_REASON`, display text only |
| `command`, `argv`, `cwd`, `tty` | What will run. For contextual PAM this is the advisory invocation the host submitted |
| `env_names` | The names of the request's environment variables. **Values are never logged** |
| `outcome`, `error` | `approved`, `denied`, `expired`, `canceled` or `failed`, and why |
| `request_sha256`, `device_id` | SHA-256 of the exact request bytes the signature covers, and the signing device's fingerprint (its key's credential id on the browser-relay lane) |

`request_sha256` and `device_id` let you match a line to the host's own
record of the verification.

The log fails closed. A signature is released only after its line is written
and synced. If the line cannot be written, the signature is withheld, the
request is denied (the host times out), and the reason goes to
`~/.config/vouch/agent.log`. Outcomes with no signature (expired, canceled,
failed) are logged on a best-effort basis. A dismissed Touch ID sheet is
`canceled`; `denied` is a signed refusal from the terminal prompt.

Read it with `vouch log`:

```sh
vouch log                        # everything, as a table
vouch log --since 2h             # or 30m, 7d, or an RFC 3339 time
vouch log --session shell --json # one JSON line per match
```

Hosts keep their own record. The hook writes one `vouch verdict` line to
syslog's authpriv facility (journald on Linux, the unified log on macOS) for
each verdict it accepts or rejects, with the request id, user, argv and
outcome (`approved`, `denied`, `authenticated` or `rejected` with the
reason). Contextual PAM goes through the same hook, so it is covered too. On
Linux: `journalctl -t vouch | grep 'vouch verdict'`. On macOS:
`log show --last 1h --predicate 'process == "logger"' | grep 'vouch verdict'`.

The agent itself has no tool-permission lane yet; tool approvals happen in
the browser and are not in this log.

## Start at login

For a Mac whose own sudo is configured, use `vouch-laptop-setup` in the
[local](local-sudo.md) or [remote](remote-sudo.md) setup. It manages:

- `~/Library/LaunchAgents/com.hev.vouch.agent.plist`
- `~/.config/vouch/agent.log`

It verifies the packaged agent and uses Homebrew's stable `opt` path, so an
upgrade followed by cleanup does not break the next login.

For an approval-only Mac using a source checkout, pair it first and load its
device-role NATS environment, then:

```sh
scripts/mac/install-agent
```

This separate installer manages `dev.hev.vouch.agent` and logs to
`~/Library/Logs/vouch-agent.log`. It requires NATS and builds the app bundle
if needed. `--dry-run` previews a redacted plist; `--uninstall` removes this
LaunchAgent. Re-run it after rebuilding. Use only one installer/agent for an
identity at a time.

Check the service you installed:

```sh
launchctl print gui/$(id -u)/com.hev.vouch.agent
vouch-agent show
tail -f ~/.config/vouch/agent.log
```

For the source installer, substitute `dev.hev.vouch.agent` and its log path.

## Prompts and recovery

Only one Touch ID sheet can run at a time. A locked screen
cannot complete approval, and the request deadline ends an unanswered prompt.
Cancellation never approves a request. PAM cancellation leaves password
fallback available; command approval fails closed without a valid decision.

Set `OSHIOKI_SESSION` in the invoking shell to label requests. Without it the
summary uses a recognizable caller process or tty when available.

Adding or removing a Touch ID fingerprint invalidates the existing enclave
key. Retrying cannot repair that key: follow
[re-pairing](../RUNBOOK.md#re-pairing), then update every host that pinned it.

Identity creation and loading need the user's unlocked login keychain.
`User interaction is not allowed` usually means setup is running outside
that graphical session. Run setup in a Terminal window on the Mac.

For bundle signing and release checks, see [contributing](../CONTRIBUTING.md).
