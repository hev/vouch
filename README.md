# Vouch

<p align="center"><img src="assets/vouch-160.png" alt="Vouch logo: a pixel-art head holding up a gold key" width="160" height="160"></p>

Vouch lets you approve `sudo`, and the permission prompts from coding
agents such as Claude Code and Codex, with Touch ID. When an agent asks to
run something as root, a panel opens next to the Touch ID sheet and shows
who is asking, why, and exactly what will run. Your fingerprint is the
approval.

<p align="center"><img src="docs/images/panel-local-sudo.png" alt="The Vouch panel beside a sudo request from a tmux session" width="520"></p>

Approvals are signed by a key in the Mac's Secure Enclave, and the host
checks that signature before sudo runs anything. The same Mac can approve
sudo on servers and VMs over NATS, and a phone can approve through
WebAuthn.

## Quick start

On an Apple Silicon Mac:

```sh
git clone https://github.com/hev/vouch && cd vouch
scripts/vouch-laptop-setup --local   # builds, bundles Vouch.app, installs
```

Then run `sudo true`. The Touch ID sheet and the panel should appear.
Agent permission prompts are approved with a passkey (Touch ID on a Mac)
from an enrolled browser; see [harness approvals](docs/harness-approvals.md).
Vouch has no Homebrew tap or apt repository yet. [Installation](docs/install.md)
covers source builds and Linux hosts.

## How it works

1. sudo's approval plugin hands the exact request (argv, run-as user, cwd,
   environment) to the `vouch` hook.
2. The hook seals it to each paired device: the Mac's `vouch-agent` over a
   local socket, or a remote Mac or phone through the server and NATS.
3. The agent opens the review panel and the Touch ID sheet together. The
   panel has no Approve button. Touch ID approves; Esc or Deny cancels.
4. The Secure Enclave signs the request, and the hook verifies the signature
   before sudo continues.

The panel has three sections:

- **Who's asking:** the session name, with chips for the harness, the host
  (marked remote when it isn't this Mac) and the cwd.
- **Why:** the agent's own reason, labelled as unverified, or "No reason
  given."
- **What will run:** the exact argv, user, host, cwd and environment from
  the signed request.

Every request the Mac decides gets one line in an append-only approval log,
written before the signature is released; if the line can't be written,
the request is denied. `vouch log --since 2h` prints it as a table, and
hosts write their own syslog line per verdict. See
[the approval log](docs/mac-approvals.md#approval-log).

The server only routes ciphertext. It cannot make an approval the host will
accept. More detail is in [architecture](docs/architecture.md) and
[Mac approvals](docs/mac-approvals.md#the-review-panel).

## Session and reason

Two optional variables fill the panel's first two sections. sudo's plugin
reads them before `env_reset`:

```sh
export VOUCH_SESSION="$(tmux display -p '#S')"   # once per shell
VOUCH_REASON="Reload hevd for the new port" sudo launchctl kickstart -k system/com.hev.hevd
```

`VOUCH_SESSION` is at most 64 characters and `VOUCH_REASON` at most 500.
Values containing control characters are dropped. Both are for display
only and never change what is verified or run. `OSHIOKI_SESSION` is still
read for one release. For tool-permission prompts the reason comes from
the tool call itself, such as the Bash `description`. See
[configuration](docs/configuration.md#session-labels-and-reasons).

## Remote hosts

A server or VM runs the hook and the sudo plugin, and your Mac approves over
NATS with JetStream. Hosts that need PAM use contextual authentication. In
that mode Touch ID authenticates the sudo session instead of signing the
exact command, and the panel says so. Setup is in
[remote sudo](docs/remote-sudo.md). The wire format is unchanged from
Oshioki 0.4.x, so existing hosts keep working.

## Docs

| I want to… | Guide |
| --- | --- |
| Approve sudo on this Mac | [Local sudo](docs/local-sudo.md) |
| Approve a server or VM's sudo from my Mac | [Remote sudo](docs/remote-sudo.md) |
| Approve sudo from my phone | [Phone enrollment](docs/phone-enrollment.md) |
| Approve Codex or Claude Code permission prompts | [Harness approvals](docs/harness-approvals.md) |
| Approve a Google CLI login with Touch ID | [Browser ceremonies](docs/browser-ceremony-relay.md) |
| Change settings | [Configuration](docs/configuration.md) |
| Update an existing installation | [Update and restore](docs/update.md) |
| Diagnose an approval or recover sudo | [Runbook](RUNBOOK.md) |
| Build, change, or test Vouch | [Contributing](CONTRIBUTING.md) |

Reference: [native identity and pairing](docs/native-agent.md) ·
[server requirements](docs/requirements.md) ·
[transports](docs/transports.md) ·
[compatibility](docs/compatibility.md) ·
[security policy](SECURITY.md) · [changelog](CHANGELOG.md)

## License

[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE), at your option.

## Acknowledgements

Vouch is built on [Oshioki](https://github.com/epsalmond/oshioki) by
epsalmond, licensed MIT OR Apache-2.0. The sudo plugin, Secure Enclave
signing, the NATS lane and contextual PAM come from that project. For
compatibility with existing Oshioki installs, wire formats, signing domains,
NATS subjects and enrollment records still use the `oshioki` spelling.
