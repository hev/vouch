# Vouch

<p align="center"><img src="assets/vouch.svg" alt="Vouch placeholder logo" width="160"></p>

Adds Touch ID, WebAuthn, or native device approval to `sudo`. You vouch for
a command with your fingerprint.

Vouch is a fork of [Oshioki](https://github.com/epsalmond/oshioki) by
epsalmond, dual-licensed MIT OR Apache-2.0 like the original (see
[LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE)). The sudo
plugin, Secure Enclave signing, the NATS lane and contextual PAM are
upstream's work. This fork renames the tool and adds a review panel beside
the Touch ID sheet that shows who is asking, why, and what will run. Wire
formats, signing domains and NATS subjects still use the `oshioki` spelling,
so a Vouch install talks to Oshioki 0.4.x hosts unchanged.

WebAuthn runs in a WebAuthn-compatible browser. Native approvals use
`vouch-agent`.

The command and environment are encrypted. Approvals are signed.
A local Unix socket is available for native approvals.
NATS with JetStream connects your servers, VMs, etc to your
phone or laptop.

## The review panel

When a Mac agent raises the Touch ID sheet it also opens a small panel next
to it. The panel has three sections, in this order:

1. **Who's asking:** the session (`VOUCH_SESSION`, a tmux session or a
   dispatch run name), with chips for how it runs, the harness, the host and
   the folder.
2. **Why:** the agent's own words from `VOUCH_REASON`, labelled as
   unverified. "No reason given." when there is none.
3. **What will run:** the exact argv, run-as user, cwd, tty and environment
   from the signed request.

The panel has no Approve button; Touch ID on the sheet is the approval. Esc
or Deny cancels. Set `VOUCH_PANEL=0` in the agent's environment to turn it
off. See [Mac approvals](docs/mac-approvals.md#the-review-panel).

## Install

Vouch has no Homebrew tap or apt repository yet. Build it from source on an
Apple Silicon Mac:

```sh
git clone https://github.com/hev/vouch && cd vouch
scripts/vouch-laptop-setup --local   # builds, bundles Vouch.app, installs
```

See [installation](docs/install.md) for source builds, Linux hosts, and host
activation.

## Choose your task

| I want to… | Guide |
| --- | --- |
| Approve sudo on this Mac | [Local sudo](docs/local-sudo.md) |
| Approve a server or VM's sudo from my Mac | [Remote sudo](docs/remote-sudo.md) |
| Approve sudo from my phone | [Phone enrollment](docs/phone-enrollment.md) |
| Approve Codex or Claude Code permission prompts from a browser | [Harness approvals](docs/harness-approvals.md) |
| Approve a Google CLI login with Touch ID, locally or remotely | [Browser ceremonies](docs/browser-ceremony-relay.md) |
| Update an existing installation | [Update and restore](docs/update.md) |
| Build, change, or test Vouch | [Contributing](CONTRIBUTING.md) |
| Diagnose an approval or recover sudo | [Runbook](RUNBOOK.md) |

An opt-in setup helper can route the exact `gcloud auth login` command through
the browser relay; other gcloud commands and login forms with flags pass
through unchanged. Vercel login is not supported yet. See the
[Google Cloud CLI login guide](docs/browser-ceremony-relay.md).

## Reference

[Configuration](docs/configuration.md) ·
[Native identity and pairing](docs/native-agent.md) ·
[Mac approval behavior](docs/mac-approvals.md) ·
[Server requirements](docs/requirements.md) ·
[Architecture](docs/architecture.md) ·
[Transport contract](docs/transports.md) ·
[Compatibility contract](docs/compatibility.md)

[Security policy](SECURITY.md) · [Changelog](CHANGELOG.md) ·
Licensed under [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE).
