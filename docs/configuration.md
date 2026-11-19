# Configuration reference

For setup commands, use [local sudo](local-sudo.md),
[remote sudo](remote-sudo.md), or [phone enrollment](phone-enrollment.md).

## Where settings live

| File | Owner and purpose |
| --- | --- |
| `/etc/vouch/install.env` | Root-owned, mode 0600; installer inputs |
| `/etc/vouch/config.env` | Root-owned hook runtime settings; the sudo lanes never read the caller's environment |
| `/etc/vouch/hook.json` | Hook origin, RP ID, and server URL |
| `/etc/vouch/devices.json` | Pinned device registry |
| `~/.config/vouch/agent.json` | User-owned, mode 0600; native identity |
| `~/.config/vouch/agent.env` | Agent environment for terminal startup |
| `${XDG_CONFIG_HOME:-~/.config}/vouch/approvals/<profile>/` | User-owned, mode 0700; browser approval profile and pinned browser devices |
| Mac LaunchAgent plist | Agent environment for autostart; private because it can contain credentials |
| `/etc/vouch/server.env` | Environment for the Debian system server |

The installer rejects symlinked, non-root-owned, or non-0600 configuration and
unknown keys. Setup helpers preserve existing identities and device records.

## Device revocation

`vouch revoke <fingerprint>` first durably disables the local device, then
waits for remote confirmation and removes its local record. A remote failure
leaves an inactive record; retry the same command to finish. Pinning or enrolling
that fingerprint is refused while revocation is pending. A cleanup write can
fail after replacing the file: the error reports remote confirmation and the
observed local state separately. An absent local record can still be retried.

Each local revoke increments `revocation_epoch` in `devices.json`. This
invalidates **all outstanding command and authentication requests**, including
requests addressed to other devices. Newly captured requests can proceed. A
command authorized before the local disable commit may still execute afterward;
revocation does not cancel an authorization that already passed its final gate.

The registry directory must belong to the hook's effective user with no group
or other access (normally root, mode 0700); the registry and stable
`.devices.lock` / `.devices-lifecycle.lock` files must also be private regular
files (normally mode 0600). Symlinks are refused. Do not delete or replace lock
files while hooks are running. Hook installation, Debian reconfiguration, and
phone configuration tighten an existing owner-controlled directory (including
legacy mode 0750) to 0700 without rewriting the registry or replacing locks.
They refuse symlinked, foreign-owned, or group/world-writable directories; fix
those paths explicitly before setup. Concurrent management operations return a
busy error and can be retried. Enrollment and revocation serialize their bounded
remote work separately from short registry transactions.

Legacy registries without an epoch load as epoch zero. Wire records and signed
request bytes are unchanged. Every new hook mutation preserves the epoch and
signature-counter high-water marks. Older hooks ignore the epoch and do not
participate in locking: running mixed versions or rolling back restores the
revocation race. The lifecycle lock orders live cooperating local operations;
it cannot fence delayed remote messages from an earlier timeout or crash.

## NATS settings

These apply separately to the hook, server, and native agent:

| Variable | Meaning |
| --- | --- |
| `NATS_URL` | Broker URL; use `tls://` outside loopback. TLS checks hostname and system trust roots. |
| `NATS_USER`, `NATS_PASS` | Set both together. Give each role its own credentials. |
| `VOUCH_ALLOW_PLAINTEXT_NATS` | Development-only override: `1`, `true`, or `yes`. |
| `VOUCH_TRANSPORT` | `nats`, the only configurable backend (hook/server). |

A hook without `NATS_URL` must have a local socket. An agent without it serves
only the socket. Browser approvals always need the server/NATS path.

Laptop setup takes the **agent's** role from `VOUCH_AGENT_NATS_URL`,
`VOUCH_AGENT_NATS_USER`, and `VOUCH_AGENT_NATS_PASS`. In server mode those
go in `install.env`; local setup reads them from its environment. It never
copies hook credentials to the agent. Re-runs preserve an existing LaunchAgent
environment unless `--reconfigure` is supplied.

## Hook and installer

| Setting | Meaning |
| --- | --- |
| `VOUCH_CONFIG_DIR` | Hook state directory for operator verbs, default `/etc/vouch`; a user-owned directory keeps the caller's curl config for development. Ignored by the sudo `check` and `authenticate` verbs. |
| `VOUCH_ORIGIN`, `VOUCH_RP_ID` | Installer inputs for the browser origin and relying-party hostname. |
| `VOUCH_AGENT_SOCKET` | Socket path in hook `config.env`; tried before NATS. |
| `VOUCH_LOG` | Hook terminal logging, e.g. `info` or `audit=info`; set in `config.env`. |
| `VOUCH_CONTEXTUAL_PAM=1` | Explicit opt-in for Debian package migration; laptop setup also accepts it in the environment or `--contextual-pam`. |
| `VOUCH_SUDO_USER` | User for the plugin's sudoers rule; otherwise the installer uses `SUDO_USER`. |
| `HOOK_BIN`, `PLUGIN_BIN`, `PAM_MODULE_BIN`, `VOUCH_CHECKSUMS` | Optional artifact overrides; packaged installers discover their own files. |
| `VOUCH_OPENER` | Test-only executable override for `watch`; receives one URL argument. |

PAM opt-in waits until a hardware-backed device is active. Once migrated, host
state keeps subsequent package updates on PAM even if the opt-in key is removed.

## Native agent

| Variable | Meaning |
| --- | --- |
| `VOUCH_AGENT_STATE` | Identity directory, default `~/.config/vouch`; `--state` also selects it. |
| `VOUCH_AGENT_SOCKET` | Default `agent.sock` inside the identity directory. A live socket prevents a second agent. |
| `RUST_LOG` | Agent diagnostics. The privileged sudo hook does not honor caller-controlled `RUST_LOG`. |

## Server

These are binary defaults, not Compose test values:

| Variable | Default / meaning |
| --- | --- |
| `VOUCH_LISTEN` | `127.0.0.1:8443`; put HTTPS in front of this HTTP listener. |
| `VOUCH_ORIGIN` | Public HTTPS origin; must match the hook and browser. |
| `VOUCH_RP_ID` | WebAuthn relying-party hostname. Keep stable after enrollment. |
| `VOUCH_STATE_PATH` | Writable SQLite database path; use persistent storage. |
| `VOUCH_VAPID_KEY_PATH` | Defaults beside the database to `vapid-private.pem`; created privately on first start. Preserve across updates. |
| `VOUCH_VAPID_SUBJECT` | Defaults to the origin; optional `https:` or `mailto:` contact URI. |
| `VOUCH_NTFY_URL` | Optional independent notification broker. |
| `VOUCH_DARWIN_DIST` | Optional directory of immutable Mac distribution artifacts. |

`/healthz` reports server and Web Push readiness; it cannot prove delivery to a
phone. See [server requirements](requirements.md) for infrastructure.

## Session labels and reasons

Set a label in the shell invoking sudo:

```sh
export VOUCH_SESSION=maintenance
# Or, inside tmux:
export VOUCH_SESSION=$(tmux display-message -p '#S')
```

An agent can add its own reason for one command:

```sh
VOUCH_REASON="Reload hevd so the new gossip port takes effect" sudo launchctl kickstart -k system/com.hev.hevd
```

The plugin captures both before sudo's environment reset. Labels are limited
to 64 printable characters after trimming, reasons to 500; invalid values are
ignored. `OSHIOKI_SESSION` is still read for one release when `VOUCH_SESSION`
is unset. Both are display text in the approval panel and never affect what is
verified or run. Over SSH, set the variables on the remote host or configure
SSH's `SendEnv`/`AcceptEnv` pair.

## Development and browser relay

`scripts/dev` manages `VOUCH_UID`, `VOUCH_HOST_UID`,
`VOUCH_STATE_ROOT`, and `VOUCH_HTTP_PORT`. Test-only overrides belong to
the test harness. See [contributing](../CONTRIBUTING.md).

The browser relay uses its own private JSON configuration and signing keys;
see [browser ceremonies](browser-ceremony-relay.md).
