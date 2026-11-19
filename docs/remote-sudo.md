# Approve remote sudo from a Mac

Run sudo on the **host** (server or VM); review and approve it on the **Mac**.
The Mac can use the same identity for local and remote sudo.

You need an Vouch HTTPS server and a TLS NATS broker reachable by both
machines. The deployment supplies separate hook and agent credentials;
see [server requirements](requirements.md). For a phone instead, use
[phone enrollment](phone-enrollment.md).

## 1. Configure the host

[Install Vouch](install.md). Create its root-owned configuration:

```sh
sudo install -d -m 0750 /etc/vouch
sudo install -m 0600 /dev/null /etc/vouch/install.env
sudoedit /etc/vouch/install.env
```

For a new host, enter:

```text
VOUCH_ORIGIN=https://sudo.example.com
VOUCH_RP_ID=sudo.example.com
NATS_URL=tls://nats.example.com:4222
NATS_USER=vouch-hook
NATS_PASS=<host-role-password>
```

For an existing host, edit its existing file rather than recreating it.
Use the installer path for your package; on Debian:

```sh
sudo /usr/share/vouch/install-vouch-hook --prelaunch --dry-run --config-file /etc/vouch/install.env
sudo /usr/share/vouch/install-vouch-hook --prelaunch --config-file /etc/vouch/install.env
sudo vouch enroll
```

Leave enrollment running. With an empty device registry, the installer prepares
the hook but leaves command approval disabled.

## 2. Pair the Mac

Install Vouch on the Mac. Put its device-role credentials in a mode-600
`~/.config/vouch/agent.env` file:

```text
NATS_URL=tls://nats.example.com:4222
NATS_USER=vouch-agent
NATS_PASS=<device-role-password>
```

Load them in a terminal in your logged-in graphical session, then run the
pairing command printed by the host:

```sh
set -a
. ~/.config/vouch/agent.env
set +a
vouch-agent pair '<enrollment-url>' --label my-mac
vouch-agent run
```

Pairing requires Touch ID. A second enrollment reuses the identity; do not
use `--force` when adding another host. Leave the agent running for the test.

For persistent operation, [Mac approvals](mac-approvals.md#start-at-login)
explains the two LaunchAgent installers. Do not start a second agent alongside
one already serving the same identity/socket.

## 3. Activate and verify on the host

After enrollment completes:

```sh
sudo vouch status
sudo vouch test
```

Approve the synthetic request on the Mac, then
[activate the host's sudo integration](install.md#activate-a-manually-configured-sudo-host)
and complete a real `sudo true`. Repeat host configuration and enrollment for
each additional server.

The Mac must be awake, reachable, and have a graphical login session.
If delivery fails, check the agent's credentials and subscriptions first:
using the hook's NATS role on the Mac causes subscription permission errors.

## Local and remote together

A Mac already configured with `vouch-laptop-setup --local` can keep using
its Unix socket for local sudo while the agent listens to remote NATS requests.
Supply `VOUCH_AGENT_NATS_URL`, `VOUCH_AGENT_NATS_USER`, and
`VOUCH_AGENT_NATS_PASS` in the setup environment and re-run
`vouch-laptop-setup --local --reconfigure`. Keep secrets in a private file,
not shell command arguments. These are the agent's credentials, separate from
the hook's NATS settings.

See [configuration](configuration.md) for those roles and
[the runbook](../RUNBOOK.md) for recovery.
