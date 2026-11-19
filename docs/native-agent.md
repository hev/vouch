# Native identities and pairing

For a complete setup, start with [local sudo](local-sudo.md) or
[remote sudo](remote-sudo.md). This page covers identity management.

## Commands

| Command | Purpose |
| --- | --- |
| `vouch-agent init` | Create an identity if none exists. |
| `vouch-agent pair '<enrollment-url>' --label <label>` | Pair with a host waiting in `sudo vouch enroll`. |
| `vouch-agent run` | Listen on the local socket and, when configured, NATS. |
| `vouch-agent show` | Show the fingerprint and signing backend. |
| `vouch-agent device-record --label <label>` | Export the public device record for offline pinning. |

The default state directory is `~/.config/vouch`; override it with
`--state` or `VOUCH_AGENT_STATE`. Its `agent.json` is private (0600).

## Identity lifetime

One identity can pair with many hosts. Ordinary `init` and `pair` preserve it.
`--force` replaces it, changes its fingerprint, and requires every paired host
to enroll or pin the new record and revoke the old one.

macOS defaults to a Secure Enclave signing key; other platforms use a software
P-256 key. `--signer software` explicitly selects the software backend on a
Mac. Software identities cannot replace sudo password authentication or approve
browser relay ceremonies.

On macOS the X25519 decryption secret lives in the login keychain; elsewhere
it is in the identity file. Legacy Mac files migrate without changing their
fingerprint and retain `agent.json.prev` for [restore](update.md#restore).

## Pair without a server

On the approval device:

```sh
vouch-agent init
vouch-agent device-record --label my-device > /tmp/vouch-device.json
```

Copy the public record to the host. On the approval device, read
`vouch-agent show` and send its fingerprint to the host over a trusted
channel independent of the record file. Compare it with the fingerprint
printed by `pin-record` before typing the full value to confirm:

```sh
sudo vouch pin-record /tmp/vouch-device.json
sudo vouch status
```

The record contains public material only. Offline pinning removes the server
dependency from pairing; it does not create a network transport between two
machines. Same-host approval can use the Unix socket. Remote approval still
needs NATS. Later server pairing preserves this fingerprint.

## Run the agent

Mac hardware approvals need a graphical login session but no terminal.
Use [Mac autostart](mac-approvals.md#start-at-login) for persistent operation.

A software agent needs a terminal for every decision. Linux setup writes
`~/.config/vouch/agent.env` and prints:

```sh
set -a
. ~/.config/vouch/agent.env
set +a
vouch-agent run
```

Keep that terminal open. No Linux user service is installed because it would
have no terminal to answer. Release builds have no automatic approval option;
`run --auto` exists only with the test-only `unattended` build feature.

NATS credentials are environment settings, separate from identity state.
Use the device role, with both `NATS_USER` and `NATS_PASS` set together.
See [configuration](configuration.md).
