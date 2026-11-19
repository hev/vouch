# Security policy

Vouch sits in the sudo approval path and handles keys and approvals.
Please treat it accordingly.

## Supported versions

Pre-1.0: only the current `main` branch receives security fixes. Once 1.0
ships, the two most recent minor releases will be supported.

Vouch has not published a release yet. Releases will be signed annotated
tags with package hashes bound to their verified source; the signer,
rotation and emergency recovery procedures are in the
[release guide](docs/releases.md). Tags up to v0.5.1 are upstream Oshioki
releases; report issues in them that also affect Vouch here. After a security fix, recovery must use a fixed release or
newer; do not roll back to a version known to be vulnerable.

## Reporting a vulnerability

Do **not** open a public issue or PR for a suspected vulnerability.

Vouch is maintained by Adam Hevenor. Report privately through GitHub's
private vulnerability reporting on
[hev/vouch](https://github.com/hev/vouch/security/advisories/new)
(Security tab → Report a vulnerability). Include:

- What you think is affected (crate, endpoint, device kind).
- Steps to reproduce or a proof of concept.
- What an attacker gains and what they need (local user? enrolled device?
  network position?).

You will get an acknowledgement within 72 hours and a remediation plan once
the report is confirmed. Please give us a reasonable window to fix before any
public disclosure, and do not exfiltrate or retain other users' data while
investigating.

## Scope notes for reviewers

- Plaintext sudo commands must never enter SQLite, logs, notifications, or
  metrics. ntfy messages may carry host, user, request ID, and `/r/<id>` URL
  only.
- The server stores routing data and opaque ciphertext; it must never be able
  to produce an approval the hook accepts.
- The sudo lanes (`vouch check`, `vouch authenticate`) never consult the
  caller's environment or working directory for configuration, transport, or
  helper execution: they restart in `/` with only a fixed `PATH`, read only
  `/etc/vouch`, and run curl with `-q`.
- Release agent builds must offer no prompt bypass: `run --auto` exists only
  under the `unattended` cargo feature.
- `unsafe` is confined to the macOS `enclave` crate and the existing sudo
  plugin's FFI, process, tty, and PAM boundary. New unsafe code elsewhere
  will be rejected.
