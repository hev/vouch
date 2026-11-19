# Debian and Ubuntu apt repository

> **Not published yet.** Vouch has no apt repository or archive signing key
> yet, and the release workflow's publishing jobs are switched off (see
> [releases](releases.md#publishing-is-off)). Until then, build the `.deb`
> yourself as described in [installation](install.md#debian-or-ubuntu). The
> steps below describe the repository as it will work once it exists, at
> `https://hev.github.io/vouch`. Replace `ARCHIVE_FINGERPRINT` with the
> published key's fingerprint at that point.

Configure apt to install and update Vouch from
`https://hev.github.io/vouch`.

Published archive signing fingerprint: **ARCHIVE_FINGERPRINT** (not yet issued).

## Install

Download and inspect the scoped archive key. The command stops before
installing it unless the keyring has exactly one primary public key with the
published fingerprint:

```sh
(
  set -e
  keyring_tmp="$(mktemp)"
  trap 'rm -f "$keyring_tmp"' EXIT
  expected_fingerprint='ARCHIVE_FINGERPRINT'
  curl --fail --show-error --silent --location \
    https://hev.github.io/vouch/vouch-archive-keyring.gpg \
    --output "$keyring_tmp"
  gpg --show-keys --with-fingerprint "$keyring_tmp"
  keyring_info="$(gpg --show-keys --with-colons "$keyring_tmp")"
  public_key_count="$(printf '%s\n' "$keyring_info" \
    | awk -F: '$1 == "pub" { count++ } END { print count + 0 }')"
  actual_fingerprint="$(printf '%s\n' "$keyring_info" \
    | awk -F: '$1 == "fpr" { print toupper($10); exit }')"
  if [ "$public_key_count" != 1 ] || [ "$actual_fingerprint" != "$expected_fingerprint" ]; then
    echo 'Vouch archive key must contain exactly one public key matching the published fingerprint.' >&2
    exit 1
  fi
  sudo install -d -m 0755 /etc/apt/keyrings
  sudo install -m 0644 "$keyring_tmp" \
    /etc/apt/keyrings/vouch-archive-keyring.gpg
)
```

Add the repository with `Signed-By` so this key is trusted only for the
Vouch repository:

```sh
printf '%s\n' \
  'deb [arch=amd64 signed-by=/etc/apt/keyrings/vouch-archive-keyring.gpg] https://hev.github.io/vouch stable main' \
  | sudo tee /etc/apt/sources.list.d/vouch.list >/dev/null
sudo apt update
sudo apt install vouch
```

For package updates, follow [update and restore](update.md#debian-or-ubuntu).

For a one-time package install, follow
[Debian or Ubuntu installation](install.md#debian-or-ubuntu).

See [the runbook](../RUNBOOK.md#maintain-the-apt-repository) for signing,
rotation, and repository publishing.
