# Install Vouch

Install on each machine that runs sudo and each Mac that approves requests.
The browser login helper can be used on its own; it does not require sudo setup.

## macOS

Apple Silicon packages are available through Homebrew:

```sh
# Vouch has no Homebrew tap yet; from a checkout:
scripts/vouch-laptop-setup --local
```

Next, choose [local sudo](local-sudo.md), [remote sudo](remote-sudo.md),
[phone approval](phone-enrollment.md), [Codex or Claude Code browser
approvals](harness-approvals.md), or [Google login](browser-ceremony-relay.md).

Run setup helpers as your logged-in user. They request sudo when needed.
Mac identity creation and Touch ID require a graphical login session with an
unlocked login keychain.

## Debian or Ubuntu

Configure the signed [apt repository](apt-repository.md), then install with
apt:

```sh
sudo apt update
sudo apt install vouch
```

For a one-time install without configuring the repository, download the amd64
`.deb` built with `packaging/build-deb` (Vouch publishes no releases yet), then:

```sh
sudo apt install ./vouch_X.Y.Z_amd64.deb
```

The package includes the sudo hook, plugin, PAM module, server, phone setup
helper, browser relay, and the opt-in `vouch-google-login-setup` and
`vouch-browser-service` commands. Python 3 is installed as a runtime
dependency (3.9 or newer) for these commands. It does not include the Linux
native agent or laptop setup helper; use a source build for those.

A fresh install does not activate sudo approval without host configuration
and a pinned device. Continue with [remote sudo](remote-sudo.md) or
[phone approval](phone-enrollment.md). For Google login on this host, follow
the [Google Cloud CLI login](browser-ceremony-relay.md) instructions. Its
wrapper and background services remain opt-in.

## From source

Install Rust through rustup; this checkout selects its pinned toolchain.
Linux also needs the PAM development headers (`libpam0g-dev` on Debian/Ubuntu).

```sh
cargo build --locked --release --workspace
```

Binaries are under `target/release`. To configure local sudo from this checkout:

```sh
scripts/vouch-laptop-setup --local
```

For a manually configured host, create the installer manifest after building.
On Linux:

```sh
(cd target/release && sha256sum vouch libvouch_plugin.so libvouch_pam.so > SHA256SUMS)
```

On macOS:

```sh
(cd target/release && shasum -a 256 vouch libvouch_plugin.dylib libvouch_pam.dylib > SHA256SUMS)
```

Then use `scripts/install-vouch-hook` wherever a guide uses the packaged
installer. Hashes must describe the binaries from this build.

## Activate a manually configured sudo host

Use this after the phone or remote guide has configured the host and pinned
a device. Keep a second root shell open until verification succeeds.

The installer is `install-vouch-hook` on Homebrew,
`/usr/share/vouch/install-vouch-hook` on Debian, or
`scripts/install-vouch-hook` in a checkout. For Debian:

```sh
sudo /usr/share/vouch/install-vouch-hook --prelaunch --dry-run --config-file /etc/vouch/install.env
sudo /usr/share/vouch/install-vouch-hook --prelaunch --config-file /etc/vouch/install.env
sudo /usr/share/vouch/install-vouch-hook --prelaunch-status
sudo -k
sudo true
```

The final command must produce and complete an approval. A successful
`vouch test` checks delivery and signing, but does not prove sudo integration.

The installer preserves the device registry and leaves approval disabled
while it is empty. Hardware-backed devices qualify for its passwordless
sudoers rule; software native devices retain the normal sudo password.
The opt-in [PAM mode](local-sudo.md#sudo-authentication-through-pam) uses
sudo's authentication and timestamp behavior instead.

The passwordless rule is written only after root's `sudo -V` prints
`Vouch approval plugin version X.Y.Z`, which proves that this sudo loads
the plugin. Without that line the installer writes no rule, removes an
existing one, and exits with status 3. Sudo then keeps its password path.
`--prelaunch-status` reports `plugin loaded: yes` or `no` from the same check
and fails when a rule exists without a loaded plugin.

## Supported sudo

The approval plugin requires Todd Miller's sudo ([sudo.ws](https://www.sudo.ws))
1.9 or newer with approval-plugin support. macOS ships it, as does the
Debian and Ubuntu `sudo` package.

[sudo-rs](https://github.com/trifectatechfoundation/sudo-rs) is the default
`sudo` on Ubuntu 25.10 and later. It reads `/etc/sudoers.d` but has no
plugin API and ignores `/etc/sudo.conf`, so the plugin can never run there.
The installer detects sudo-rs from `sudo -V`, refuses the plugin lane, and
removes its passwordless rule.

Switching the `sudo` alternative back to classic sudo is not enough. The
sudo-rs binaries stay installed and setuid root (`/usr/bin/sudo-rs`,
`/usr/lib/cargo/bin/sudo`), and they still honour a `NOPASSWD` rule without
running the plugin. The installer therefore refuses the passwordless rule
whenever sudo-rs is installed, whichever `sudo` is selected. To use the
plugin lane on such a host, install classic sudo, remove the `sudo-rs`
package, and re-run the installer. The contextual
[PAM mode](local-sudo.md#sudo-authentication-through-pam) may work with
sudo-rs, but it has not been validated.

On Debian and Ubuntu, the package also enables `vouch-sudo-reconcile.path`.
It watches `/etc/sudo.conf`, the `sudo` alternative, `/usr/bin/sudo`, and
the sudo-rs paths. On any change it runs
`install-vouch-hook --reconcile-plugin-rule`, which repeats the proof and
removes the passwordless rule if the proof fails. It never writes the rule;
re-run `--prelaunch` to restore it once the host qualifies again.
