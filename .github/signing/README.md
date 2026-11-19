# Release signing policy

Release tags are verified against `allowed_signers` on reviewed `main` by
`scripts/verify-release-tag`. **No release signer is configured yet.** The
file is empty on purpose: upstream Oshioki's signer was removed when this
repository became Vouch, and an empty policy makes the verifier reject every
tag. Releases are also switched off in `release.yml` (see
[the release guide](../../docs/releases.md#publishing-is-off)).

To set up releases:

1. Generate or choose an SSH signing key for Adam's release host. Keep the
   private half there; it never goes to Actions.
2. Add one line to `allowed_signers` through a reviewed PR:
   `<principal> namespaces="git" ssh-ed25519 AAAA...`
   and record the principal and `SHA256:` fingerprint in this file.
3. Approve the fingerprint independently before merging. The verifier trusts
   the committed policy on fetched `origin/main`, never a key carried by the
   tag or supplied through the environment.

Rotation and emergency recovery are in [the release guide](../../docs/releases.md).
