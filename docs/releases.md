# Release and recovery

## Publishing is off

Vouch has not published a release. The `release` workflow's `gate` job runs
only when the repository is `hev/vouch` and the repository variable
`VOUCH_RELEASES_ENABLED` is `true`. Every build, release and apt job needs
`gate`, so with the variable unset nothing is built or published. Tags
`v0.5.1` and older are upstream Oshioki releases and stay as they are.

Before turning publishing on:

1. Add a release signer to [`.github/signing/allowed_signers`](../.github/signing/README.md).
   It is empty now, so `scripts/verify-release-tag` rejects every tag.
2. Create the apt and provenance signing key and set the
   `APT_SIGNING_PRIVATE_KEY` secret and `APT_SIGNING_KEY_FINGERPRINT`
   variable. Publish the fingerprint in [the apt guide](apt-repository.md).
3. Enable GitHub Pages (Actions source) for the apt repository.
4. Set `VOUCH_RELEASES_ENABLED=true`.

## Signing

Sign new commits and annotated `vMAJOR.MINOR.PATCH` tags, and keep existing
history append-only. Release provenance binds each published package to its
verified source tag.

## Prepare a release

Update `[workspace.package].version` in `Cargo.toml`, run
`cargo update --workspace --offline`, and add the public changelog entry.
Run `scripts/test-release-signing`, `scripts/test-apt-repository`, and the
package/compatibility checks relevant to the release. Submit signed commits
for review, merge, and confirm the merged commit's signature and tree.

Use the signer in [the committed policy](../.github/signing/README.md). After
fetching complete history and tags from `hev/vouch`, create a signed
annotated tag on the exact reviewed main commit, then verify it:

```sh
git fetch origin main --tags
git tag -s vX.Y.Z REVIEWED_COMMIT_SHA -m 'Vouch vX.Y.Z'
scripts/verify-release-tag vX.Y.Z REVIEWED_COMMIT_SHA
```

Substitute the intended new version and commit; never move an existing tag.
Record the verifier's tag-object and source-commit SHAs. Tag creation/push
and publication require the maintainer's release decision. Keep competing
main merges paused through publication, and verify the same SHAs afterward.

The workflow fetches full history, verifies SSH tag identity against reviewed
main, requires direct commit targets reachable from main and matching
workspace/package/lockfile versions, and pins builds to that exact commit.
Verification requires a clean source tree. Before publication it checks the
tag again and checks both build jobs' recorded source identities.

The existing APT signing secret and fingerprint must be configured before a
release: the publish job uses that signer to create
`RELEASE-PROVENANCE.json.asc`, binding the verified tag object, source commit,
version, package/archive hashes, and `SHA256SUMS` hash. The key is exposed
only to the provenance signing step and APT signing step. This is a build
provenance assertion by the release workflow, not a reproducible-build proof
or Apple Developer ID signature. The SSH private signer never enters CI.

APT releases/rebuilds verify this manifest with the configured APT primary
fingerprint, independently verify the SSH source tag, and then check package
hashes and metadata before signing the index. Pre-v0.4.1 packages lack this
binding and are omitted from newly published APT indexes. Their existing
GitHub releases remain intact. Manual APT rebuild does not authorize a new
source release or an unsigned tag.

## Rotate a key

Confirm the replacement public key and fingerprint independently. Add it
through a reviewed PR signed by the existing signer, with a documented
overlap. Verify a disposable signature with the replacement before using it.
Remove the old release permission prospectively once the transition is
complete. For APT signing-subkey rotation keep the primary fingerprint and
the historical verification subkeys; a new primary key requires a client
keyring rollover and an explicit plan for old provenance signatures.

For a compromised SSH key, stop releases, record its public key in
`.github/signing/revoked_keys` through a reviewed signed recovery change,
and confirm the verifier rejects it. Consumers checking compromise need the
latest reviewed policy: an old tag's policy cannot know a later revocation,
and GitHub's persistent Verified record is not a current revocation check.
Do not silently re-sign or replace published assets/tags.

If the signer is lost, restore access on its host or establish a replacement
through an explicit, independently reviewed recovery decision. Keep signed
commit requirements enabled; do not bypass them or copy a private signer
into CI. Keep exact checkpoint SHAs in the recovery evidence.

## Recover a bad release

Use a signed revert or fix through review and publish a new version. Never
reset main, rewrite public history, force-move tags, or replace published
package bytes under the same version. Stop publication if verification fails.
After a security fix, roll back only to a release that includes the fix or
to a newer corrected release; compatibility rollback tests do not make a
vulnerable version an acceptable recovery target. Follow the
[compatibility restore procedure](compatibility.md) for state files.
