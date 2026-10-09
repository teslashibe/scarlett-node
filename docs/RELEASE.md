# Releasing Scarlett Node

One release ships the three desktop installers, the three headless bundles, the
updater signatures and one changelog entry. Publishing it starts automatic
installs on nodes that opted in, so each step below is a gate.

## 1. Version bump pull request

1. Set the version in every file `release-manifest.py check-version` reads:
   `desktop/src-tauri/tauri.conf.json`, `desktop/package.json`,
   `desktop/package-lock.json` (twice), `desktop/src-tauri/Cargo.toml`,
   `desktop/src-tauri/Cargo.lock` and `NodeRelease` in
   `internal/coordinator/release.go`.
2. Write `release-notes/<version>.json` (rules in `release-notes/README.md`):
   a title, one to three highlights written for operators, and the planned date.
   This one file becomes the app's "Updated to" banner, the update notice's
   "What's new", the public changelog entry and the GitHub release body.
3. Compatibility rule: a release must keep every local file readable by the
   previous release, because rollback runs it again. That includes
   `preferences.json` and its extensions, the attempt journal, `status.json` and
   `update-state.json`. `update-state.json` is also read by the previous
   release's guard during an update: add fields only together with a reader that
   ignores them in the release before.
4. Run `python3 desktop/scripts/release-manifest.py check-version <version>` and
   the usual test suites, then merge.

## 2. Build and sign

Dispatch `desktop release` on `main` with the version. It builds and signs the
installers, builds the headless bundles, signs all six files for the updater in
`updater_sign` and assembles `scarlett-node-release-<version>`. Without the
`SCARLETT_UPDATER_MINISIGN_KEY` and `SCARLETT_UPDATER_MINISIGN_PASSWORD`
secrets in the `release-signing` environment the release has no `updates`: apps
then show the download page instead of installing. The updater keys are pinned
with `desktop/scripts/signing_identities.py set-updater-keys` (public keys only;
the private keys stay in `~/.scarlett-signing` and the environment secret).

Review the artifact: `release/manifest.json` (`notes`, `updates.keyId` equal to
the primary key in `desktop/signing/identities.json`), `release/changelog.json`,
`evidence/` and `SHA256SUMS`.

## 3. Publish

On the download host, with the k8s-control publisher (which verifies every
signature again against its reviewed `node-updater-keys.json`):

```sh
python3 baremetal/scarlett/publish-node-downloads.py /path/to/scarlett-node-release-<version>/release
```

It writes the immutable `/downloads/v<version>/`, then selects `manifest.json`
and `changelog.json`. Then create the GitHub release from the same notes:

```sh
gh release create v<version> --title "Scarlett Node <version>" \
  --notes-file scarlett-node-release-<version>/evidence/release-notes.md \
  scarlett-node-release-<version>/release/Scarlett-Node-<version>-* \
  scarlett-node-release-<version>/release/scarlett-node-<version>-*.tar.gz
```

(For an unsigned release the bundles are in `headless/` instead of `release/`.)

## 4. Check and watch

- `https://network.scarlett.ai/downloads/manifest.json` and
  `/downloads/changelog.json` name the new version;
  `https://network.scarlett.ai/changelog/#v<version>` shows its entry.
- The API now offers new jobs to this release and the one before it; nodes two
  releases behind see "Update required" and install at once in automatic mode.
- Optional updates spread over four hours. Watch
  `scarlett_network_nodes_by_version` through that window, starting with the
  canary nodes.

## Rollback lever

`publish-node-downloads.py --select-version <previous>` selects the retained
previous release again (manifest and changelog). Nodes that have not updated
stop at their next check; nodes already updated stay above the minimum and keep
working. A version that fails to start on a node is rolled back there by the
updater and skipped by automatic mode.
