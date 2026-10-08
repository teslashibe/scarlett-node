# Release notes

One file per node release, `<version>.json`, written in the version-bump pull
request and reviewed with it. It is the single source for:

- the desktop app's "Updated to x.y.z" banner (compiled into that version by
  `desktop/src-tauri/build.rs`, so it needs no network);
- the "What's new" text of the update notice for a version the operator does
  not have yet (`notes` in the download `manifest.json`);
- the public changelog at <https://network.scarlett.ai/changelog/>
  (`/downloads/changelog.json`, cumulative, newest first);
- the GitHub release body (`evidence/release-notes.md` from the release
  assembler).

```json
{
  "schemaVersion": 1,
  "version": "0.1.13",
  "date": "2026-10-09",
  "title": "Automatic updates",
  "highlights": ["...", "..."],
  "details": "https://network.scarlett.ai/docs/changelog#..."
}
```

Rules, enforced by `desktop/scripts/release-manifest.py check-version`, the
download publisher and the app:

- `title`: 1-80 characters. `highlights`: 1-3 entries of 1-160 characters.
  Plain text written for operators: no markup, no `<` or `>`, no control
  characters, no leading or trailing spaces.
- `date`: the planned release date, `YYYY-MM-DD`; correct it in the bump PR.
- `details` (optional): a developer page on `https://network.scarlett.ai/docs/`.
- The changelog and GitHub release links are derived from the version and are
  never written here: `https://network.scarlett.ai/changelog/#v<version>` and
  `https://github.com/teslashibe/scarlett-node/releases/tag/v<version>`.
- `check-version` refuses a release without the file for its version.
