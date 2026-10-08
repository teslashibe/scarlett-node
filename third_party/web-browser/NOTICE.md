# Web browser runtime notices

The node's web browser tier runs `scarlett_web_helper.py` inside a bundled Python. `scripts/prepare-web-runtime.mjs` builds that runtime from the pinned inputs below and copies this file and `wafer-LICENSE.txt` into the archive under `notices/`. Every installed wheel keeps its own `*.dist-info` licence files in the archive.

## Bundled in the runtime archive

| Component | Version | Licence |
|---|---|---|
| CPython, from python-build-standalone release `20261003` (`install_only_stripped`) | 3.13.16 | PSF License (`python/lib/python3.13/LICENSE.txt`; Windows `python/LICENSE.txt`); the python-build-standalone build scripts are MPL-2.0 |
| scrapling | 0.4.15 | BSD-3-Clause |
| patchright | 1.63.0 | Apache-2.0 |
| playwright | 1.63.0 | Apache-2.0 |
| curl-cffi | 0.16.3 | MIT |
| lxml | 6.1.3 | BSD-3-Clause |
| orjson | 3.13.0 | MPL-2.0 AND (Apache-2.0 OR MIT) |
| msgspec | 0.22.0 | BSD-3-Clause |
| greenlet | 3.5.6 | MIT AND PSF-2.0 |
| cffi | 2.1.1 | MIT-0 |
| pycparser | 3.0 | BSD-3-Clause |
| browserforge | 1.2.4 | Apache-2.0 |
| apify-fingerprint-datapoints | 0.15.0 | Apache-2.0 |
| anyio | 4.15.1 | MIT |
| click | 8.5.0 | BSD-3-Clause |
| cssselect | 1.5.0 | BSD-3-Clause |
| tld | 0.13.2 | MPL-1.1 OR GPL-2.0-only OR LGPL-2.1-or-later |
| w3lib | 2.5.0 | BSD-3-Clause |
| protego | 0.7.0 | BSD-3-Clause |
| pyee | 13.0.1 | MIT |
| certifi | 2026.7.22 | MPL-2.0 |
| idna | 3.20 | BSD-3-Clause |
| typing-extensions | 4.16.0 | PSF-2.0 |

The Playwright and Patchright driver packages are kept; their bundled Node executables are removed and the x-login runtime's Node 22.23.3 runs the driver instead.

## Downloaded by the node, not shipped

Chrome for Testing 155.0.8059.39 is downloaded by the node from `storage.googleapis.com/chrome-for-testing-public`, checked against the zip sha256 and per-file inventory in `chrome-for-testing.json` and `chrome-inventory/`, and extracted into node state. Chromium's licence and third-party notices are inside that download (`chrome://credits`, and `ABOUT` at the zip root).

## Code adapted from other projects

`scarlett_web_helper.py` `wait_for_datadome`, `dd_frame`, `dd_frame_blocked` and `dd_click_confirm` are adapted from [Averyy/wafer](https://github.com/Averyy/wafer) `wafer/browser/_datadome.py` (`wait_for_datadome`, `_find_dd_frame`, `_is_hard_block`, `_try_click_confirm`), read on 2026-10-07 at revision `f353ddafa01893aae9cbbd2dd2111e1a7f7a6c3d`. Copyright 2026 Avery. Licensed under the Apache License, Version 2.0; the full text is in `wafer-LICENSE.txt`.

Changes from the original: ported from wafer's synchronous solver to Patchright's async API inside a Scrapling `page_action`; the wait is bounded by the job's remaining budget (at most 15 s); the mouse-replay recordings are replaced by a short direct move before the confirm click; a cookie change counts as a clearance only when the challenge iframe has left and the page no longer carries DataDome challenge markers; `t=bv`, a restricted or blocked device and an interactive (`/captcha/`) frame end the wait and stop the helper's fresh-context retry; logging is removed.
