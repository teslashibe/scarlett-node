# Web browser runtime notices

The node's web browser tier runs `scarlett_web_helper.py` inside a bundled Python. `scripts/prepare-web-runtime.mjs` builds that runtime from the pinned inputs below and copies this file and `wafer-LICENSE.txt` into the archive under `notices/`. Every installed wheel keeps its own `*.dist-info` licence files in the archive.

## Bundled in the runtime archive

| Component | Version | Licence |
|---|---|---|
| CPython, from python-build-standalone release `20261003` (`install_only_stripped`) | 3.13.16 | PSF License (`python/lib/python3.13/LICENSE.txt`; Windows `python/LICENSE.txt`); the python-build-standalone build scripts are MPL-2.0 |
| scrapling | 0.4.15+scarlett.2 | BSD-3-Clause; its `NOTICE` (in `scrapling-0.4.15+scarlett.2.dist-info/licenses/`) lists the Apache-2.0 and MIT code it adapts |
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

## The Scrapling build

The runtime installs Scrapling from Scarlett's fork, [teslashibe/Scrapling](https://github.com/teslashibe/Scrapling), release `v0.4.15-scarlett.2`: upstream 0.4.15 plus the anti-bot handlers (`scrapling/engines/antibot/`) and the captcha-solver router, built from branch `scarlett/antibot` at commit `87bbb2aa9a3b5fc1b15ce935d17cdcad9fd136d7`. `requirements.lock` pins the release's wheel by its sha256, so the build installs those exact bytes. The fork stays under Scrapling's BSD-3-Clause licence. Its `NOTICE`, shipped in the wheel's `dist-info/licenses/`, credits the code the handlers adapt: Averyy/wafer (Apache-2.0; the full licence text is `wafer-LICENSE.txt` here), Crawl4AI (Apache-2.0), Hyper Solutions hyper-sdk-py (MIT), SeleniumBase (MIT) and xKiian/awswaf (MIT).

## Code adapted from other projects

`scarlett_web_helper.py` no longer carries code from other projects. Its earlier DataDome device-check wait, adapted from [Averyy/wafer](https://github.com/Averyy/wafer) `wafer/browser/_datadome.py` (Apache-2.0, Copyright 2026 Avery), now lives in the fork's `scrapling/engines/antibot/datadome.py` with the attribution above.
