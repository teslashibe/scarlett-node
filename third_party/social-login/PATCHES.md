# Local interactive X patch

Source is pinned to social-login v0.2.20 at `11e2ffafe3e7f32f531af7b08b677430af0bf7d4`. `UPSTREAM.json` contains the original file hashes; `PATCHED.json` lists every distributed tracked byte. `patches/interactive-x.patch` reconstructs modified and added files from the upstream snapshot. Source carries upstream comments, and NOTICE.md explains the absence of an upstream LICENSE file.

The patch lets X park its live browser at a verification-code prompt, then submit only that code on the same page. It checks for a warmed profile session before credentials, filters cookies to X, refuses stale-cookie success on login/challenge pages, preserves the captured browser identity, and never generates TOTP in the X recipe. Go must validate the returned candidate session against the requested identity.

The existing owner-bound challenge and browser-hold registries retain ownership, expiry and cancellation. The patch carries aggregate attempts and absolute deadline across continuation, counts parked browsers in existing admission capacity, excludes concurrent fresh login/harvest/prewarm on a challenged profile, and closes on code-attempt exhaustion or browser crash. `interactive_x: 1` advertises this contract; consumers must reject an unpatched X recipe.

Native helper support uses explicit `CAP_BROWSER_EXECUTABLE_PATH`, loopback `HOST`, and `SOCIAL_LOGIN_MANAGED=1` stdin EOF shutdown. Native readiness requires Xvfb only on Linux. No login-time browser download is introduced.

Run `node scripts/verify-social-login.mjs`, `npm ci --ignore-scripts --prefix third_party/social-login`, and `npm test --prefix third_party/social-login`. Every X route in `interactive-x.test.js` is intercepted, so the fixtures never contact the provider. Native generated resources additionally require `scripts/verify-x-login-runtime.mjs`. Linux Chromium fixture acceptance runs in `x-browser-runtime.yml`; installed macOS/Windows acceptance and one bounded opt-in live burner test remain release gates.

When upstream implements the same guarantees, pin that release, remove equivalent patch hunks, regenerate source hashes and run all fixtures. This repository does not modify or publish the upstream repository.
