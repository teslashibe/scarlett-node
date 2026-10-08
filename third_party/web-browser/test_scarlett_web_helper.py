"""Tests for scarlett_web_helper.py; run with the prepared runtime's Python:

    <runtime>/python/bin/python3.13 -B -m unittest discover -s third_party/web-browser -p 'test_*.py'

They build the real Scrapling session (never started) and drive the fetch
path with fake pages; no browser, no network.
"""

import asyncio
import json
import logging
import os
import re
import stat
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import scarlett_web_helper as helper  # noqa: E402
from scrapling.engines._browsers._base import StealthySessionMixin  # noqa: E402
from scrapling.engines.constants import STEALTH_ARGS  # noqa: E402

UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"
SOLVED = open(os.path.join(HERE, "testdata", "cf_solved_page.html"), encoding="utf-8").read()
MANAGED = "<html><head><title>Just a moment...</title></head><body><script>window._cf_chl_opt={cType: 'managed'}</script></body></html>"


def run(coro):
    return asyncio.run(coro)


class OptionSetTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.profile = os.path.join(tmp.name, helper.PROFILE_PREFIX + "x")
        helper.seed_profile(self.profile)
        self.session = helper.new_session(sys.executable, UA, "http://127.0.0.1:1111", "http://127.0.0.1:2222", 3, self.profile)
        self.args = self.session._browser_options["args"]

    def test_feature_switches_are_one_merged_pair(self):
        disable = [a for a in self.args if a.startswith("--disable-features=")]
        enable = [a for a in self.args if a.startswith("--enable-features=")]
        self.assertEqual(len(disable), 1)
        self.assertEqual(len(enable), 1)
        self.assertEqual(set(disable[0].split("=", 1)[1].split(",")), set(helper.DISABLED))
        self.assertTrue({"WebRtcHideLocalIpsWithMdns", "MediaRouter", "CastMediaRouteProvider"} <= set(helper.DISABLED))
        self.assertEqual(set(enable[0].split("=", 1)[1].split(",")), set(helper.ENABLED))

    def test_stealth_args_kept_and_ours_added(self):
        for arg in STEALTH_ARGS:
            if not arg.startswith(("--disable-features=", "--enable-features=")):
                self.assertIn(arg, self.args)
        for arg in ("--webrtc-ip-handling-policy=disable_non_proxied_udp", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                    "--deny-permission-prompts", "--disable-quic", "--disable-component-update",
                    "--use-fake-device-for-media-stream", "--disable-blink-features=AutomationControlled"):
            self.assertIn(arg, self.args)
        self.assertNotIn("--no-sandbox", self.args)
        # Fake devices, never a fake prompt that grants them.
        self.assertNotIn("--use-fake-ui-for-media-stream", self.args)
        self.assertNotIn("--force-webrtc-ip-handling-policy", self.args)
        for arg in helper.FILTERED_ARGS:
            self.assertNotIn(arg, self.args)

    def test_launch_options(self):
        options = self.session._browser_options
        # The helper passes the whole argv: Patchright's defaults first, the
        # seeded profile and the pipe last, and nothing of Patchright's own.
        self.assertIs(options["ignore_default_args"], True)
        head = helper.PW_SWITCHES + helper.PW_HEADLESS + ["--proxy-server=http://127.0.0.1:2222", "--proxy-bypass-list=<-loopback>"]
        self.assertEqual(self.args[:len(head)], head)
        self.assertEqual(self.args[-3:], ["--user-data-dir=" + self.profile, "--remote-debugging-pipe", "--no-startup-window"])
        self.assertEqual(len([a for a in self.args if "user-data-dir" in a]), 1)
        self.assertNotIn("--disable-features=" + ",".join(helper.PW_DISABLED), self.args)
        self.assertNotIn("--enable-features=CDPScreenshotNewSurface", self.args)
        self.assertEqual(options["proxy"], {"server": "http://127.0.0.1:2222"})
        self.assertIs(options["chromium_sandbox"], True)
        self.assertIs(options["headless"], True)
        self.assertEqual(options["executable_path"], sys.executable)
        self.assertFalse(self.session._config.extra_flags)
        self.assertEqual(helper.option_problems(self.session, 3), [])

    def test_patchright_defaults_match(self):
        """PW_SWITCHES and PW_HEADLESS are what the shipped Patchright driver
        builds for a headless launch, and the driver still ends a non-persistent
        argv with the profile, the pipe and --no-startup-window."""
        import patchright
        bundle = os.path.join(os.path.dirname(patchright.__file__), "driver", "package", "lib", "coreBundle.js")
        with open(bundle, encoding="utf-8") as f:
            text = f.read()
        start = text.index("chromiumSwitches = (options) => [")
        body = text[start:text.index("].filter(Boolean)", start)].splitlines()[1:]
        switches = []
        for line in body:
            line = line.split("//")[0].strip().rstrip(",")
            if not line or line == '"--disable-features=" + disabledFeatures.join(",")':
                continue
            m = re.fullmatch(r'"([^"]+)"', line) or re.fullmatch(r'[\w.?]+ \? "" : "([^"]+)"', line)
            self.assertIsNotNone(m, line)
            if m.group(1) != "--enable-features=CDPScreenshotNewSurface":
                switches.append(m.group(1))
        self.assertEqual(switches, helper.PW_SWITCHES)
        disabled = text[text.rindex("disabledFeatures = [", 0, start):start]
        self.assertEqual(re.findall(r'^\s*"(\w+)"', disabled, re.M), helper.PW_DISABLED)
        launcher = text.index("const chromeArguments = [...chromiumSwitches()];")
        headless = text[launcher:text.index("if (options.chromiumSandbox !== true)", launcher)]
        self.assertEqual(re.findall(r'"(--[^"]+)"', headless), helper.PW_HEADLESS)
        tail = re.sub(r"\s+", " ", text[text.rindex("async defaultArgs(options, isPersistent, userDataDir)", 0, launcher):launcher])
        self.assertIn('chromeArguments.push(`--user-data-dir=${userDataDir}`); chromeArguments.push("--remote-debugging-pipe"); '
                      'if (isPersistent) chromeArguments.push("about:blank"); else chromeArguments.push("--no-startup-window");', tail)
        proxy = re.sub(r"\s+", " ", text[launcher:launcher + 2500])
        self.assertIn("chromeArguments.push(`--proxy-server=${proxy.server}`);", proxy)
        self.assertIn('if (options.socksProxyPort || shouldProxyLoopback(proxy.bypass)) proxyBypassRules.push("<-loopback>");', proxy)
        self.assertIn("chromeArguments.push(...args); return chromeArguments;", proxy)

    def test_context_options(self):
        context = self.session._context_options
        self.assertIs(context["ignore_https_errors"], False)
        self.assertEqual(context["permissions"], [])
        self.assertIs(context["accept_downloads"], False)
        self.assertEqual(context["user_agent"], UA)
        self.assertEqual(self.session.max_pages, 3)
        self.assertEqual(self.session._config.max_pages, 3)
        self.assertIsNotNone(self.session._config.proxy_rotator)  # launch mode, fresh context per fetch

    def test_scrapling_logger_disabled(self):
        self.assertTrue(logging.getLogger("scrapling").disabled)

    def test_problems_are_reported(self):
        self.session._browser_options["args"].append("--no-sandbox")
        self.session._browser_options["ignore_default_args"] = ["--enable-automation"]
        problems = helper.option_problems(self.session, 2)
        self.assertIn("forbidden-arg", problems)
        self.assertIn("ignore_default_args", problems)
        self.assertIn("max_pages", problems)
        self.assertIn("profile", problems)  # the profile and the pipe are no longer last
        self.session._browser_options["args"] = self.session._browser_options["args"][1:]
        self.assertIn("driver-defaults", helper.option_problems(self.session, 3))

    def test_launch_reason(self):
        self.assertEqual(helper.launch_reason(Exception("chrome: error while loading shared libraries: libnss3.so")), "deps_missing")
        self.assertEqual(helper.launch_reason(Exception("Host system is missing dependencies to run browsers.")), "deps_missing")
        self.assertEqual(helper.launch_reason(Exception("[FATAL:zygote_host_impl_linux.cc(128)] No usable sandbox! If you are running on Ubuntu 23.10+")), "sandbox_unavailable")
        self.assertEqual(helper.launch_reason(Exception("Target closed; call log: chromium_sandbox=true --no-first-run")), "launch_failed")


class ProfileTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = tmp.name
        self.profile = os.path.join(tmp.name, "p")

    def test_seeded_preferences(self):
        helper.seed_profile(self.profile)
        with open(os.path.join(self.profile, "Default", "Preferences"), encoding="utf-8") as f:
            prefs = json.load(f)
        handlers = prefs["custom_handlers"]["registered_protocol_handlers"]
        self.assertIs(prefs["custom_handlers"]["enabled"], True)
        self.assertEqual(sorted(h["protocol"] for h in handlers), ["mailto", "news"])
        for h in handlers:
            # https on a reserved .invalid host: the egress proxy refuses it
            # before any lookup; usable in the off-the-record job contexts.
            self.assertEqual(h["url"], "https://scarlett-blocked.invalid/?u=%s")
            self.assertIs(h["default"], True)
            self.assertIs(h["is_allowed_in_incognito"], True)
            self.assertNotIn("security_level", h)  # the strict HTML level
        # Chrome's always-allowed external schemes never leave the browser.
        self.assertEqual(prefs["policy"], {"url_blocklist": ["mailto:*", "news:*", "snews:*"]})
        self.assertEqual(prefs["profile"]["default_content_setting_values"],
                         {"bluetooth_guard": 2, "hid_guard": 2, "serial_guard": 2, "usb_guard": 2})
        self.assertIs(prefs["hardware"]["screen_capture_enabled"], False)
        self.assertEqual(os.listdir(self.profile), ["Default"])
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.profile, "Default")).st_mode) & 0o077, 0)
        self.assertEqual(helper.profile_problems(self.profile), [])

    def test_seed_needs_a_new_directory_and_problems_are_reported(self):
        helper.seed_profile(self.profile)
        with self.assertRaises(FileExistsError):
            helper.seed_profile(self.profile)
        with open(os.path.join(self.profile, "Default", "Preferences"), "w", encoding="utf-8") as f:
            json.dump({"custom_handlers": {"enabled": False}}, f)
        self.assertEqual(helper.profile_problems(self.profile), ["profile-prefs"])
        self.assertEqual(helper.profile_problems(os.path.join(self.root, "missing")), ["profile-prefs"])

    def test_serve_removes_the_profile_when_the_browser_cannot_start(self):
        class NoBrowser:
            async def start(self):
                raise Exception("Target closed; call log: chromium_sandbox=true")
        saved = (helper.new_session, os.environ.copy(), os.dup(1), tempfile.tempdir)
        seen = []

        def fake_session(executable, ua, proxy, deny, capacity, profile):
            seen.append((profile, helper.profile_problems(profile)))
            return NoBrowser()
        try:
            helper.new_session = fake_session
            tempfile.tempdir = self.root
            os.environ.update({"WEB_HELPER_BEARER": "ab" * 32, "WEB_MAX_PAGES": "1", "WEB_BROWSER_EXECUTABLE": sys.executable,
                               "WEB_USER_AGENT": UA, "WEB_EGRESS_PROXY": "http://127.0.0.1:1", "WEB_DENY_PROXY": "http://127.0.0.1:2"})
            with self.assertRaises(helper.LaunchError):
                run(helper.serve())
        finally:
            helper.new_session, env, stdout, tempfile.tempdir = saved
            os.dup2(stdout, 1)
            os.close(stdout)
            os.environ.clear()
            os.environ.update(env)
        self.assertEqual(len(seen), 1)
        self.assertTrue(os.path.basename(seen[0][0]).startswith(helper.PROFILE_PREFIX))
        self.assertEqual(seen[0][1], [])
        self.assertEqual(os.listdir(self.root), [])


class RedirectGuardTests(unittest.TestCase):
    def event(self, status, location=None, url="https://example.com/a/b"):
        headers = [{"name": "Content-Type", "value": "text/html"}]
        if location is not None:
            headers.append({"name": "Location", "value": location})
        return {"requestId": "r1", "request": {"url": url}, "responseStatusCode": status, "responseHeaders": headers}

    def test_only_non_http_redirect_targets_are_refused(self):
        for location in ("mailto:a@example.com", "  MAILTO:a@example.com", "news:x", "facetime:+15555550100", "tel:1",
                         "itms-apps://apps.apple.com/app/id0", "intent://x#Intent;scheme=y;end", "javascript:alert(1)",
                         "data:text/html,x", "file:///etc/passwd", "chrome://settings", "zoommtg://x", "x-apple.systempreferences:",
                         # Chrome drops tabs and newlines anywhere and C0 controls at the ends.
                         "mail\tto:a@example.com", "mailto\n:a@example.com", "\x01mailto:a@example.com", "ma\rilto:x"):
            self.assertTrue(helper.refused_redirect(self.event(302, location)), location)
        for location in ("/next", "next", "//other.example/x", "https://other.example/", "HTTP://other.example/", "?q=1", ""):
            self.assertFalse(helper.refused_redirect(self.event(301, location)), location)
        self.assertFalse(helper.refused_redirect(self.event(200, "mailto:a@example.com")))
        self.assertFalse(helper.refused_redirect(self.event(302)))
        self.assertTrue(helper.refused_redirect(self.event(307, "mailto:x", url="http://example.com/")))

    def test_guard_fails_refused_redirects_and_continues_the_rest(self):
        async def go():
            page = FakePage("<html></html>")
            await helper.guard_redirects(page)
            cdp = page.context.cdp
            self.assertEqual(cdp.sent[0], ("Fetch.enable", {"patterns": [{"urlPattern": "*", "resourceType": "Document", "requestStage": "Response"}]}))
            for ev in (self.event(302, "mailto:x"), self.event(302, "/ok"), self.event(200)):
                cdp.emit("Fetch.requestPaused", ev)
            await asyncio.sleep(0.01)
            return cdp.sent[1:]
        self.assertEqual(run(go()), [("Fetch.failRequest", {"requestId": "r1", "errorReason": "BlockedByClient"}),
                                     ("Fetch.continueResponse", {"requestId": "r1"}), ("Fetch.continueResponse", {"requestId": "r1"})])


class CapTests(unittest.TestCase):
    def test_code_point_truncation(self):
        cap = helper.HTML_CAP
        text = "a" * (cap - 1) + "é" + "tail"  # é is two bytes; it straddles the cap
        out, truncated = helper.cap_html(text)
        self.assertTrue(truncated)
        self.assertEqual(len(out.encode("utf-8")), cap - 1)
        self.assertEqual(out, "a" * (cap - 1))
        out, truncated = helper.cap_html("short é")
        self.assertEqual((out, truncated), ("short é", False))
        out, _ = helper.cap_html("lone \ud800 surrogate")
        out.encode("utf-8")  # valid UTF-8 after replacement

    def test_header_pairs(self):
        headers, names = helper.header_pairs([("Content-Type", "text/html"), ("Set-Cookie", "__cf_bm=abc; Path=/"),
                                              ("set-cookie", "bad name=x"), ("Cookie", "a=b"), ("X-Bin", "a\x01b"),
                                              ("Bad Name", "x"), ("X-Long", "v" * 4097)])
        self.assertEqual(headers, [["content-type", "text/html"]])
        self.assertEqual(names, ["__cf_bm"])
        many, _ = helper.header_pairs([("x-%d" % i, "v") for i in range(200)])
        self.assertEqual(len(many), helper.MAX_HEADERS)


class FakeLocator:
    def __init__(self, page, selector):
        self.page, self.selector = page, selector
        self.first = self

    async def wait_for(self, state, timeout):
        self.page.selector_waits.append((self.selector, state, timeout))
        await asyncio.sleep(min(timeout / 1000, 0.05))
        if self.selector not in self.page.html:
            raise TimeoutError("selector")

    async def is_visible(self, timeout=None):
        return False

    async def text_content(self, timeout=None):
        return self.page.dd_title


class FakeRequest:
    def __init__(self, frame):
        self.resource_type = "document"
        self.frame = frame


class FakeResponse:
    def __init__(self, page, status, url, headers):
        self.status, self.url, self._headers = status, url, headers
        self.request = FakeRequest(page.main_frame)
        self.frame = page.main_frame
        self.headers = {k.lower(): v for k, v in headers}

    async def headers_array(self):
        return [{"name": k, "value": v} for k, v in self._headers]


class FakeCDP:
    def __init__(self):
        self.sent, self.handlers = [], {}

    def on(self, event, handler):
        self.handlers[event] = handler

    def emit(self, event, params):
        self.handlers[event](params)

    async def send(self, method, params=None):
        self.sent.append((method, params))
        return {}


class FakeContext:
    def __init__(self, page):
        self.page = page
        self.cdp = None

    async def cookies(self):
        return list(self.page.cookie_jar)

    async def new_cdp_session(self, page):
        self.cdp = FakeCDP()
        return self.cdp


class FakeFrame:
    def __init__(self, url, page=None):
        self.url, self.page = url, page

    def locator(self, selector):
        return FakeLocator(self.page, selector)


class FakePage:
    def __init__(self, html, status=200, headers=(("content-type", "text/html; charset=utf-8"),)):
        self.main_frame = FakeFrame("https://example.com/")
        self.frames = [self.main_frame]
        self.url = "https://example.com/"
        self.html = html
        self.status, self.headers = status, list(headers)
        self.handlers = []
        self.context = FakeContext(self)
        self.cookie_jar = []
        self.selector_waits = []
        self.default_timeouts = []
        self.dd_title = ""
        self.timeline = []  # (delay, callable) applied while the page is waited on

    def on(self, event, handler):
        self.handlers.append(handler)

    def emit_document(self, status=None, url=None, headers=None):
        response = FakeResponse(self, status or self.status, url or self.url, headers or self.headers)
        for handler in self.handlers:
            handler(response)
        return response

    async def content(self):
        return self.html

    async def wait_for_load_state(self, state, timeout=None):
        await asyncio.sleep(0)

    def set_default_timeout(self, ms):
        self.default_timeouts.append(ms)

    def locator(self, selector):
        return FakeLocator(self, selector)


class FakeScraplingResponse:
    def __init__(self, page):
        self.url = page.url
        self.body = page.html.encode("utf-8")
        self.status = page.status
        self.headers = dict(page.headers)
        self.cookies = tuple(page.cookie_jar)


class FakeSession:
    """Calls page_setup, emits the main document, calls page_action and
    builds the response, in Scrapling's order. Detection is Scrapling's."""

    _detect_cloudflare = staticmethod(StealthySessionMixin._detect_cloudflare)

    def __init__(self, pages, solver=None):
        self.pages = list(pages)
        self.solver_calls = 0
        self.solver = solver
        self.fetch_calls = []

    async def _cloudflare_solver(self, page):
        self.solver_calls += 1
        if self.solver:
            await self.solver(page)

    async def fetch(self, url, **kwargs):
        self.fetch_calls.append(kwargs)
        page = self.pages.pop(0)
        await kwargs["page_setup"](page)
        page.emit_document()
        await kwargs["page_action"](page)
        return FakeScraplingResponse(page)


def request(**overrides):
    raw = {"url": "https://example.com/", "wait": "load", "wait_ms": 0, "timeout_ms": 30000, "block_resources": False, "solve_challenge": True}
    raw.update(overrides)
    return helper.Request(raw)


class FetchTests(unittest.TestCase):
    def fetch(self, session, req=None):
        async def go():
            return await helper.Fetcher(session, "http://127.0.0.1:1111", 2).fetch(req or request())
        return run(go())["data"]

    def test_fetch_options_and_last_document_capture(self):
        page = FakePage("<html><body><p>hello</p></body></html>", headers=[("content-type", "text/html"), ("x-last", "1"),
                                                                           ("set-cookie", "sid=1"), ("set-cookie", "__cf_bm=2")])
        page.cookie_jar = [{"name": "__cf_bm", "value": "v", "domain": ".example.com", "path": "/", "expires": -1, "secure": True, "httpOnly": True}]
        session = FakeSession([page])
        data = self.fetch(session)
        self.assertEqual(data["outcome"], "ok")
        self.assertEqual(data["status_code"], 200)
        self.assertEqual(data["challenge"], "none")
        self.assertIn(["x-last", "1"], data["headers"])
        self.assertEqual(data["set_cookie_names"], ["sid", "__cf_bm"])
        self.assertEqual(data["cookies"][0]["http_only"], True)
        self.assertEqual(data["html"], page.html)
        kwargs = session.fetch_calls[0]
        self.assertEqual(kwargs["proxy"], "http://127.0.0.1:1111")
        self.assertIs(kwargs["network_idle"], False)
        self.assertIs(kwargs["solve_cloudflare"], False)
        self.assertIs(kwargs["google_search"], False)
        self.assertNotIn("extra_flags", kwargs)
        # The redirect guard is on before the page navigates.
        self.assertEqual(page.context.cdp.sent[0][0], "Fetch.enable")

    def test_solver_never_runs_on_a_solved_page(self):
        page = FakePage(SOLVED)
        self.assertEqual(StealthySessionMixin._detect_cloudflare(SOLVED), "embedded")  # the script stays
        session = FakeSession([page])
        data = self.fetch(session)
        self.assertEqual(session.solver_calls, 0)
        self.assertEqual(data["challenge"], "none")

    def test_solver_runs_on_a_managed_interstitial(self):
        page = FakePage(MANAGED, status=403, headers=[("content-type", "text/html"), ("cf-mitigated", "challenge")])

        async def solve(p):
            p.html, p.status = "<html><body>welcome</body></html>", 200
            p.emit_document(status=200)
        session = FakeSession([page], solver=solve)
        data = self.fetch(session)
        self.assertEqual(session.solver_calls, 1)
        self.assertEqual(data["challenge"], "solved")
        self.assertEqual(data["status_code"], 200)
        self.assertIn(5000, page.default_timeouts)  # the solver's own waits are bounded

    def test_a_hung_solver_is_bounded_and_unsolved(self):
        async def hang(p):
            await asyncio.sleep(3600)
        session = FakeSession([FakePage(MANAGED)], solver=hang)
        started = time.monotonic()
        data = self.fetch(session, request(timeout_ms=3000))
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(data["challenge"], "unsolved")
        self.assertEqual(session.solver_calls, 1)  # under 15 s left: no fresh-context retry

    def test_unsolved_with_time_left_retries_once_in_a_fresh_context(self):
        session = FakeSession([FakePage(MANAGED), FakePage("<html><body>ok</body></html>")])
        data = self.fetch(session, request(solve_challenge=False))
        self.assertEqual(len(session.fetch_calls), 2)
        self.assertEqual(data["challenge"], "none")

    def test_selector_and_settle_time_stay_in_budget(self):
        page = FakePage("<html><body><div id=late></div></body></html>")
        data = self.fetch(FakeSession([page]), request(wait_selector="#never", wait_ms=10, timeout_ms=5000))
        self.assertEqual(data["outcome"], "ok")
        selector, state, timeout = page.selector_waits[0]
        self.assertEqual((selector, state), ("#never", "attached"))
        self.assertLessEqual(timeout, 4000)

    def test_tls_and_timeout_errors(self):
        class Failing(FakeSession):
            async def fetch(self, url, **kwargs):
                raise Exception("Page.goto: net::ERR_CERT_AUTHORITY_INVALID at https://self-signed.example/")
        data = self.fetch(Failing([]))
        self.assertEqual((data["outcome"], data["error"], data["html"]), ("failed", "tls", ""))

        class Slow(FakeSession):
            async def fetch(self, url, **kwargs):
                await asyncio.sleep(3600)
        started = time.monotonic()
        data = self.fetch(Slow([]), request(timeout_ms=1000))
        self.assertEqual((data["outcome"], data["error"]), ("timeout", "timeout"))
        self.assertLess(time.monotonic() - started, 3)

    def test_non_html_documents_return_no_html(self):
        page = FakePage('{"a":1}', headers=[("content-type", "application/json")])
        data = self.fetch(FakeSession([page]))
        self.assertEqual((data["html"], data["content_type"]), ("", "application/json"))


class DataDomeTests(unittest.TestCase):
    """The device-check wait ported from wafer: a cookie change counts only
    once the challenge iframe has gone; t=bv and interactive frames stop."""

    def interstitial(self):
        page = FakePage("<html><script>var dd={'rt':'i','cid':'x','hsh':'y','s':1}</script>"
                        "<script src='https://ct.captcha-delivery.com/i.js'></script></html>", status=403)
        page.cookie_jar = [{"name": "datadome", "value": "first"}]
        return page

    def test_pending_device_check_is_never_success(self):
        page = self.interstitial()
        page.frames.append(FakeFrame("https://geo.captcha-delivery.com/interstitial/?x", page))

        async def go():
            loop = asyncio.get_running_loop()
            return await helper.wait_for_datadome(page, helper.Document(page), loop.time() + 2)
        self.assertEqual(run(go()), "unsolved")

    def test_cookie_change_alone_is_a_rejection_while_the_frame_stays(self):
        page = self.interstitial()
        page.frames.append(FakeFrame("https://geo.captcha-delivery.com/interstitial/?x", page))
        page.cookie_jar = [{"name": "datadome", "value": "first"}]

        async def go():
            loop = asyncio.get_running_loop()

            async def rotate():
                await asyncio.sleep(0.3)
                page.cookie_jar = [{"name": "datadome", "value": "second"}]
            asyncio.ensure_future(rotate())
            return await helper.wait_for_datadome(page, helper.Document(page), loop.time() + 2.5)
        self.assertEqual(run(go()), "unsolved")

    def test_cookie_change_and_frame_gone_is_solved(self):
        page = self.interstitial()
        frame = FakeFrame("https://geo.captcha-delivery.com/interstitial/?x", page)
        page.frames.append(frame)

        async def go():
            loop = asyncio.get_running_loop()

            async def pass_check():
                await asyncio.sleep(0.6)
                page.cookie_jar = [{"name": "datadome", "value": "cleared"}]
                page.frames.remove(frame)
                page.html, page.status = "<html><body>article</body></html>", 200
                page.emit_document(status=200)
            asyncio.ensure_future(pass_check())
            return await helper.wait_for_datadome(page, helper.Document(page), loop.time() + 5)
        self.assertEqual(run(go()), "solved")

    def test_blocked_visitor_stops_at_once(self):
        page = FakePage("<html><script>var dd={'rt':'c','cid':'x','t':'bv','s':1}</script></html>", status=403)

        async def go():
            loop = asyncio.get_running_loop()
            start = loop.time()
            verdict = await helper.wait_for_datadome(page, helper.Document(page), loop.time() + 10)
            return verdict, loop.time() - start
        verdict, took = run(go())
        self.assertEqual(verdict, "stop")
        self.assertLess(took, 0.5)

    def test_only_a_captcha_delivery_frame_is_datadome(self):
        for url in ("https://geo.captcha-delivery.com/interstitial/?x", "https://captcha-delivery.com/c", "https://GEO.Captcha-Delivery.com/captcha/"):
            self.assertTrue(helper.dd_frame_url(url), url)
        for url in ("https://buyer.example/x?captcha-delivery.com", "https://buyer.example/captcha-delivery.com/", "https://captcha-delivery.com.buyer.example/",
                    "https://evilcaptcha-delivery.com/", "http://geo.captcha-delivery.com/", "https://user@buyer.example/#captcha-delivery.com",
                    "about:blank", "", "https://[::1/"):
            self.assertFalse(helper.dd_frame_url(url), url)

    def test_a_buyer_frame_naming_datadome_is_never_clicked(self):
        # The page carries DataDome's markers and a frame whose URL names the
        # host, with the confirm button shown: the helper waits, never clicks.
        page = FakePage("<html><script>var dd={'rt':'i'}</script><p>captcha-delivery.com</p></html>", status=200)
        page.frames.append(FakeFrame("https://buyer.example/x?captcha-delivery.com", page))
        clicks = []
        helper_click = helper.dd_click_confirm

        async def recording(p, frame):
            clicks.append(frame.url)
            return await helper_click(p, frame)
        helper.dd_click_confirm = recording
        try:
            async def go():
                loop = asyncio.get_running_loop()
                return await helper.wait_for_datadome(page, helper.Document(page), loop.time() + 1.5)
            run(go())
        finally:
            helper.dd_click_confirm = helper_click
        self.assertEqual(clicks, [])
        self.assertIsNone(helper.dd_frame(page))

    def test_interactive_frame_stops_without_retry(self):
        page = self.interstitial()
        page.frames.append(FakeFrame("https://geo.captcha-delivery.com/captcha/?x", page))
        page.dd_title = "Access is temporarily restricted"
        session = FakeSession([page, FakePage("<html>never fetched</html>")])

        async def go():
            return await helper.Fetcher(session, "http://127.0.0.1:1111", 1).fetch(request(timeout_ms=40000))
        data = run(go())["data"]
        self.assertEqual(data["challenge"], "unsolved")
        self.assertEqual(len(session.fetch_calls), 1)  # a stopped DataDome check is not retried


class ServerTests(unittest.TestCase):
    def setUp(self):
        class Fetcher:
            async def fetch(self, req):
                return {"data": {"outcome": "ok", "url": req.url}, "no_retry": False}
        self.server = helper.Server("ab" * 32, Fetcher(), "155.0.8059.39", 2)

    def call(self, raw):
        async def go():
            reader = asyncio.StreamReader(limit=helper.MAX_REQUEST_HEAD)
            reader.feed_data(raw)
            reader.feed_eof()
            return await self.server.route(reader)
        return run(go())

    def head(self, method, path, body=b"", bearer="ab" * 32, extra=""):
        auth = "Authorization: Bearer %s\r\n" % bearer if bearer else ""
        return ("%s %s HTTP/1.1\r\nHost: x\r\n%s%sContent-Length: %d\r\n\r\n" % (method, path, auth, extra, len(body))).encode() + body

    def test_bearer_required(self):
        self.assertEqual(self.call(self.head("GET", "/v1/ready", bearer=None))[0], 401)
        self.assertEqual(self.call(self.head("GET", "/v1/ready", bearer="cd" * 32))[0], 401)
        self.assertEqual(self.call(self.head("GET", "/v1/ready")), (200, {"data": {"status": "ready"}}))

    def test_capabilities(self):
        status, body = self.call(self.head("GET", "/v1/capabilities"))
        self.assertEqual(body, {"data": {"web_browser": 1, "engine": "scrapling/0.4.15", "browser_version": "155.0.8059.39", "max_pages": 2}})

    def test_body_caps_and_validation(self):
        big = b"{" + b" " * helper.MAX_REQUEST_BODY + b"}"
        self.assertEqual(self.call(self.head("POST", "/v1/fetch", big, extra="Content-Type: application/json\r\n"))[0], 413)
        self.assertEqual(self.call(self.head("POST", "/v1/fetch", b"{}", extra="Content-Type: text/plain\r\n"))[0], 400)
        body = json.dumps({"url": "https://example.com/", "unknown": 1}).encode()
        self.assertEqual(self.call(self.head("POST", "/v1/fetch", body, extra="Content-Type: application/json\r\n"))[0], 400)
        body = json.dumps({"url": "file:///etc/passwd"}).encode()
        self.assertEqual(self.call(self.head("POST", "/v1/fetch", body, extra="Content-Type: application/json\r\n"))[0], 400)
        body = json.dumps({"url": "https://example.com/", "wait": "load", "timeout_ms": 5000}).encode()
        status, out = self.call(self.head("POST", "/v1/fetch", body, extra="Content-Type: application/json\r\n"))
        self.assertEqual((status, out["data"]["outcome"]), (200, "ok"))
        self.assertEqual(self.call(self.head("GET", "/v1/fetch"))[0], 405)
        self.assertEqual(self.call(b"GET /v1/ready HTTP/1.1\r\n" + b"X: " + b"y" * helper.MAX_REQUEST_HEAD + b"\r\n\r\n")[0], 400)

    def test_encoded_response_is_valid_utf8(self):
        raw = helper.encode(200, {"data": {"html": "lone \ud800 surrogate é"}})
        raw.decode("utf-8")
        self.assertIn(b"Content-Length:", raw)


if __name__ == "__main__":
    unittest.main()
