"""Tests for scarlett_web_helper.py; run with the prepared runtime's Python:

    <runtime>/python/bin/python3.13 -B -m unittest discover -s third_party/web-browser -p 'test_*.py'

They build the real Scrapling session (never started) and drive the fetch
path with fake pages and fake anti-bot outcomes; no browser, no network. The
anti-bot handlers themselves are tested in the Scrapling fork.
"""

import asyncio
import contextlib
import json
import logging
import os
import re
import stat
import sys
import tempfile
import time
import unittest
from importlib import import_module
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import scarlett_web_helper as helper  # noqa: E402
from scrapling.engines._browsers import _stealth  # noqa: E402
from scrapling.engines._browsers._page import PageInfo  # noqa: E402
from scrapling.engines.antibot import runner as antibot_runner  # noqa: E402
from scrapling.engines.antibot.base import Detection  # noqa: E402
from scrapling.engines.constants import STEALTH_ARGS  # noqa: E402

antibot_detect = import_module("scrapling.engines.antibot.detect")  # the module; the package re-exports the function

UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"
PAGE = "<html><body><p>hello</p></body></html>"
KEY = "0123456789abcdef0123456789abcdef"

# response.meta["antibot"] as the fork reports it.
CLEAN = {"vendor": None, "kind": None, "rule": None, "solved": False, "reason": "none", "layers": [], "elapsed_s": 0.4}


def layer(vendor, kind, rule, solved, reason, used_solver=None, elapsed=1.0, solver_kind=None):
    return {"vendor": vendor, "kind": kind, "rule": rule, "solved": solved, "reason": reason, "cookies": [],
            "used_solver": used_solver, "solver_kind": solver_kind, "elapsed_s": elapsed}


def outcome(*layers, solver=None, elapsed=2.5):
    last = layers[-1]
    out = {"vendor": last["vendor"], "kind": last["kind"], "rule": last["rule"], "solved": all(x["solved"] for x in layers),
           "reason": last["reason"], "layers": list(layers), "elapsed_s": elapsed}
    if solver:
        out["solver"] = solver
    return out


SOLVED_DD = outcome(layer("datadome", "device_check", "dd.frame_device", True, "solved"))
SLIDER = outcome(layer("datadome", "captcha", "dd.frame_captcha", False, "slider", solver_kind="datadome_slider"))
PX_HOLD = outcome(layer("perimeterx", "captcha", "px.hold", False, "unsolved:attempts_exhausted"))
BANNED = outcome(layer("datadome", "ban", "dd.frame_device", False, "ban"))
TIMED_OUT = outcome(layer("akamai", "challenge", "akamai.sec_cpt_html", False, "timeout"))
PAID = outcome(layer("cloudflare", "captcha", "cf.turnstile", True, "solved", used_solver="capmonster"),
               solver={"solves": 1, "attempts": 1, "cost_usd": 0.0012, "records": []})


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

    def test_antibot_launch_hardening(self):
        # solve_antibot is on the session, so the fork rewrites the argv at
        # start(): headless tells out, one common display and the UA in, and
        # everything the helper built otherwise unchanged.
        from scrapling.engines.antibot.headless import canonical_displays, display_policy

        self.assertEqual(display_policy(), "canonical")
        self.assertIn(canonical_displays()[0].screen_info_switch(), self.session._launch_options()["args"])
        self.assertIs(self.session._config.solve_antibot, True)
        self.assertIsNone(self.session._config.captcha_solver)
        launch = self.session._launch_options()
        args = launch["args"]
        for gone in ("--hide-scrollbars", "--force-color-profile=srgb"):
            self.assertIn(gone, self.args)
            self.assertNotIn(gone, args)
        self.assertFalse([a for a in args if a.startswith("--blink-settings=")])
        for prefix in ("--screen-info=", "--force-device-scale-factor=", "--window-size="):
            self.assertEqual(len([a for a in args if a.startswith(prefix)]), 1, prefix)
        self.assertIn("--user-agent=" + UA, args)
        kept = [a for a in self.args if not helper.antibot_dropped(a)]
        self.assertEqual(args[:len(kept)], kept)
        for arg in ("--proxy-server=http://127.0.0.1:2222", "--user-data-dir=" + self.profile, "--remote-debugging-pipe",
                    "--webrtc-ip-handling-policy=disable_non_proxied_udp", "--disable-quic"):
            self.assertIn(arg, args)
        self.assertEqual({k: v for k, v in launch.items() if k != "args"},
                         {k: v for k, v in self.session._browser_options.items() if k != "args"})
        self.assertIs(self.session._context_options.get("no_viewport"), True)
        self.assertEqual(helper.launch_problems(self.session), [])

    def test_launch_problems_are_reported(self):
        original = self.session._launch_options

        def tampered(extra=(), drop=()):
            def launch():
                options = original()
                options["args"] = [a for a in options["args"] if a not in drop] + list(extra)
                return options
            return launch
        for extra, drop, problem in ((["--no-sandbox"], (), "launch-added"), (["--remote-debugging-port=9222"], (), "launch-forbidden-arg"),
                                     ([], ("--disable-quic",), "launch-kept"), (["--user-agent=HeadlessChrome"], (), "launch-user-agent")):
            self.session._launch_options = tampered(extra, drop)
            self.assertIn(problem, helper.launch_problems(self.session), (extra, drop))
        self.session._launch_options = original
        self.session._config.solve_antibot = False
        self.assertEqual(helper.launch_problems(self.session), ["antibot-launch"])

    def test_datadome_slide_to_target_is_not_dragged(self):
        from scrapling.engines.antibot import registry

        self.assertIs(registry.get("datadome").drag_simple_slider, False)
        registry.get("datadome").drag_simple_slider = True
        try:
            self.assertIn("datadome-slider", helper.option_problems(self.session, 3))
        finally:
            registry.get("datadome").drag_simple_slider = False

    def test_the_operators_own_displays_are_a_problem(self):
        from scrapling.engines.antibot import headless

        self.assertNotIn("display", helper.option_problems(self.session, 3))
        headless.set_display_policy("host")
        try:
            self.assertIn("display", helper.option_problems(self.session, 3))
        finally:
            headless.set_display_policy("canonical")

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
                               "WEB_USER_AGENT": UA, "WEB_EGRESS_PROXY": "http://127.0.0.1:1", "WEB_DENY_PROXY": "http://127.0.0.1:2",
                               "WEB_SOLVER_CONFIG": json.dumps({"capmonster": KEY})})
            with self.assertRaises(helper.LaunchError):
                run(helper.serve())
            # The bearer and the solver keys never reach the driver or the browser.
            popped = ("WEB_HELPER_BEARER" not in os.environ, "WEB_SOLVER_CONFIG" not in os.environ)
        finally:
            helper.new_session, env, stdout, tempfile.tempdir = saved
            os.dup2(stdout, 1)
            os.close(stdout)
            os.environ.clear()
            os.environ.update(env)
        self.assertEqual(popped, (True, True))
        self.assertEqual(len(seen), 1)
        self.assertTrue(os.path.basename(seen[0][0]).startswith(helper.PROFILE_PREFIX))
        self.assertEqual(seen[0][1], [])
        self.assertEqual(os.listdir(self.root), [])

    def test_serve_refuses_a_bad_solver_config(self):
        saved = (os.environ.copy(), os.dup(1))
        try:
            for raw in ("{", json.dumps({"capmonster": 1}), json.dumps({"anticaptcha": KEY}), json.dumps({"max_solves_per_fetch": 2}),
                        json.dumps({"capmonster": KEY, "max_solves_per_fetch": 9}), json.dumps({"capmonster": "short"})):
                os.environ.update({"WEB_HELPER_BEARER": "ab" * 32, "WEB_MAX_PAGES": "1", "WEB_SOLVER_CONFIG": raw})
                with self.assertRaises(SystemExit) as caught:
                    run(helper.serve())
                self.assertEqual(caught.exception.code, 2)
                self.assertNotIn("WEB_SOLVER_CONFIG", os.environ)
        finally:
            env, stdout = saved
            os.dup2(stdout, 1)
            os.close(stdout)
            os.environ.clear()
            os.environ.update(env)


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

    def is_navigation_request(self):
        return True


class FakeResponse:
    def __init__(self, page, status, url, headers):
        self.status, self.url, self._headers = status, url, headers
        self.request = FakeRequest(page.main_frame)
        self.frame = page.main_frame
        self.headers = {k.lower(): v for k, v in headers}

    async def headers_array(self):
        return [{"name": k, "value": v} for k, v in self._headers]


class FakeCDP:
    def __init__(self, failing=()):
        self.sent, self.handlers = [], {}
        self.failing = set(failing)

    def on(self, event, handler):
        self.handlers[event] = handler

    def emit(self, event, params):
        self.handlers[event](params)

    async def send(self, method, params=None):
        if method in self.failing:
            raise Exception("Protocol error (%s): Target closed" % method)
        self.sent.append((method, params))
        return {}


class FakeContext:
    def __init__(self, page):
        self.page = page
        self.cdp = None
        self.cdp_error = None  # raised by new_cdp_session
        self.cdp_failing = ()  # CDP methods whose send raises

    async def cookies(self):
        return list(self.page.cookie_jar)

    async def new_cdp_session(self, page):
        if self.cdp_error:
            raise self.cdp_error
        self.cdp = FakeCDP(self.cdp_failing)
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
        self.closed = False
        self.close_error = None  # raised by close
        self.navigations = 0

    def on(self, event, handler):
        self.handlers.append(handler)

    def remove_listener(self, event, handler):
        self.handlers.remove(handler)

    def emit_document(self, status=None, url=None, headers=None):
        response = FakeResponse(self, status or self.status, url or self.url, headers or self.headers)
        for handler in list(self.handlers):
            result = handler(response)
            if asyncio.iscoroutine(result):  # as Playwright runs async listeners
                asyncio.ensure_future(result)
        return response

    async def goto(self, url, referer=None):
        if self.closed:
            raise Exception("Page.goto: Target page, context or browser has been closed")
        self.navigations += 1
        return self.emit_document()

    async def close(self):
        if self.close_error:
            raise self.close_error
        self.closed = True

    def is_closed(self):
        return self.closed

    async def wait_for_timeout(self, ms):
        await asyncio.sleep(ms / 1000)

    async def content(self):
        return self.html

    async def wait_for_load_state(self, state, timeout=None):
        await asyncio.sleep(0)

    def set_default_timeout(self, ms):
        self.default_timeouts.append(ms)

    def set_default_navigation_timeout(self, ms):
        self.default_timeouts.append(ms)

    def locator(self, selector):
        return FakeLocator(self, selector)


class FakeScraplingResponse:
    def __init__(self, page, meta=None):
        self.url = page.url
        self.body = page.html.encode("utf-8")
        self.status = page.status
        self.headers = dict(page.headers)
        self.cookies = tuple(page.cookie_jar)
        self.meta = meta if meta is not None else {}


class FakeSession:
    """Calls page_setup, navigates, runs the anti-bot pass (when the fetch
    asks for it), calls page_action and builds the response, in the fork's
    order and, as Scrapling does, logging and swallowing an exception from
    page_setup or page_action. outcomes are the passes' results, one per
    fetch; a callable gets the page and may change it. ScraplingFetchTests
    drive Scrapling's own fetch instead."""

    def __init__(self, pages, outcomes=()):
        self.pages = list(pages)
        self.outcomes = list(outcomes)
        self.fetch_calls = []

    async def fetch(self, url, **kwargs):
        self.fetch_calls.append(kwargs)
        page = self.pages.pop(0)
        try:
            await kwargs["page_setup"](page)
        except Exception:
            pass
        await page.goto(url)
        meta = {"proxy": kwargs.get("proxy")}
        if kwargs.get("solve_antibot"):
            result = self.outcomes.pop(0) if self.outcomes else CLEAN
            if callable(result):
                result = await result(page)
            meta["antibot"] = result
        try:
            await kwargs["page_action"](page)
        except Exception:
            pass
        return FakeScraplingResponse(page, meta)


def request(**overrides):
    raw = {"url": "https://example.com/", "wait": "load", "wait_ms": 0, "timeout_ms": 30000, "block_resources": False, "solve_challenge": True}
    raw.update(overrides)
    return helper.Request(raw)


class FakeRouter:
    """A SolverRouter stand-in: each job gets a scope, whose ledger the
    helper reports (spent and attempts as if the pass had paid them)."""
    providers = ["capmonster", "capsolver"]

    def __init__(self, spent=0.0, attempts=0):
        self.spent = spent
        self.attempts = attempts
        self.scopes = []

    def scope(self):
        scope = FakeScope(self.spent, self.attempts)
        self.scopes.append(scope)
        return scope

    def supports(self, kind):
        return True

    async def solve_token(self, *args, **kwargs):
        raise AssertionError("never called by the helper")

    async def recognize(self, *args, **kwargs):
        raise AssertionError("never called by the helper")


class FakeScope(FakeRouter):
    is_scope = True

    def __init__(self, spent, attempts):
        super().__init__(spent, attempts)
        self.spent_usd = spent


class FetchTests(unittest.TestCase):
    def fetch(self, session, req=None, solver=None):
        async def go():
            return await helper.Fetcher(session, "http://127.0.0.1:1111", 2, solver).fetch(req or request())
        return run(go())["data"]

    def test_fetch_options_and_last_document_capture(self):
        page = FakePage(PAGE, headers=[("content-type", "text/html"), ("x-last", "1"), ("set-cookie", "sid=1"), ("set-cookie", "__cf_bm=2")])
        page.cookie_jar = [{"name": "__cf_bm", "value": "v", "domain": ".example.com", "path": "/", "expires": -1, "secure": True, "httpOnly": True}]
        session = FakeSession([page])
        data = self.fetch(session)
        self.assertEqual(data["outcome"], "ok")
        self.assertEqual(data["status_code"], 200)
        self.assertEqual((data["challenge"], data["solver"], data["solver_cost_micro_usd"]), ("none", "", 0))
        self.assertIn(["x-last", "1"], data["headers"])
        self.assertEqual(data["set_cookie_names"], ["sid", "__cf_bm"])
        self.assertEqual(data["cookies"][0]["http_only"], True)
        self.assertEqual(data["html"], page.html)
        kwargs = session.fetch_calls[0]
        self.assertEqual(kwargs["proxy"], "http://127.0.0.1:1111")
        self.assertIs(kwargs["network_idle"], False)
        self.assertIs(kwargs["solve_cloudflare"], False)  # the fork's Cloudflare handler does it
        self.assertIs(kwargs["solve_antibot"], True)
        self.assertIsNone(kwargs["captcha_solver"])
        self.assertIs(kwargs["google_search"], False)
        self.assertNotIn("extra_flags", kwargs)
        # The redirect guard is on before the page navigates.
        self.assertEqual(page.context.cdp.sent[0][0], "Fetch.enable")

    def test_the_solver_goes_only_to_fetches_the_node_allows(self):
        router = FakeRouter()
        session = FakeSession([FakePage(PAGE), FakePage(PAGE)])
        self.fetch(session, request(solver=True), solver=router)
        self.fetch(session, request(solver=False), solver=router)
        self.assertEqual(len(router.scopes), 1)  # one scope per job that may use the solver
        self.assertIs(session.fetch_calls[0]["captcha_solver"], router.scopes[0])
        self.assertIsNone(session.fetch_calls[1]["captcha_solver"])
        # No router configured: a request that allows one gets none.
        session = FakeSession([FakePage(PAGE)])
        self.fetch(session, request(solver=True))
        self.assertIsNone(session.fetch_calls[0]["captcha_solver"])

    def test_a_solved_challenge(self):
        async def solve(page):
            page.html = PAGE
            page.emit_document(status=200)
            return SOLVED_DD
        page = FakePage("<html><script>var dd={}</script></html>", status=403)
        session = FakeSession([page], [solve])
        data = self.fetch(session)
        self.assertEqual((data["challenge"], data["solver"], data["status_code"]), ("solved", "", 200))
        self.assertEqual(data["timings"]["challenge_ms"], 2500)
        self.assertEqual(len(session.fetch_calls), 1)

    def test_a_paid_solve_is_used_and_costed(self):
        router = FakeRouter(spent=0.0012, attempts=1)
        data = self.fetch(FakeSession([FakePage(PAGE)], [PAID]), request(solver=True), solver=router)
        self.assertEqual((data["challenge"], data["solver"], data["solver_cost_micro_usd"]), ("solved", "used", 1200))

    def test_both_passes_share_one_scope_and_its_ledger(self):
        router = FakeRouter(spent=0.0025, attempts=2)
        session = FakeSession([FakePage(PAGE), FakePage(PAGE)], [TIMED_OUT, PAID])
        data = self.fetch(session, request(solver=True), solver=router)
        self.assertEqual(len(session.fetch_calls), 2)
        self.assertEqual(len(router.scopes), 1)
        self.assertIs(session.fetch_calls[1]["captcha_solver"], router.scopes[0])
        # The scope's ledger, once: never the passes' summaries added up.
        self.assertEqual((data["challenge"], data["solver"], data["solver_cost_micro_usd"]), ("solved", "used", 2500))

    def test_a_pass_cut_off_mid_solve_still_reports_its_spend(self):
        class Slow(FakeSession):
            async def fetch(self, url, **kwargs):
                self.fetch_calls.append(kwargs)
                await asyncio.sleep(3600)
        router = FakeRouter(spent=0.002, attempts=1)  # a task sent before the cut-off may still be billed
        data = self.fetch(Slow([]), request(solver=True, timeout_ms=1000), solver=router)
        self.assertEqual((data["outcome"], data["solver"], data["solver_cost_micro_usd"]), ("timeout", "needed", 2000))

    def test_the_retry_pass_gets_only_the_time_left(self):
        async def slow(page):
            await asyncio.sleep(1.5)
            return TIMED_OUT
        session = FakeSession([FakePage(PAGE), FakePage(PAGE)], [slow, CLEAN])
        started = time.monotonic()
        self.fetch(session, request(timeout_ms=20000))
        first, second = (call["timeout"] for call in session.fetch_calls)
        self.assertTrue(19000 <= first <= 20000, first)
        # The second pass started at least 1.5 s in: its budget (and the fork's anti-bot deadline inside it) ends
        # before the job's own deadline.
        self.assertLessEqual(second, 20000 - 1500 - 250)
        self.assertLess(time.monotonic() - started, 20)

    def test_unsolved_with_time_left_retries_once_in_a_fresh_context(self):
        session = FakeSession([FakePage(PAGE), FakePage(PAGE)], [TIMED_OUT, CLEAN])
        data = self.fetch(session)
        self.assertEqual(len(session.fetch_calls), 2)
        self.assertEqual(data["challenge"], "none")

    def test_unsolved_without_time_left_is_not_retried(self):
        session = FakeSession([FakePage(PAGE), FakePage(PAGE)], [TIMED_OUT, CLEAN])
        data = self.fetch(session, request(timeout_ms=10000))
        self.assertEqual(len(session.fetch_calls), 1)
        self.assertEqual(data["challenge"], "unsolved")

    def test_a_ban_or_a_captcha_is_never_retried(self):
        for result, solver in ((BANNED, ""), (SLIDER, "needed")):
            session = FakeSession([FakePage(PAGE), FakePage(PAGE)], [result, CLEAN])
            data = self.fetch(session, request(timeout_ms=40000))
            self.assertEqual(len(session.fetch_calls), 1, result["reason"])
            self.assertEqual((data["challenge"], data["solver"]), ("unsolved", solver), result["reason"])

    def test_a_press_and_hold_that_failed_is_retried_and_needs_no_solver(self):
        session = FakeSession([FakePage(PAGE), FakePage(PAGE)], [PX_HOLD, PX_HOLD])
        data = self.fetch(session, request(timeout_ms=40000))
        self.assertEqual(len(session.fetch_calls), 2)
        self.assertEqual((data["challenge"], data["solver"]), ("unsolved", ""))

    def test_a_missing_or_failed_pass_is_unsolved(self):
        for meta in (None, antibot_runner.error_outcome(RuntimeError("x"))):
            async def give(page, meta=meta):
                return meta
            data = self.fetch(FakeSession([FakePage(PAGE)], [give]), request(timeout_ms=10000))
            self.assertEqual(data["challenge"], "unsolved")

    def test_detection_only_when_the_job_turns_solving_off(self):
        seen = []

        async def signal(page, **kwargs):
            seen.append(kwargs)
            return "signal"
        for found, want in ((Detection("akamai", "challenge", "akamai.sec_cpt", {}), "unsolved"), (None, "none")):
            session = FakeSession([FakePage(PAGE)])
            with mock.patch.object(antibot_runner, "read_signal", signal), \
                    mock.patch.object(antibot_detect, "detect", lambda s, found=found: found):
                data = self.fetch(session, request(solve_challenge=False, timeout_ms=10000))
            self.assertIs(session.fetch_calls[0]["solve_antibot"], False)
            self.assertEqual(data["challenge"], want)
        self.assertEqual(seen[0]["status"], 200)

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

    def test_a_guard_that_cannot_start_closes_the_page_and_fails(self):
        for case in ("session", "enable"):
            page = FakePage(PAGE)
            if case == "session":
                page.context.cdp_error = Exception("Target.attachToTarget: Target closed")
            else:
                page.context.cdp_failing = ("Fetch.enable",)
            session = FakeSession([page])
            data = self.fetch(session)
            self.assertEqual((data["outcome"], data["error"], data["html"], data["challenge"]),
                             ("failed", "navigation_failed", "", "none"), case)
            self.assertTrue(page.closed, case)
            self.assertEqual(page.navigations, 0, case)  # nothing loaded unguarded

    def test_an_unguarded_page_is_never_ok(self):
        # The guard fails and so does closing the page: Scrapling navigates
        # anyway, and the result must still not be a success.
        page = FakePage(PAGE)
        page.context.cdp_error = Exception("Target closed")
        page.close_error = Exception("Target closed")
        session = FakeSession([page])
        data = self.fetch(session)
        self.assertEqual(page.navigations, 1)
        self.assertEqual((data["outcome"], data["error"], data["html"]), ("failed", "navigation_failed", ""))

    def test_waits_that_do_not_finish_fail(self):
        async def broken(*args):
            raise RuntimeError("settle")
        page = FakePage(PAGE)
        with mock.patch.object(helper, "settle_navigation", broken):
            data = self.fetch(FakeSession([page]))
        self.assertEqual(page.navigations, 1)
        self.assertEqual((data["outcome"], data["error"], data["html"]), ("failed", "navigation_failed", ""))


class AntibotResultTests(unittest.TestCase):
    def test_mapping(self):
        cases = [
            (CLEAN, ("none", False, "", 0)),
            (SOLVED_DD, ("solved", False, "", 0)),
            (PAID, ("solved", False, "used", 1200)),
            (SLIDER, ("unsolved", True, "needed", 0)),
            (BANNED, ("unsolved", True, "", 0)),
            (TIMED_OUT, ("unsolved", False, "", 0)),
            # Only a layer the fork names a solver kind for needs one: no provider takes Imperva's GeeTest, a
            # widgetless incident page, HUMAN's press and hold, or a hard block found inside the captcha frame.
            (outcome(layer("imperva", "captcha", "imperva.incident", False, "captcha_required:geetest")), ("unsolved", False, "", 0)),
            (outcome(layer("imperva", "captcha", "imperva.incident", False, "blocked:no_widget")), ("unsolved", False, "", 0)),
            (outcome(layer("imperva", "captcha", "imperva.incident", False, "captcha_required:hcaptcha", solver_kind="hcaptcha")),
             ("unsolved", True, "needed", 0)),
            (PX_HOLD, ("unsolved", False, "", 0)),
            (outcome(layer("perimeterx", "captcha", "px.hold", False, "timeout")), ("unsolved", False, "", 0)),
            (outcome(layer("datadome", "captcha", "dd.frame_captcha", False, "ban")), ("unsolved", True, "", 0)),
            (outcome(layer("cloudflare", "captcha", "cf.turnstile", False, "unsolved:cf.turnstile", solver_kind="turnstile")),
             ("unsolved", True, "needed", 0)),
            (outcome(layer("datadome", "captcha", "dd.frame_captcha", False, "ban"), solver={"attempts": 1, "cost_usd": 0.003}),
             ("unsolved", True, "", 3000)),
            (outcome(layer("datadome", "captcha", "dd.frame_captcha", False, "solver_error:ERROR_ZERO_BALANCE", used_solver="capsolver"),
                     solver={"attempts": 1, "cost_usd": 0}), ("unsolved", True, "needed", 0)),
            (outcome(layer("imperva", "challenge", "imperva.interstitial", True, "solved"),
                     layer("datadome", "device_check", "dd.frame_device", True, "solved")), ("solved", False, "", 0)),
            (outcome(layer("akamai", "challenge", "akamai.sec_cpt_html", True, "solved:sec_cpt"),
                     layer("datadome", "captcha", "dd.frame_captcha", False, "slider", solver_kind="datadome_slider")),
             ("unsolved", True, "needed", 0)),
            (antibot_runner.error_outcome(ValueError()), ("unsolved", False, "", 0)),
            (None, ("unsolved", False, "", 0)),
            ("junk", ("unsolved", False, "", 0)),
        ]
        for meta, want in cases:
            self.assertEqual(helper.antibot_result(meta, True), want, meta)
        self.assertEqual(helper.antibot_result(SLIDER, False), ("none", False, "", 0))
        weird = dict(PAID, solver={"attempts": 1, "cost_usd": "lots"})
        self.assertEqual(helper.antibot_result(weird, True)[3], 0)
        for odd in (float("inf"), float("nan"), None, -5):
            self.assertEqual(helper.antibot_result(dict(PAID, solver={"attempts": 1, "cost_usd": odd}), True)[3], 0, odd)
        huge = dict(PAID, solver={"attempts": 1, "cost_usd": 1e9})
        self.assertEqual(helper.antibot_result(huge, True)[3], 10_000_000)


class SolverRouterTests(unittest.TestCase):
    def test_no_config_no_router(self):
        self.assertIsNone(helper.solver_router(""))

    def test_router_from_node_config(self):
        import certifi
        router = helper.solver_router(json.dumps({"capmonster": KEY, "2captcha": "f" * 32, "max_solves_per_fetch": 3, "experimental": True}))
        self.assertEqual(router.providers, ["2captcha", "capmonster"])
        self.assertIs(router.allow_proxy, False)
        self.assertEqual((router.max_solves_per_fetch, router.experimental), (3, True))
        self.assertNotIn(KEY, repr(router))
        for solver in router._shared.solvers.values():
            transport = solver._transport
            https = [h for h in transport._opener.handlers if h.__class__.__name__ == "HTTPSHandler"]
            proxies = [h for h in transport._opener.handlers if h.__class__.__name__ == "ProxyHandler"]
            self.assertEqual(len(https), 1)
            self.assertEqual(https[0]._context.verify_mode, helper.ssl.CERT_REQUIRED)
            self.assertTrue(https[0]._context.check_hostname)
            self.assertTrue(https[0]._context.get_ca_certs() or os.path.exists(certifi.where()))
            self.assertEqual(proxies, [])  # never HTTP(S)_PROXY from the environment

    def test_bad_configs_never_echo_a_key(self):
        secret = "s3cr3t-0123456789"
        for raw in ("{", "[]", json.dumps({"capmonster": 1}), json.dumps({"anticaptcha": secret}),
                    json.dumps({"capmonster": secret, "proxy": "http://x"}), json.dumps({"capmonster": secret + " x"}),
                    json.dumps({"capmonster": secret, "max_solves_per_fetch": 0}), json.dumps({"capmonster": secret, "experimental": "yes"}),
                    json.dumps({"max_solves_per_fetch": 2})):
            with self.assertRaises(ValueError) as caught:
                helper.solver_router(raw)
            self.assertNotIn(secret, str(caught.exception))


class ScraplingFetchTests(unittest.TestCase):
    """Scrapling's own AsyncStealthySession.fetch, with its page source and
    response builder replaced by fakes and the fork's anti-bot runner
    replaced by recorders: it runs the pass after navigation and before
    page_action, passes the per-fetch solver through, logs and swallows an
    exception from page_setup and page_action and navigates anyway, and the
    Fetcher must fail closed regardless."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        profile = os.path.join(tmp.name, helper.PROFILE_PREFIX + "x")
        helper.seed_profile(profile)
        self.session = helper.new_session(sys.executable, UA, "http://127.0.0.1:1111", "http://127.0.0.1:2222", 1, profile)
        self.session._is_alive = True
        self.pages = []
        self.calls = []
        self.outcome = CLEAN

        @contextlib.asynccontextmanager
        async def page_generator(*args, **kwargs):
            yield PageInfo(page=self.pages.pop(0), state="busy", url="")
        self.session._page_generator = page_generator

        async def build(page, first_response, final_response, selector_config, meta=None, **kwargs):
            return FakeScraplingResponse(page, meta)

        async def prepare(page, **kwargs):
            self.calls.append(("prepare", page.navigations))
            return {"hardened": True, "errors": 0}

        async def solve(page, *, document, deadline, solver=None, log=None):
            self.calls.append(("solve", page.navigations, solver, deadline - time.monotonic()))
            return self.outcome
        for target, name, value in ((_stealth.ResponseFactory, "from_async_playwright_response", build),
                                    (antibot_runner, "prepare_page", prepare), (antibot_runner, "solve_page", solve),
                                    (antibot_runner, "release_page", lambda page: None)):
            patcher = mock.patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def fetch(self, page, req=None, solver=None):
        self.pages.append(page)

        async def go():
            return await helper.Fetcher(self.session, "http://127.0.0.1:1111", 1, solver).fetch(req or request())
        return run(go())["data"]

    def test_a_guarded_page_is_ok(self):
        page = FakePage(PAGE)
        data = self.fetch(page)
        self.assertEqual((data["outcome"], data["status_code"], data["html"], data["challenge"]), ("ok", 200, page.html, "none"))
        self.assertEqual(page.context.cdp.sent[0][0], "Fetch.enable")
        self.assertEqual(page.navigations, 1)

    def test_the_pass_runs_after_navigation_with_the_fetch_budget_and_solver(self):
        router = FakeRouter(spent=0.0012, attempts=1)
        self.outcome = PAID
        data = self.fetch(FakePage(PAGE), request(solver=True, timeout_ms=20000), solver=router)
        self.assertEqual(self.calls[0], ("prepare", 0))  # hardened before it navigates
        name, navigations, solver, budget = self.calls[1]
        self.assertEqual((name, navigations), ("solve", 1))
        self.assertIs(solver, router.scopes[0])
        self.assertTrue(15 < budget <= 18, budget)  # the fetch's 20 s less its reserve
        self.assertEqual((data["challenge"], data["solver"], data["solver_cost_micro_usd"]), ("solved", "used", 1200))
        self.calls.clear()
        self.fetch(FakePage(PAGE), request(solver=False), solver=router)
        self.assertIsNone(self.calls[1][2])

    def test_an_unsolved_page_is_reported(self):
        self.outcome = SLIDER
        data = self.fetch(FakePage(PAGE), request(timeout_ms=40000))
        self.assertEqual((data["outcome"], data["challenge"], data["solver"]), ("ok", "unsolved", "needed"))

    def test_the_retry_pass_deadline_ends_before_the_jobs(self):
        """The fork's anti-bot deadline on the retry pass (where paid solves run) is inside the job's deadline."""
        outcomes = [TIMED_OUT, CLEAN]
        seen = []

        async def solve(page, *, document, deadline, solver=None, log=None):
            seen.append(deadline)
            if len(seen) == 1:
                await asyncio.sleep(2)
            return outcomes.pop(0)
        self.pages.append(FakePage(PAGE))
        started = time.monotonic()
        with mock.patch.object(antibot_runner, "solve_page", solve):
            data = self.fetch(FakePage(PAGE), request(timeout_ms=20000))
        job_deadline = started + 20
        self.assertEqual((len(seen), data["challenge"]), (2, "none"))
        self.assertLess(seen[0], job_deadline)
        self.assertLess(seen[1], job_deadline - 1)  # inside the job's budget, with the response's reserve

    def test_a_guard_that_cannot_start_fails_before_navigation(self):
        for case in ("session", "enable"):
            page = FakePage(PAGE)
            if case == "session":
                page.context.cdp_error = Exception("Target.attachToTarget: Target closed")
            else:
                page.context.cdp_failing = ("Fetch.enable",)
            data = self.fetch(page)
            self.assertEqual((data["outcome"], data["error"], data["html"]), ("failed", "navigation_failed", ""), case)
            self.assertEqual(page.navigations, 0, case)

    def test_an_unguarded_page_is_never_ok(self):
        page = FakePage(PAGE)
        page.context.cdp_error = Exception("Target closed")
        page.close_error = Exception("Target closed")
        data = self.fetch(page)
        self.assertEqual(page.navigations, 1)  # Scrapling navigated without the guard
        self.assertEqual((data["outcome"], data["error"], data["html"]), ("failed", "navigation_failed", ""))

    def test_waits_that_do_not_finish_fail(self):
        async def broken(*args):
            raise RuntimeError("settle")
        page = FakePage(PAGE)
        with mock.patch.object(helper, "settle_navigation", broken):
            data = self.fetch(page)
        self.assertEqual(page.navigations, 1)
        self.assertEqual((data["outcome"], data["error"], data["html"]), ("failed", "navigation_failed", ""))


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
        self.assertEqual(body, {"data": {"web_browser": 1, "engine": "scrapling/0.4.15+scarlett.2", "browser_version": "155.0.8059.39",
                                         "max_pages": 2, "solvers": []}})

    def test_capabilities_name_the_solvers_never_their_keys(self):
        class Fetcher:
            solver = FakeRouter()
        server = helper.Server("ab" * 32, Fetcher(), "155.0.8059.39", 1)
        self.server = server
        status, body = self.call(self.head("GET", "/v1/capabilities"))
        self.assertEqual(body["data"]["solvers"], ["capmonster", "capsolver"])

    def test_solver_flag_is_a_boolean(self):
        for value, ok in ((True, True), (False, True), ("yes", False), (1, False)):
            body = json.dumps({"url": "https://example.com/", "solver": value}).encode()
            status, _ = self.call(self.head("POST", "/v1/fetch", body, extra="Content-Type: application/json\r\n"))
            self.assertEqual(status == 200, ok, value)

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
