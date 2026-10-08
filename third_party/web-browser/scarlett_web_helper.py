"""Scarlett node web browser helper.

The node (internal/webruntime) starts this module inside its bundled Python
with an allowlisted environment, then talks to it over loopback HTTP with a
bearer. It renders one page per request in a fresh browser context through
Scrapling's AsyncStealthySession and Chrome for Testing. Every per-job context
uses the node's filtering egress proxy; the browser's own background traffic
goes to the node's deny listener.

Bot protection is handled by the Scrapling build the runtime pins
(0.4.15+scarlett.1, teslashibe/Scrapling): with solve_antibot on the session
the browser launches as the real machine, and after each navigation the page
is checked for DataDome, HUMAN (PerimeterX), Akamai, Imperva, AWS WAF, Kasada
and Cloudflare and their challenges are solved within the fetch's budget. The
outcome is response.meta["antibot"]. When the operator configured captcha
solver accounts, the node passes them in WEB_SOLVER_CONFIG; the helper takes
the variable out of its environment at once and the keys only ever go to the
providers' own APIs.

It never logs URLs, headers, cookies, page content or solver keys. Its only
stderr line of its own is SCARLETT_WEB_BROWSER_ERROR=<reason> when the browser
cannot start. Standard library plus that Scrapling build (and certifi, one of
its dependencies, for the solver providers' TLS roots) only.
"""

import asyncio
import hmac
import json
import logging
import os
import re
import shutil
import ssl
import sys
import tempfile
import threading
import time
from urllib.parse import urljoin, urlsplit

SCRAPLING_VERSION = "0.4.15+scarlett.1"
PORT_PREFIX = "SCARLETT_WEB_HELPER_PORT="
ENGINE = "scrapling/" + SCRAPLING_VERSION
MAX_REQUEST_BODY = 65536
MAX_REQUEST_HEAD = 16384
HTML_CAP = 10485760
MAX_HEADERS = 128
MAX_HEADER_BYTES = 65536
MAX_SET_COOKIE_NAMES = 50
MAX_REDIRECTS = 20

# Patchright 1.63.0 disabledFeatures, in order. The helper replaces Patchright's
# feature pair with one merged pair (DISABLED, ENABLED below).
PW_DISABLED = [
    "AvoidUnnecessaryBeforeUnloadCheckSync", "DestroyProfileOnBrowserClose", "DialMediaRouteProvider",
    "GlobalMediaControls", "HttpsUpgrades", "LensOverlay", "MediaRouter", "PaintHolding", "ThirdPartyStoragePartitioning",
    "BlockOriginHeaderModificationOnRedirect", "Translate", "AutoDeElevate", "OptimizationHints", "msForceBrowserSignIn",
    "msEdgeUpdateLaunchServicesPreferredVersion",
]
# The rest of Patchright 1.63.0's default argv for a headless launch, in its
# order: chromiumSwitches without the feature pair, then the headless switches.
# The helper passes the whole argv itself (ignore_default_args=True) because
# Patchright only takes a profile directory in persistent mode, and the
# browser must start on a profile the helper created and seeded (PROFILE_PREFS).
# With the profile path aside, the argv is byte for byte what Patchright built;
# test_patchright_defaults_match pins these lists to the shipped driver.
PW_SWITCHES = [
    "--disable-field-trial-config", "--disable-background-networking", "--disable-background-timer-throttling",
    "--disable-backgrounding-occluded-windows", "--disable-breakpad", "--no-default-browser-check", "--disable-dev-shm-usage",
    "--disable-edgeupdater", "--disable-hang-monitor", "--disable-prompt-on-repost", "--disable-renderer-backgrounding",
    "--disable-updater-scheduler", "--force-color-profile=srgb", "--no-first-run", "--password-store=basic",
    "--use-mock-keychain", "--no-service-autorun", "--export-tagged-pdf", "--disable-search-engine-choice-screen",
    "--edge-skip-compat-layer-relaunch", "--disable-infobars", "--disable-search-engine-choice-screen", "--disable-sync",
    "--disable-blink-features=AutomationControlled",
]
PW_HEADLESS = ["--headless", "--hide-scrollbars", "--mute-audio",
               "--blink-settings=primaryHoverType=2,availableHoverTypes=2,primaryPointerType=4,availablePointerTypes=4"]
# Scrapling's HARMFUL_ARGS without --disable-component-update (which we pass):
# Patchright used to drop these from the argv; the helper still does.
FILTERED_ARGS = ["--enable-automation", "--disable-popup-blocking", "--disable-default-apps", "--disable-extensions"]
# Scrapling's three disabled features, then ours: no Cast, and no mDNS names
# for local WebRTC candidates (mDNS is a macOS local network operation).
DISABLED = PW_DISABLED + ["AudioServiceOutOfProcess", "TranslateUI", "BlinkGenPropertyTrees",
                          "CastMediaRouteProvider", "WebRtcHideLocalIpsWithMdns"]
ENABLED = ["CDPScreenshotNewSurface", "NetworkService", "NetworkServiceInProcess", "TrustTokens",
           "TrustTokensAlwaysAllowIssuance"]
WEBRTC_POLICY = ["--webrtc-ip-handling-policy=disable_non_proxied_udp",
                 "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"]
# Fake capture devices: getUserMedia never reaches the camera or microphone,
# so a page cannot make the OS ask the operator for them (measured: a real
# device request raised a macOS microphone prompt and hung the browser).
EXTRA_ARGS = ["--deny-permission-prompts", "--disable-quic", "--disable-component-update",
              "--use-fake-device-for-media-stream"]
PIPE_ARGS = ["--remote-debugging-pipe", "--no-startup-window"]

# The browser profile's only file before launch (<profile>/Default/Preferences).
# Every job context is an off-the-record child of this profile and reads it.
#  - URL blocklist for Chrome's always-allowed external schemes (mailto: is
#    the one Chrome 155 still hands to the OS with no prompt and no gesture;
#    news: and snews: were): a navigation to them fails as blocked before it
#    reaches the external-protocol code. Every other scheme gets Chrome's
#    dialog, which the hidden browser never shows.
#  - Protocol handlers, the second layer for mailto: and news:: a registered
#    handler takes precedence over the OS handler, so the link becomes an
#    https navigation to a reserved .invalid host, which the egress proxy
#    refuses before any lookup. Chrome for Testing never registers with the
#    OS as a default handler, and the off-the-record contexts see only
#    handlers marked for incognito.
#  - Device choosers off (the "don't allow sites to ask" setting): Bluetooth,
#    USB, HID and serial requests fail at once, before any scan. A scan made a
#    macOS Bluetooth TCC request and crashed the browser (no usage string).
#  - Screen capture off (the ScreenCaptureAllowed setting): getDisplayMedia
#    fails before the picker, which made Screen Recording TCC requests.
BLOCKED_HANDLER = "https://scarlett-blocked.invalid/?u=%s"
HANDLED_SCHEMES = ("mailto", "news")
BLOCKED_SCHEMES = ("mailto", "news", "snews")
PROFILE_PREFS = {
    "custom_handlers": {
        "enabled": True,
        "registered_protocol_handlers": [
            {"protocol": scheme, "url": BLOCKED_HANDLER, "default": True, "is_allowed_in_incognito": True}
            for scheme in HANDLED_SCHEMES],
    },
    "policy": {"url_blocklist": [scheme + ":*" for scheme in BLOCKED_SCHEMES]},
    "profile": {"default_content_setting_values": {"bluetooth_guard": 2, "hid_guard": 2, "serial_guard": 2, "usb_guard": 2}},
    "hardware": {"screen_capture_enabled": False},
}
PROFILE_PREFIX = "scarlett-profile-"

# The launch switches the anti-bot launch hardening may drop from the
# helper's argv (display-only headless tells: window placement, colour
# profile, scrollbars, font hinting, compositor threading, a touch pointer),
# and the only switches it may add: the host's real screen, scale and window,
# a wide-gamut colour profile and the User-Agent.
ANTIBOT_DROPPED = ("--window-position=0,0", "--force-color-profile=srgb", "--hide-scrollbars", "--font-render-hinting=none",
                   "--disable-threaded-animation", "--disable-threaded-scrolling", "--start-maximized")
ANTIBOT_DROPPED_PREFIXES = ("--blink-settings=", "--window-size=", "--screen-info=", "--force-device-scale-factor=")
ANTIBOT_ADDED_PREFIXES = ("--screen-info=", "--force-device-scale-factor=", "--window-size=",
                          "--force-color-profile=scrgb-linear", "--user-agent=")
# Captcha-solver providers and the options the node may set (WEB_SOLVER_CONFIG).
SOLVER_PROVIDERS = ("capmonster", "capsolver", "2captcha")
SOLVER_OPTIONS = ("max_solves_per_fetch", "experimental")
# A page left at one of these needs a captcha solver to get further.
SOLVER_REASONS = ("slider", "slider_failed", "slider_unreadable", "captcha", "captcha_required", "solver_error",
                  "awswaf_images")
TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9a-z-]{1,64}$")
SELECTOR = re.compile(r"^[\x20-\x7e]{1,256}$")
URL_STRIP = re.compile(r"[\t\n\r]")

logging.getLogger("scrapling").disabled = True


class LaunchError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def launch_reason(error):
    """The closed reason for a browser that did not start (never its text)."""
    text = str(error)
    if "error while loading shared libraries" in text or "is missing dependencies" in text:
        return "deps_missing"
    # Chrome's own fatal lines when unprivileged user namespaces are blocked
    # (Ubuntu 23.10+ AppArmor) or the setuid sandbox is unusable.
    if any(m in text for m in ("No usable sandbox", "Failed to move to new namespace", "setuid sandbox", "zygote_host_impl_linux")):
        return "sandbox_unavailable"
    return "launch_failed"


def browser_args(base, deny_proxy, profile):
    """The whole launch argv: Patchright's defaults, the deny proxy, Scrapling's
    set with its feature switches replaced by one merged pair, the WebRTC
    policy with its value, ours, then the seeded profile and the pipe."""
    own = [a for a in base if not a.startswith(("--disable-features=", "--enable-features=",
                                                 "--webrtc-ip-handling-policy", "--force-webrtc-ip-handling-policy"))
           and a not in FILTERED_ARGS]
    own += ["--disable-features=" + ",".join(DISABLED), "--enable-features=" + ",".join(ENABLED)] + WEBRTC_POLICY + EXTRA_ARGS
    return PW_SWITCHES + PW_HEADLESS + ["--proxy-server=" + deny_proxy, "--proxy-bypass-list=<-loopback>"] + own + \
        ["--user-data-dir=" + profile] + PIPE_ARGS


def seed_profile(profile):
    """Writes PROFILE_PREFS into a new, empty profile directory."""
    os.makedirs(os.path.join(profile, "Default"), mode=0o700)
    with open(os.path.join(profile, "Default", "Preferences"), "x", encoding="utf-8") as f:
        json.dump(PROFILE_PREFS, f)


def profile_problems(profile):
    try:
        with open(os.path.join(profile, "Default", "Preferences"), encoding="utf-8") as f:
            return [] if json.load(f) == PROFILE_PREFS else ["profile-prefs"]
    except (OSError, ValueError):
        return ["profile-prefs"]


def new_session(executable, user_agent, proxy, deny_proxy, max_pages, profile):
    """Builds the session exactly as contract C.6 says, without starting it.
    profile is the seeded profile directory the browser will use. The anti-bot
    pass is on for the session, so the browser launches hardened (the fork
    rewrites the launch argv at start(); launch_problems checks the result);
    each fetch still turns the pass on or off and picks its solver."""
    from scrapling.fetchers import AsyncStealthySession
    from scrapling.engines.toolbelt.proxy_rotation import ProxyRotator

    session = AsyncStealthySession(
        headless=True, executable_path=executable, useragent=user_agent, locale="en-US", google_search=False,
        retries=1, block_webrtc=True, hide_canvas=False, allow_webgl=True, max_pages=max_pages, timeout=30000,
        solve_antibot=True,
        # Launch mode (chromium.launch) with a fresh context per fetch.
        proxy_rotator=ProxyRotator([proxy]),
        additional_args={"permissions": [], "accept_downloads": False, "service_workers": "allow",
                         "ignore_https_errors": False})
    # Never extra_flags: Scrapling 0.4.15 then drops its default and stealth
    # args and both WebRTC switches. Edit the launch options instead.
    options = session._browser_options
    options["chromium_sandbox"] = True
    options["proxy"] = {"server": deny_proxy}
    options["args"] = browser_args(options["args"], deny_proxy, profile)
    options["ignore_default_args"] = True
    return session


def option_problems(session, capacity):
    """What --self-check and the tests assert about a built session."""
    from scrapling.engines.constants import STEALTH_ARGS

    problems = []
    options = session._browser_options
    args = options["args"]
    disable = [a for a in args if a.startswith("--disable-features=")]
    enable = [a for a in args if a.startswith("--enable-features=")]
    if len(disable) != 1 or set(disable[0].split("=", 1)[1].split(",")) != set(DISABLED):
        problems.append("disable-features")
    if len(enable) != 1 or set(enable[0].split("=", 1)[1].split(",")) != set(ENABLED):
        problems.append("enable-features")
    for arg in STEALTH_ARGS:
        if not arg.startswith(("--disable-features=", "--enable-features=")) and arg not in args:
            problems.append("stealth:" + arg)
    for arg in WEBRTC_POLICY + EXTRA_ARGS + ["--disable-blink-features=AutomationControlled"]:
        if arg not in args:
            problems.append("missing:" + arg)
    if any(a == "--no-sandbox" or a == "--force-webrtc-ip-handling-policy" or a in FILTERED_ARGS or
           a.startswith(("--remote-debugging-port", "--use-fake-ui-for-media-stream")) for a in args):
        problems.append("forbidden-arg")
    proxy = options.get("proxy") if isinstance(options.get("proxy"), dict) else {}
    head = PW_SWITCHES + PW_HEADLESS + ["--proxy-server=" + str(proxy.get("server")), "--proxy-bypass-list=<-loopback>"]
    if args[:len(head)] != head or options.get("headless") is not True:
        problems.append("driver-defaults")
    profiles = [a for a in args if "user-data-dir" in a]
    if len(profiles) != 1 or args[-3:] != profiles + PIPE_ARGS or not profiles[0].startswith("--user-data-dir=") or \
            not os.path.isabs(profiles[0][len("--user-data-dir="):]) or args.count("--remote-debugging-pipe") != 1:
        problems.append("profile")
    if options.get("ignore_default_args") is not True:
        problems.append("ignore_default_args")
    if options.get("chromium_sandbox") is not True:
        problems.append("sandbox")
    if not proxy.get("server"):
        problems.append("deny-proxy")
    if session._config.extra_flags:
        problems.append("extra_flags")
    context = session._context_options
    if context.get("ignore_https_errors") is not False or context.get("permissions") != [] or context.get("accept_downloads") is not False:
        problems.append("context")
    if session.max_pages != capacity or session._config.max_pages != capacity:
        problems.append("max_pages")
    if not logging.getLogger("scrapling").disabled:
        problems.append("logger")
    return problems + launch_problems(session)


def antibot_dropped(arg):
    return arg in ANTIBOT_DROPPED or arg.startswith(ANTIBOT_DROPPED_PREFIXES)


def launch_problems(session):
    """What the browser really starts with. With solve_antibot on the session
    the fork rewrites the argv at start(): it may drop only the headless tells
    (ANTIBOT_DROPPED) and append only the host's screen, scale, window, colour
    profile and User-Agent; every other launch option, the deny proxy, the
    sandbox, the seeded profile and the pipe stay as built."""
    problems = []
    config = session._config
    if not (config.solve_antibot and config.headless and not config.cdp_url and session._antibot_hardened_launch()):
        return ["antibot-launch"]
    built = session._browser_options
    launch = session._launch_options()
    if {k: v for k, v in launch.items() if k != "args"} != {k: v for k, v in built.items() if k != "args"}:
        problems.append("launch-options")
    kept = [a for a in built["args"] if not antibot_dropped(a)]
    args = launch.get("args") or []
    added = args[len(kept):]
    if args[:len(kept)] != kept:
        problems.append("launch-kept")
    if any(not a.startswith(ANTIBOT_ADDED_PREFIXES) for a in added) or \
            any(sum(a.startswith(p) for a in added) > 1 for p in ANTIBOT_ADDED_PREFIXES):
        problems.append("launch-added")
    if any(a.startswith("--user-agent=") and a != "--user-agent=" + config.useragent for a in added):
        problems.append("launch-user-agent")
    if any(a == "--no-sandbox" or a in FILTERED_ARGS or a.startswith(("--remote-debugging-port", "--use-fake-ui-for-media-stream"))
           for a in args) or args.count("--remote-debugging-pipe") != 1:
        problems.append("launch-forbidden-arg")
    if session._context_options.get("no_viewport") is not True:
        problems.append("launch-viewport")
    return problems


def solver_router(raw):
    """The SolverRouter for WEB_SOLVER_CONFIG, or None when it is empty.

    raw is the node's JSON: provider keys (capmonster, capsolver, 2captcha)
    and SOLVER_OPTIONS. Providers are reached directly (never through the
    page's proxy, and never with a proxy for the provider to use), over TLS
    verified against certifi's roots. Raises ValueError without the value."""
    if not raw:
        return None
    try:
        config = json.loads(raw)
    except ValueError:
        raise ValueError("solver config") from None
    if not isinstance(config, dict) or set(config) - set(SOLVER_PROVIDERS) - set(SOLVER_OPTIONS) or \
            not any(isinstance(config.get(p), str) and config.get(p) for p in SOLVER_PROVIDERS):
        raise ValueError("solver config")
    solves = config.get("max_solves_per_fetch", 2)
    if type(solves) is not int or not 1 <= solves <= 4 or type(config.get("experimental", False)) is not bool:
        raise ValueError("solver config")
    for name in SOLVER_PROVIDERS:
        key = config.get(name)
        if key is not None and (not isinstance(key, str) or not 8 <= len(key) <= 256 or any(not "!" <= c <= "~" for c in key)):
            raise ValueError("solver config")
    import certifi
    from scrapling.engines.antibot.solvers import SolverRouter, UrllibTransport

    context = ssl.create_default_context(cafile=certifi.where())
    options = {name: config[name] for name in SOLVER_PROVIDERS if config.get(name)}
    options.update(allow_proxy=False, trust_env=False, max_solves_per_fetch=solves, max_attempts_per_solve=3,
                   experimental=config.get("experimental", False))
    return SolverRouter.from_config(options, transport=UrllibTransport(ssl_context=context))


def self_check():
    import curl_cffi
    import lxml.etree
    import patchright
    import playwright
    import scrapling
    from importlib.metadata import version

    from scrapling.engines.antibot import runner
    from scrapling.fetchers import AsyncStealthySession

    assert scrapling.__version__ == SCRAPLING_VERSION, "scrapling version"
    for name in ("_antibot_hardened_launch", "_launch_options", "_antibot_solve", "_antibot_prepare"):
        assert callable(getattr(AsyncStealthySession, name, None)), "scrapling internal " + name
    for name in ("solve_page", "prepare_page", "read_signal"):
        assert callable(getattr(runner, name, None)), "scrapling antibot " + name
    # A router builds offline from a synthetic key; nothing is sent.
    router = solver_router(json.dumps({"capmonster": "0" * 32, "max_solves_per_fetch": 2}))
    assert router is not None and router.providers == ["capmonster"] and router.allow_proxy is False, "solver router"
    # Any existing absolute file stands in for the browser; nothing starts.
    with tempfile.TemporaryDirectory() as tmp:
        profile = os.path.join(tmp, "profile")
        seed_profile(profile)
        session = new_session(sys.executable, "Mozilla/5.0", "http://127.0.0.1:9", "http://127.0.0.1:9", 2, profile)
        assert isinstance(getattr(session, "_browser_options", None), dict), "scrapling internal _browser_options"
        problems = option_problems(session, 2) + profile_problems(profile)
    assert not problems, "option set: " + ",".join(problems)
    report = {"self_check": "passed", "python": ".".join(map(str, sys.version_info[:3])), "scrapling": scrapling.__version__,
              "patchright": version("patchright"), "playwright": version("playwright"), "curl_cffi": curl_cffi.__version__,
              "lxml": lxml.etree.__version__}
    del patchright, playwright
    print(json.dumps(report, sort_keys=True))


# ---------------------------------------------------------------- fetch


class Request:
    def __init__(self, raw):
        if not isinstance(raw, dict) or set(raw) - {"url", "wait", "wait_ms", "wait_selector", "timeout_ms",
                                                     "block_resources", "solve_challenge", "solver"}:
            raise ValueError("fields")
        self.url = raw.get("url")
        self.wait = raw.get("wait", "networkidle")
        self.wait_ms = raw.get("wait_ms", 0)
        self.wait_selector = raw.get("wait_selector", "") or ""
        self.timeout_ms = raw.get("timeout_ms", 30000)
        self.block_resources = raw.get("block_resources", False)
        self.solve_challenge = raw.get("solve_challenge", True)
        # The node turns the operator's solver off once its daily cap is spent.
        self.solver = raw.get("solver", False)
        if not isinstance(self.url, str) or len(self.url) > 2048 or not self.url.startswith(("https://", "http://")) or \
                any(c <= " " or c == "\x7f" for c in self.url):
            raise ValueError("url")
        if self.wait not in ("load", "networkidle"):
            raise ValueError("wait")
        for name, low, high in (("wait_ms", 0, 15000), ("timeout_ms", 1000, 45000)):
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ValueError(name)
        if self.wait_selector and not SELECTOR.match(self.wait_selector):
            raise ValueError("wait_selector")
        if type(self.block_resources) is not bool or type(self.solve_challenge) is not bool or type(self.solver) is not bool:
            raise ValueError("flags")


def cap_html(html):
    """At most HTML_CAP UTF-8 bytes, cut on a code-point boundary."""
    raw = html.encode("utf-8", "replace")
    if len(raw) <= HTML_CAP:
        return raw.decode("utf-8"), False
    return raw[:HTML_CAP].decode("utf-8", "ignore"), True


def header_pairs(pairs):
    """Lowercase token names and printable values within the upload caps; the
    Set-Cookie and Cookie values never leave, only Set-Cookie names do."""
    headers, names, total = [], [], 0
    for name, value in pairs:
        name = name.lower()
        if name == "set-cookie":
            cookie = value.split("=", 1)[0].strip()
            if cookie and len(names) < MAX_SET_COOKIE_NAMES and TOKEN.match(cookie.lower()) and "=" in value:
                names.append(cookie)
            continue
        if name == "cookie" or not TOKEN.match(name) or len(value) > 4096 or any(not " " <= c <= "~" for c in value):
            continue
        if len(headers) >= MAX_HEADERS or total + len(name) + len(value) > MAX_HEADER_BYTES:
            break
        total += len(name) + len(value)
        headers.append([name, value])
    return headers, names


class Document:
    """The main-frame document responses of one page, newest last."""

    def __init__(self, page):
        self.page = page
        self.responses = []
        self.pending = set()
        self.headers = {}

    def on_response(self, response):
        try:
            if response.request.resource_type != "document" or response.frame != self.page.main_frame:
                return
        except Exception:
            return
        self.responses.append(response)
        task = asyncio.ensure_future(self._capture(response))
        self.pending.add(task)
        task.add_done_callback(self.pending.discard)

    async def _capture(self, response):
        try:
            self.headers[id(response)] = [(h["name"], h["value"]) for h in await response.headers_array()]
        except Exception:
            pass

    async def settle(self, timeout):
        if self.pending:
            await asyncio.wait(list(self.pending), timeout=max(0.05, timeout))

    @property
    def last(self):
        return self.responses[-1] if self.responses else None

    def last_header(self, name):
        last = self.last
        if last is None:
            return ""
        for key, value in self.headers.get(id(last), []):
            if key.lower() == name:
                return value
        try:
            return last.headers.get(name, "")
        except Exception:
            return ""

    def header(self, response, name):
        for key, value in self.pairs(response):
            if key.lower() == name:
                return value
        return ""

    def pairs(self, response):
        if id(response) in self.headers:
            return self.headers[id(response)]
        try:
            return list(response.headers.items())
        except Exception:
            return []


async def settle_navigation(page, document, remaining):
    """Wait for the load of any main-frame document that arrived meanwhile, so
    a challenge's reload is read as the new page, not mid-navigation."""
    for _ in range(4):
        seen = len(document.responses)
        try:
            await page.wait_for_load_state("load", timeout=max(1, min(5000, int(remaining() * 1000) - 1000)))
        except Exception:
            return
        if len(document.responses) == seen:
            return


def refused_redirect(event):
    """True for a paused document response that redirects to anything but
    http(s): mailto:, facetime:, an app's own scheme and the like."""
    status = event.get("responseStatusCode") or 0
    if not 300 <= status < 400:
        return False
    location = next((h.get("value", "") for h in event.get("responseHeaders") or () if h.get("name", "").lower() == "location"), None)
    if location is None:
        return False
    # As a URL parser does: tabs and newlines go anywhere, C0 controls and
    # spaces at the ends.
    location = URL_STRIP.sub("", location).strip("".join(map(chr, range(0x21))))
    try:
        target = urljoin(event.get("request", {}).get("url", ""), location)
        return urlsplit(target).scheme.lower() not in ("http", "https")
    except ValueError:
        return True


async def guard_redirects(page):
    """Fails any document redirect whose Location is not http(s), so a 3xx
    (which Chrome follows like a typed navigation, skipping its anti-flood
    check) never hands the browser an external protocol. Covers the page's
    target: the main frame and same-process frames; for cross-site frames,
    pop-ups and service workers the seeded handlers and Chrome's own dialog
    remain (PROFILE_PREFS). If it raises, the Fetcher closes the page before
    it navigates and fails the fetch."""
    cdp = await page.context.new_cdp_session(page)

    async def paused(event):
        try:
            if refused_redirect(event):
                await cdp.send("Fetch.failRequest", {"requestId": event["requestId"], "errorReason": "BlockedByClient"})
            else:
                await cdp.send("Fetch.continueResponse", {"requestId": event["requestId"]})
        except Exception:
            pass  # the page or context is gone

    cdp.on("Fetch.requestPaused", lambda event: asyncio.ensure_future(paused(event)))
    await cdp.send("Fetch.enable", {"patterns": [{"urlPattern": "*", "resourceType": "Document", "requestStage": "Response"}]})


def solver_state(outcome):
    """'used' when an operator-paid solve cleared the page, 'needed' when the
    page stopped at a captcha that takes a solver (none configured, none
    allowed for this fetch, or the solver failed), else ''."""
    layers = [layer for layer in outcome.get("layers") or () if isinstance(layer, dict)]
    used = bool((outcome.get("solver") or {}).get("attempts")) or any(layer.get("used_solver") for layer in layers)
    if outcome.get("solved"):
        return "used" if used else ""
    last = layers[-1] if layers else {}
    reason = str(outcome.get("reason") or "")
    if used or last.get("kind") == "captcha" or reason.split(":", 1)[0] in SOLVER_REASONS or reason.endswith(":captcha"):
        return "needed"
    return ""


def antibot_result(outcome, solving):
    """Maps response.meta["antibot"] to the node's closed fields: challenge
    (none, solved, unsolved), no_retry, solver ('', used, needed) and the
    estimated solver spend in micro-USD. A fetch that asked for the pass and
    got no outcome is unsolved; a ban, and anything a solver touched or
    needs, is never retried in a fresh context."""
    if not solving:
        return "none", False, "", 0
    if not isinstance(outcome, dict):
        return "unsolved", False, "", 0
    try:
        cost = max(0, min(10_000_000, round(float((outcome.get("solver") or {}).get("cost_usd") or 0) * 1_000_000)))
    except (TypeError, ValueError, OverflowError):
        cost = 0
    solver = solver_state(outcome)
    if outcome.get("vendor") is None and outcome.get("reason") == "none":
        return "none", False, solver, cost
    if outcome.get("solved") is True:
        return "solved", False, solver, cost
    banned = outcome.get("kind") == "ban" or outcome.get("reason") == "ban" or \
        any(isinstance(layer, dict) and layer.get("kind") == "ban" for layer in outcome.get("layers") or ())
    return "unsolved", banned or solver != "", solver, cost


class Fetcher:
    def __init__(self, session, proxy, max_pages, solver=None):
        self.session = session
        self.proxy = proxy
        self.slots = asyncio.Semaphore(max_pages)
        self.solver = solver

    async def fetch(self, request):
        async with self.slots:
            loop = asyncio.get_running_loop()
            started = loop.time()
            deadline = started + request.timeout_ms / 1000
            result = await self._once(request, deadline)
            if result["data"]["challenge"] == "unsolved" and not result["no_retry"] and deadline - loop.time() >= 15:
                spent = result["data"]["solver_cost_micro_usd"]
                result = await self._once(request, deadline)
                result["data"]["solver_cost_micro_usd"] += spent
            result["data"]["timings"]["total_ms"] = round((loop.time() - started) * 1000)
            return result

    async def _once(self, request, deadline):
        loop = asyncio.get_running_loop()
        started_at_ms = int(time.time() * 1000)
        begin = loop.time()
        marks = {"context": None, "navigated": None}
        state = {"document": None, "guarded": False, "acted": False, "setup_failed": False, "detected": False}
        session = self.session

        def remaining():
            return deadline - loop.time()

        # Scrapling logs and swallows an exception from page_setup and from
        # page_action and carries on: it would navigate without the redirect
        # guard, or return a page whose waits never finished. So each records
        # that it finished, and only a fetch where both did is ok. The
        # anti-bot pass runs between the two (after navigation, before
        # page_action) and reports through response.meta["antibot"].
        async def setup(page):
            state.update(document=None, guarded=False, acted=False, setup_failed=False, detected=False)
            marks["context"] = loop.time()
            try:
                await guard_redirects(page)
            except Exception:
                # Close the page so nothing loads unguarded; the fetch fails.
                state["setup_failed"] = True
                try:
                    await page.close()
                except Exception:
                    pass
                raise
            document = Document(page)
            state["document"] = document
            page.on("response", document.on_response)
            state["guarded"] = True

        async def act(page):
            marks["navigated"] = loop.time()
            if not state["guarded"]:
                return  # an unguarded page; the fetch fails below
            document = state["document"]
            if not request.solve_challenge:
                # Detection only: the page is reported as challenged, never solved.
                from scrapling.engines.antibot.detect import detect
                from scrapling.engines.antibot.runner import read_signal

                last = document.last
                headers = {k.lower(): v for k, v in document.pairs(last)} if last is not None else {}
                signal = await read_signal(page, status=last.status if last is not None else None, headers=headers,
                                           deadline=time.monotonic() + max(0.5, min(5, remaining() - 1)))
                state["detected"] = detect(signal) is not None
            if request.wait == "networkidle":
                try:
                    await page.wait_for_load_state("networkidle", timeout=max(1, min(3000, int(remaining() * 1000) - 500)))
                except Exception:
                    pass
            await settle_navigation(page, document, remaining)
            # The selector and the extra settle time stay inside the budget; a
            # selector that never appears does not fail the fetch.
            if request.wait_selector:
                try:
                    await page.locator(request.wait_selector).first.wait_for(
                        state="attached", timeout=max(1, int(remaining() * 1000) - 1000))
                except Exception:
                    pass
            if request.wait_ms:
                await asyncio.sleep(max(0, min(request.wait_ms / 1000, remaining() - 1)))
            await settle_navigation(page, document, remaining)
            await document.settle(min(1, remaining() - 0.5))
            state["acted"] = True

        data = {"outcome": "failed", "error": "navigation_failed", "final_url": "", "status_code": 0, "headers": [],
                "set_cookie_names": [], "content_type": "", "html": "", "html_truncated": False, "cookies": [],
                "challenge": "none", "redirects": [], "started_at_ms": started_at_ms, "solver": "", "solver_cost_micro_usd": 0,
                "timings": {"context_ms": 0, "navigate_ms": 0, "settle_ms": 0, "challenge_ms": 0, "total_ms": 0}}
        no_retry = False
        challenge_ms = 0
        try:
            response = await asyncio.wait_for(session.fetch(
                request.url, proxy=self.proxy, timeout=request.timeout_ms, network_idle=False, solve_cloudflare=False,
                solve_antibot=request.solve_challenge, captcha_solver=self.solver if request.solver else None,
                load_dom=True, google_search=False, disable_resources=request.block_resources, wait=0,
                page_setup=setup, page_action=act), max(0.1, remaining()))
        except asyncio.TimeoutError:
            data.update(outcome="timeout", error="timeout")
            response = None
        except Exception as error:
            text = str(error)
            if "net::ERR_CERT_" in text or "net::ERR_SSL_" in text:
                data["error"] = "tls"
            elif "Timeout" in text and "exceeded" in text:
                data.update(outcome="timeout", error="timeout")
            elif "crash" in text.lower() or "has been closed" in text:
                data["error"] = "crashed"
            response = None
        if state["setup_failed"] or (response is not None and not (state["guarded"] and state["acted"])):
            data.update(outcome="failed", error="navigation_failed")
            response = None
        if response is not None:
            meta = getattr(response, "meta", None) or {}
            outcome = meta.get("antibot")
            challenge, no_retry, solver, cost = antibot_result(outcome, request.solve_challenge)
            if not request.solve_challenge and state["detected"]:
                challenge = "unsolved"
            if isinstance(outcome, dict) and outcome.get("layers"):
                try:
                    challenge_ms = max(0, round(float(outcome.get("elapsed_s") or 0) * 1000))
                except (TypeError, ValueError):
                    challenge_ms = 0
            document = state["document"]
            last = document.last if document else None
            pairs = document.pairs(last) if last is not None else list(response.headers.items())
            headers, names = header_pairs(pairs)
            content_type = next((v for k, v in headers if k == "content-type"), "")
            html = ""
            kind = content_type.split(";", 1)[0].strip().lower()
            if kind in ("text/html", "application/xhtml+xml"):
                html = (response.body or b"").decode("utf-8", "replace")
            html, truncated = cap_html(html)
            redirects = []
            for item in (document.responses if document else []):
                if 300 <= item.status < 400 and len(redirects) < MAX_REDIRECTS:
                    redirects.append({"url": item.url, "status_code": item.status})
            cookies = []
            for c in response.cookies or ():
                cookies.append({"name": c.get("name", ""), "value": c.get("value", ""), "domain": c.get("domain", ""),
                                "path": c.get("path", "/"), "expires": c.get("expires", -1), "secure": bool(c.get("secure")),
                                "http_only": bool(c.get("httpOnly"))})
            data.update(outcome="ok", error="", final_url=response.url, status_code=last.status if last is not None else response.status,
                        headers=headers, set_cookie_names=names, content_type=content_type[:512], html=html,
                        html_truncated=truncated, cookies=cookies, challenge=challenge, redirects=redirects,
                        solver=solver, solver_cost_micro_usd=cost)
        timings = data["timings"]
        if marks["context"]:
            timings["context_ms"] = round((marks["context"] - begin) * 1000)
            if marks["navigated"]:
                timings["navigate_ms"] = max(0, round((marks["navigated"] - marks["context"]) * 1000) - challenge_ms)
                timings["settle_ms"] = max(0, round((loop.time() - marks["navigated"]) * 1000))
        timings["challenge_ms"] = challenge_ms
        return {"data": data, "no_retry": no_retry}


# ---------------------------------------------------------------- server


def encode(status, body):
    raw = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8", "replace")
    reason = {200: "OK", 400: "Bad Request", 401: "Unauthorized", 404: "Not Found", 405: "Method Not Allowed",
              413: "Payload Too Large", 500: "Internal Server Error"}.get(status, "Error")
    head = f"HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {len(raw)}\r\nConnection: close\r\n\r\n"
    return head.encode("ascii") + raw


class Server:
    def __init__(self, bearer, fetcher, version, max_pages):
        self.bearer = ("Bearer " + bearer).encode()
        self.fetcher = fetcher
        self.version = version
        self.max_pages = max_pages
        # Provider names only, so the node can check what the helper built.
        self.solvers = list(fetcher.solver.providers) if getattr(fetcher, "solver", None) is not None else []

    async def handle(self, reader, writer):
        try:
            status, body = await self.route(reader)
        except Exception:
            status, body = 400, {"error": {"code": "invalid_request"}}
        try:
            writer.write(encode(status, body))
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    async def route(self, reader):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
        except (asyncio.LimitOverrunError, asyncio.IncompleteReadError, asyncio.TimeoutError):
            return 400, {"error": {"code": "invalid_request"}}
        lines = head.decode("latin-1").split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) != 3 or parts[2] != "HTTP/1.1":
            return 400, {"error": {"code": "invalid_request"}}
        method, target = parts[0], parts[1]
        headers = {}
        for line in lines[1:]:
            if line:
                name, _, value = line.partition(":")
                headers[name.strip().lower()] = value.strip()
        if not hmac.compare_digest(headers.get("authorization", "").encode("latin-1"), self.bearer):
            return 401, {"error": {"code": "unauthorized"}}
        if "transfer-encoding" in headers:
            return 400, {"error": {"code": "invalid_request"}}
        length = headers.get("content-length", "0")
        if not length.isdigit() or int(length) > MAX_REQUEST_BODY:
            return 413, {"error": {"code": "too_large"}}
        body = await asyncio.wait_for(reader.readexactly(int(length)), 10) if int(length) else b""
        if target == "/v1/ready" and method == "GET":
            return 200, {"data": {"status": "ready"}}
        if target == "/v1/capabilities" and method == "GET":
            return 200, {"data": {"web_browser": 1, "engine": ENGINE, "browser_version": self.version,
                                  "max_pages": self.max_pages, "solvers": self.solvers}}
        if target == "/v1/fetch":
            if method != "POST":
                return 405, {"error": {"code": "method_not_allowed"}}
            if headers.get("content-type", "").split(";")[0].strip() != "application/json":
                return 400, {"error": {"code": "invalid_request"}}
            try:
                request = Request(json.loads(body))
            except (ValueError, UnicodeDecodeError):
                return 400, {"error": {"code": "invalid_request"}}
            result = await self.fetcher.fetch(request)
            return 200, {"data": result["data"]}
        return 404, {"error": {"code": "not_found"}}


def watch_stdin(loop, stop):
    """EOF on stdin is the node's graceful stop."""
    try:
        while sys.stdin.buffer.read(4096):
            pass
    except Exception:
        pass
    loop.call_soon_threadsafe(stop.set)


async def serve():
    env = os.environ
    bearer = env.pop("WEB_HELPER_BEARER", "")  # never inherited by the driver or the browser
    solver_config = env.pop("WEB_SOLVER_CONFIG", "")  # likewise
    capacity = int(env["WEB_MAX_PAGES"])
    if len(bearer) != 64 or not 1 <= capacity <= 4:
        raise SystemExit(2)
    try:
        solver = solver_router(solver_config)
    except Exception:
        raise SystemExit(2) from None
    del solver_config
    # The node reads the port this helper binds from the first stdout line.
    # Keep a private copy of stdout for it, and send everything else that
    # writes to stdout (the driver, the browser) to stderr.
    report = os.fdopen(os.dup(1), "w", encoding="ascii")
    os.dup2(2, 1)
    # The profile lives under TMPDIR, which the node wipes before every start.
    profile = tempfile.mkdtemp(prefix=PROFILE_PREFIX)
    try:
        seed_profile(profile)
        session = new_session(env["WEB_BROWSER_EXECUTABLE"], env["WEB_USER_AGENT"], env["WEB_EGRESS_PROXY"],
                              env["WEB_DENY_PROXY"], capacity, profile)
        try:
            await session.start()
        except Exception as error:
            raise LaunchError(launch_reason(error))
        await run_session(session, report, bearer, env, capacity, solver)
    finally:
        report.close()  # if the browser never started: the node reads the marker after EOF
        shutil.rmtree(profile, ignore_errors=True)


async def run_session(session, report, bearer, env, capacity, solver=None):
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    threading.Thread(target=watch_stdin, args=(loop, stop), daemon=True).start()
    server = Server(bearer, Fetcher(session, env["WEB_EGRESS_PROXY"], capacity, solver), env["WEB_BROWSER_VERSION"], capacity)
    listener = await asyncio.start_server(server.handle, "127.0.0.1", 0, limit=MAX_REQUEST_HEAD)
    report.write(PORT_PREFIX + str(listener.sockets[0].getsockname()[1]) + "\n")
    report.close()
    try:
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), 1)
            except asyncio.TimeoutError:
                if not session.browser or not session.browser.is_connected():
                    break  # the node restarts a helper whose browser died
    finally:
        listener.close()
        try:
            await asyncio.wait_for(session.close(), 5)
        except Exception:
            pass


def main(argv):
    if argv == ["--self-check"]:
        self_check()
        return 0
    if argv:
        return 2
    if hasattr(os, "nice"):
        os.nice(10)  # children inherit it
    try:
        asyncio.run(serve())
    except LaunchError as error:
        sys.stderr.write("SCARLETT_WEB_BROWSER_ERROR=" + error.reason + "\n")
        sys.stderr.flush()
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
