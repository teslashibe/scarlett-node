"""Scarlett node web browser helper.

The node (internal/webruntime) starts this module inside its bundled Python
with an allowlisted environment, then talks to it over loopback HTTP with a
bearer. It renders one page per request in a fresh browser context through
Scrapling's AsyncStealthySession and Chrome for Testing. Every per-job context
uses the node's filtering egress proxy; the browser's own background traffic
goes to the node's deny listener.

It never logs URLs, headers, cookies or page content. Its only stderr line of
its own is SCARLETT_WEB_BROWSER_ERROR=<reason> when the browser cannot start.
Standard library plus Scrapling 0.4.15 only.
"""

import asyncio
import hmac
import json
import logging
import os
import re
import sys
import threading
import time
from urllib.parse import urlsplit

SCRAPLING_VERSION = "0.4.15"
PORT_PREFIX = "SCARLETT_WEB_HELPER_PORT="
ENGINE = "scrapling/" + SCRAPLING_VERSION
MAX_REQUEST_BODY = 65536
MAX_REQUEST_HEAD = 16384
HTML_CAP = 10485760
MAX_HEADERS = 128
MAX_HEADER_BYTES = 65536
MAX_SET_COOKIE_NAMES = 50
MAX_REDIRECTS = 20

# Patchright 1.63.0 chromiumSwitches, in order. Patchright appends these two
# switches itself; they are replaced by one merged pair (ignore_default_args).
PW_DISABLED = [
    "AvoidUnnecessaryBeforeUnloadCheckSync", "DestroyProfileOnBrowserClose", "DialMediaRouteProvider",
    "GlobalMediaControls", "HttpsUpgrades", "LensOverlay", "MediaRouter", "PaintHolding", "ThirdPartyStoragePartitioning",
    "BlockOriginHeaderModificationOnRedirect", "Translate", "AutoDeElevate", "OptimizationHints", "msForceBrowserSignIn",
    "msEdgeUpdateLaunchServicesPreferredVersion",
]
PW_DISABLE = "--disable-features=" + ",".join(PW_DISABLED)
PW_ENABLE = "--enable-features=CDPScreenshotNewSurface"
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
IGNORE_DEFAULT_ARGS = ["--enable-automation", "--disable-popup-blocking", "--disable-default-apps",
                       "--disable-extensions", PW_DISABLE, PW_ENABLE]

# Cloudflare: the solver runs only on an interstitial, never because a solved
# page still embeds the Turnstile api.js script.
CF_INTERSTITIAL = ("non-interactive", "managed", "interactive")
# Other vendors: wait for the marker to leave or a new main-frame document.
# The Kasada SDK loads on served pages too, so its markers count only on an
# error status.
VENDOR_MARKERS = ("sec-if-cpt-container", "px-captcha", "pardon our interruption", "_incapsula_resource")
KASADA_MARKERS = ("kpsdk", "/ips.js")
DATADOME_MARKERS = ("captcha-delivery.com", "var dd={")
TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9a-z-]{1,64}$")
SELECTOR = re.compile(r"^[\x20-\x7e]{1,256}$")

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


def browser_args(base):
    """The launch argv: Scrapling's set with its feature switches replaced by
    one merged pair, the WebRTC policy with its value, and ours."""
    args = [a for a in base if not a.startswith(("--disable-features=", "--enable-features=",
                                                  "--webrtc-ip-handling-policy", "--force-webrtc-ip-handling-policy"))]
    return args + ["--disable-features=" + ",".join(DISABLED), "--enable-features=" + ",".join(ENABLED)] + \
        WEBRTC_POLICY + EXTRA_ARGS


def new_session(executable, user_agent, proxy, deny_proxy, max_pages):
    """Builds the session exactly as contract C.6 says, without starting it."""
    from scrapling.fetchers import AsyncStealthySession
    from scrapling.engines.toolbelt.proxy_rotation import ProxyRotator

    session = AsyncStealthySession(
        headless=True, executable_path=executable, useragent=user_agent, locale="en-US", google_search=False,
        retries=1, block_webrtc=True, hide_canvas=False, allow_webgl=True, max_pages=max_pages, timeout=30000,
        # Launch mode (chromium.launch) with a fresh context per fetch.
        proxy_rotator=ProxyRotator([proxy]),
        additional_args={"permissions": [], "accept_downloads": False, "service_workers": "allow",
                         "ignore_https_errors": False})
    # Never extra_flags: Scrapling 0.4.15 then drops its default and stealth
    # args and both WebRTC switches. Edit the launch options instead.
    options = session._browser_options
    options["chromium_sandbox"] = True
    options["proxy"] = {"server": deny_proxy}
    options["args"] = browser_args(options["args"])
    # Patchright filters user args through this list too, so it must not
    # name --disable-component-update.
    options["ignore_default_args"] = list(IGNORE_DEFAULT_ARGS)
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
    if any(a == "--no-sandbox" or a == "--force-webrtc-ip-handling-policy" for a in args):
        problems.append("forbidden-arg")
    if options.get("ignore_default_args") != IGNORE_DEFAULT_ARGS or "--disable-component-update" in options.get("ignore_default_args", []):
        problems.append("ignore_default_args")
    if options.get("chromium_sandbox") is not True:
        problems.append("sandbox")
    if not isinstance(options.get("proxy"), dict) or not options["proxy"].get("server"):
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
    return problems


def self_check():
    import curl_cffi
    import lxml.etree
    import patchright
    import playwright
    import scrapling
    from importlib.metadata import version

    from scrapling.fetchers import AsyncStealthySession

    assert scrapling.__version__ == SCRAPLING_VERSION, "scrapling version"
    for name in ("_detect_cloudflare", "_cloudflare_solver"):
        assert callable(getattr(AsyncStealthySession, name, None)), "scrapling internal " + name
    # Any existing absolute file stands in for the browser; nothing starts.
    session = new_session(sys.executable, "Mozilla/5.0", "http://127.0.0.1:9", "http://127.0.0.1:9", 2)
    assert isinstance(getattr(session, "_browser_options", None), dict), "scrapling internal _browser_options"
    problems = option_problems(session, 2)
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
                                                     "block_resources", "solve_challenge"}:
            raise ValueError("fields")
        self.url = raw.get("url")
        self.wait = raw.get("wait", "networkidle")
        self.wait_ms = raw.get("wait_ms", 0)
        self.wait_selector = raw.get("wait_selector", "") or ""
        self.timeout_ms = raw.get("timeout_ms", 30000)
        self.block_resources = raw.get("block_resources", False)
        self.solve_challenge = raw.get("solve_challenge", True)
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
        if type(self.block_resources) is not bool or type(self.solve_challenge) is not bool:
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


async def page_text(page):
    try:
        return await page.content()
    except Exception:
        return ""


def cf_cleared(html):
    return "cType: '" not in html and "<title>just a moment" not in html.lower()


# --- DataDome device check. The wait logic is ported from Averyy/wafer
# wafer/browser/_datadome.py (Apache-2.0; see NOTICE.md): wait for the
# datadome cookie to change and the captcha-delivery iframe to leave, click a
# shown confirm button once, stop on a blocked visitor (t=bv), and never call
# a check that is still pending a success.


def dd_markers(html):
    low = html.lower()
    return any(m in low for m in DATADOME_MARKERS)


def dd_hard_block(url, html):
    low = html.replace(" ", "").replace('"', "'")
    return "t=bv" in url or "'t':'bv'" in low


def dd_frame_url(url):
    """DataDome's challenge frame: https on captcha-delivery.com or a subdomain
    of it. Only such a frame is ever clicked, so a page cannot earn a trusted
    click by naming the host in its own frame's URL."""
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
    except ValueError:
        return False
    return parts.scheme == "https" and (host == "captcha-delivery.com" or host.endswith(".captcha-delivery.com"))


def dd_frame(page):
    try:
        for frame in page.frames:
            if dd_frame_url(frame.url):
                return frame
    except Exception:
        pass
    return None


def dd_cookie(cookies):
    for cookie in cookies:
        if cookie.get("name") == "datadome":
            return cookie.get("value")
    return None


async def dd_click_confirm(page, frame):
    try:
        button = frame.locator("button.captcha_display_button_submit").first
        if not await button.is_visible(timeout=1000):
            return False
        box = await button.bounding_box(timeout=2000)
        if not box:
            return False
        x, y = box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
        await page.mouse.move(x - 40, y - 25, steps=8)
        await page.mouse.move(x, y, steps=12)
        await asyncio.sleep(0.2)
        await page.mouse.click(x, y, delay=90)
        return True
    except Exception:
        return False


async def dd_frame_blocked(frame):
    try:
        text = (await frame.locator("[data-dd-captcha-human-title]").first.text_content(timeout=500) or "").lower()
        return "restricted" in text or "blocked" in text
    except Exception:
        return False


async def wait_for_datadome(page, document, deadline):
    """'solved'; 'unsolved' (pending at the deadline, retry allowed); or
    'stop': a blocked visitor (t=bv), a restricted or blocked device, or an
    interactive challenge (slider, audio). Retrying those never helps, and
    DataDome rejects CDP-dispatched input on them even with a right answer."""
    loop = asyncio.get_running_loop()
    html = await page_text(page)
    if dd_hard_block(page.url, html):
        return "stop"
    start = loop.time()
    initial = dd_cookie(await page.context.cookies())
    documents = len(document.responses)
    seen = None
    confirmed = False
    while loop.time() < deadline:
        if "t=bv" in page.url:
            return "stop"
        cookie = dd_cookie(await page.context.cookies())
        if cookie and cookie != initial:
            # A new cookie is a clearance only if the challenge iframe leaves
            # and the page is no longer a challenge; otherwise it was a
            # rejection and the next attempt's cookie.
            settle = min(loop.time() + 10, deadline)
            while loop.time() < settle:
                if dd_frame(page) is None:
                    html = await page_text(page)
                    if not dd_markers(html) and not dd_hard_block(page.url, html):
                        return "solved"
                await asyncio.sleep(0.5)
            initial, confirmed = cookie, False
            continue
        frame = dd_frame(page)
        if frame is not None:
            seen = seen or loop.time()
            if not confirmed and await dd_click_confirm(page, frame):
                confirmed = True
                await asyncio.sleep(2)
                continue
            # The device check runs on its own; past 5 s an interactive or
            # blocked frame will not resolve.
            if loop.time() - seen > 5 and ("/captcha/" in frame.url or await dd_frame_blocked(frame)):
                return "stop"
        elif len(document.responses) > documents or seen is not None or loop.time() - start > 8:
            html = await page_text(page)
            if dd_hard_block(page.url, html):
                return "stop"
            if not dd_markers(html):
                return "solved"
            if seen is None and loop.time() - start > 8:
                return "unsolved"
        await asyncio.sleep(0.5)
    return "unsolved"


async def wait_for_vendor(page, document, markers, deadline):
    loop = asyncio.get_running_loop()
    documents = len(document.responses)
    while loop.time() < deadline:
        await asyncio.sleep(0.5)
        if len(document.responses) > documents:
            return True
        low = (await page_text(page)).lower()
        if not any(m in low for m in markers):
            return True
    return False


class Fetcher:
    def __init__(self, session, proxy, max_pages):
        self.session = session
        self.proxy = proxy
        self.slots = asyncio.Semaphore(max_pages)

    async def fetch(self, request):
        async with self.slots:
            loop = asyncio.get_running_loop()
            started = loop.time()
            deadline = started + request.timeout_ms / 1000
            result = await self._once(request, deadline)
            if result["data"]["challenge"] == "unsolved" and not result["no_retry"] and deadline - loop.time() >= 15:
                result = await self._once(request, deadline)
            result["data"]["timings"]["total_ms"] = round((loop.time() - started) * 1000)
            return result

    async def _once(self, request, deadline):
        loop = asyncio.get_running_loop()
        started_at_ms = int(time.time() * 1000)
        begin = loop.time()
        marks = {"context": None, "navigated": None, "challenge_ms": 0}
        state = {"challenge": "none", "no_retry": False, "document": None}
        session = self.session

        def remaining():
            return deadline - loop.time()

        async def setup(page):
            marks["context"] = loop.time()
            document = Document(page)
            state["document"] = document
            page.on("response", document.on_response)

        async def act(page):
            marks["navigated"] = loop.time()
            document = state["document"]
            if request.wait == "networkidle":
                try:
                    await page.wait_for_load_state("networkidle", timeout=max(1, min(3000, int(remaining() * 1000) - 500)))
                except Exception:
                    pass
            await settle_navigation(page, document, remaining)
            challenge_start = loop.time()
            triggered = False
            html = await page_text(page)
            kind = session._detect_cloudflare(html)
            if kind in CF_INTERSTITIAL or (kind == "embedded" and document.last_header("cf-mitigated").lower() == "challenge"):
                triggered = True
                if request.solve_challenge:
                    # The solver's own waits use the page default timeout (the
                    # whole budget); its network-idle wait after the click never
                    # ends on pages with analytics, so bound each wait to 5 s.
                    page.set_default_timeout(5000)
                    try:
                        await asyncio.wait_for(session._cloudflare_solver(page), max(0.1, min(25, remaining() - 1)))
                    except Exception:
                        pass  # a solver that runs out of time leaves the page unsolved
                    page.set_default_timeout(max(1000, int(remaining() * 1000)))
                    await settle_navigation(page, document, remaining)
                    html = await page_text(page)
                if not cf_cleared(html):
                    state["challenge"] = "unsolved"
            elif any(document.header(r, "cf-mitigated").lower() == "challenge" for r in document.responses[:-1]):
                triggered = True  # an interstitial that cleared itself while the page loaded
            if dd_markers(html) or dd_frame(page) is not None:
                triggered = True
                verdict = await wait_for_datadome(page, document, loop.time() + max(0, min(15, remaining() - 1)))
                if verdict != "solved":
                    state["challenge"] = "unsolved"
                    state["no_retry"] = verdict == "stop"
                await settle_navigation(page, document, remaining)
                html = await page_text(page)
            low = html.lower()
            status = 0
            if document.last is not None:
                status = document.last.status
            markers = [m for m in VENDOR_MARKERS if m in low] + \
                ([m for m in KASADA_MARKERS if m in low] if status >= 400 else [])
            if markers:
                triggered = True
                if not await wait_for_vendor(page, document, markers, loop.time() + max(0, min(15, remaining() - 1))):
                    state["challenge"] = "unsolved"
                await settle_navigation(page, document, remaining)
            if triggered and state["challenge"] != "unsolved":
                state["challenge"] = "solved"
            marks["challenge_ms"] = round((loop.time() - challenge_start) * 1000) if triggered else 0
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

        data = {"outcome": "failed", "error": "navigation_failed", "final_url": "", "status_code": 0, "headers": [],
                "set_cookie_names": [], "content_type": "", "html": "", "html_truncated": False, "cookies": [],
                "challenge": "none", "redirects": [], "started_at_ms": started_at_ms,
                "timings": {"context_ms": 0, "navigate_ms": 0, "settle_ms": 0, "challenge_ms": 0, "total_ms": 0}}
        try:
            response = await asyncio.wait_for(session.fetch(
                request.url, proxy=self.proxy, timeout=request.timeout_ms, network_idle=False, solve_cloudflare=False,
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
        if response is not None:
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
                        html_truncated=truncated, cookies=cookies, challenge=state["challenge"], redirects=redirects)
        timings = data["timings"]
        if marks["context"]:
            timings["context_ms"] = round((marks["context"] - begin) * 1000)
            if marks["navigated"]:
                timings["navigate_ms"] = round((marks["navigated"] - marks["context"]) * 1000)
                timings["settle_ms"] = max(0, round((loop.time() - marks["navigated"]) * 1000) - marks["challenge_ms"])
        timings["challenge_ms"] = marks["challenge_ms"]
        return {"data": data, "no_retry": state["no_retry"]}


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
                                  "max_pages": self.max_pages}}
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
    capacity = int(env["WEB_MAX_PAGES"])
    if len(bearer) != 64 or not 1 <= capacity <= 4:
        raise SystemExit(2)
    # The node reads the port this helper binds from the first stdout line.
    # Keep a private copy of stdout for it, and send everything else that
    # writes to stdout (the driver, the browser) to stderr.
    report = os.fdopen(os.dup(1), "w", encoding="ascii")
    os.dup2(2, 1)
    session = new_session(env["WEB_BROWSER_EXECUTABLE"], env["WEB_USER_AGENT"], env["WEB_EGRESS_PROXY"],
                          env["WEB_DENY_PROXY"], capacity)
    try:
        await session.start()
    except Exception as error:
        raise LaunchError(launch_reason(error))
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    threading.Thread(target=watch_stdin, args=(loop, stop), daemon=True).start()
    server = Server(bearer, Fetcher(session, env["WEB_EGRESS_PROXY"], capacity), env["WEB_BROWSER_VERSION"], capacity)
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
