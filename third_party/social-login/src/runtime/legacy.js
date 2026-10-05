// Social login sidecar (HTTP service).
//
// Some platforms (Instagram/Facebook Bloks, X's new /i/jf onboarding flow)
// gate login behind browser-only JS challenges that are impractical to
// reproduce in a pure-Go client. This service drives the real web login in a
// headless Chromium and returns the resulting session cookies, which the Go
// MCP clients then reuse for all subsequent API calls. It mirrors the recaptcha
// sidecar pattern: a small, stateless HTTP wrapper around a browser action.
//
// API:
//   GET  /health                      -> 200 "ok"
//   GET  /platforms                   -> 200 { platforms: ["instagram", ...] }
//   POST /login { platform, username, password, totpSecret?, verificationCode?, proxyUrl?, profileKey? }
//        -> 200 { ok, finalUrl, cookies: {name: value}, session: {...} }
//        -> 4xx/5xx { error, hints? }
//
// LinkedIn PIN challenges: the first /login that hits verification_code_required
// parks the live Chromium page for a few minutes. The follow-up /login with
// verificationCode resumes that page (no password re-submit → no second email).
//
// platform: "instagram" | "facebook" | "linkedin" | "x" | "tiktok" | "reddit"
//
// Env: PORT (default 8090), CAP_HEADLESS (default true).

import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFile } from "node:child_process";
import { pathToFileURL } from "node:url";
import process from "node:process";
import { promisify } from "node:util";
import os from "node:os";
import { chromium } from "playwright";
import { currentLoginBudget, credentialSubmission, loginSleep } from "./login-budget.js";

const PORT = parseInt(process.env.PORT || "8090", 10);
const HEADLESS = String(process.env.CAP_HEADLESS || "true") !== "false";
const BROWSER_CHANNEL = (process.env.CAP_BROWSER_CHANNEL || "").trim();
const BROWSER_EXECUTABLE = (process.env.CAP_BROWSER_EXECUTABLE_PATH || "").trim();
const envInt = (name, fallback, min = 1) =>
  Math.max(min, parseInt(process.env[name] || String(fallback), 10) || fallback);
const MAX_SESSIONS = envInt("SOCIAL_LOGIN_MAX_CONCURRENCY", 4);
const MAX_QUEUE = envInt("SOCIAL_LOGIN_QUEUE_SIZE", 16, 0);
const QUEUE_TIMEOUT_MS = envInt("SOCIAL_LOGIN_QUEUE_TIMEOUT_MS", 30000);
const SESSION_CLOSE_TIMEOUT_MS = envInt("CAP_SESSION_CLOSE_TIMEOUT_MS", 10000);
const SHUTDOWN_GRACE_MS = envInt("CAP_SHUTDOWN_GRACE_MS", 30000);
const MAX_PROCESSES = envInt("CAP_MAX_PROCESSES", 180);
const CHALLENGE_HOLD_TTL_MS = envInt("CAP_CHALLENGE_HOLD_TTL_MS", 10 * 60 * 1000);
const execFileAsync = promisify(execFile);
let accepting = true;
let shuttingDown = false;
let draining = false;
let activeRequests = 0;
let drainPromise = null;
let activeAdmissions = 0;
const admissionQueue = [];
// Versioned service holds retain the same capacity charge while awaiting a code.
const serviceHolds = new Set();
const trackedSessions = new Set();

function telemetry(event, data = {}) {
  console.log("social-login", JSON.stringify({
    event,
    activeSessions: trackedSessions.size,
    heldSessions: challengeHolds.size,
    activeAdmissions,
    queuedSessions: admissionQueue.length,
    ...data,
  }));
}

class AdmissionError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "AdmissionError";
    this.code = code;
    this.statusCode = code === "profile_busy" ? 409 : (code === "queue_full" || code === "queue_timeout" ? 429 : 503);
  }
}

function dispatchAdmissions() {
  while (accepting && activeAdmissions + challengeHolds.size + serviceHolds.size < MAX_SESSIONS && admissionQueue.length) {
    const item = admissionQueue.shift();
    clearTimeout(item.timer);
    if (item.cancelled()) {
      item.reject(new AdmissionError("request_cancelled", "request cancelled while queued"));
      continue;
    }
    activeAdmissions++;
    item.resolve(releaseAdmission);
  }
}

function releaseAdmission() {
  activeAdmissions = Math.max(0, activeAdmissions - 1);
  dispatchAdmissions();
}

function acquireAdmission(cancelled = () => false, signal) {
  if (!accepting) return Promise.reject(new AdmissionError("shutting_down", "service is shutting down"));
  if (activeAdmissions + challengeHolds.size + serviceHolds.size < MAX_SESSIONS) {
    activeAdmissions++;
    return Promise.resolve(releaseAdmission);
  }
  if (admissionQueue.length >= MAX_QUEUE) {
    telemetry("admission_rejected", { reason: "queue_full" });
    return Promise.reject(new AdmissionError("queue_full", "browser session queue is full"));
  }
  return new Promise((resolve, reject) => {
    const item = { resolve, reject, cancelled, timer: null };
    item.timer = setTimeout(() => {
      const i = admissionQueue.indexOf(item);
      if (i >= 0) admissionQueue.splice(i, 1);
      telemetry("admission_rejected", { reason: "queue_timeout" });
      reject(new AdmissionError("queue_timeout", "browser session queue wait timed out"));
    }, QUEUE_TIMEOUT_MS);
    admissionQueue.push(item);
    signal?.addEventListener("abort", () => {
      const i = admissionQueue.indexOf(item);
      if (i < 0) return;
      admissionQueue.splice(i, 1);
      clearTimeout(item.timer);
      reject(new AdmissionError("request_cancelled", "request cancelled while queued"));
    }, { once: true });
    telemetry("admission_queued");
  });
}

// A verification resume reuses a browser already counted in challengeHolds.
// Claim that exact hold before considering general capacity; callers without
// the matching platform/profile key still use the normal FIFO admission path.
function acquireChallengeAdmission(platform, profileKey, verificationCode, cancelled = () => false, signal, explicitHold) {
  if (explicitHold) {
    if (!serviceHolds.delete(explicitHold)) throw new AdmissionError("challenge_not_found", "browser hold is missing or expired");
    activeAdmissions++;
    return Promise.resolve({ held: explicitHold, release: releaseAdmission });
  }
  const held = verificationCode ? takeChallengeHold(platform, profileKey) : null;
  if (held) {
    // Transfer the capacity charge from the parked-hold bucket to the active
    // request bucket. The request's finally block releases it on every exit.
    activeAdmissions++;
    return Promise.resolve({ held, release: releaseAdmission });
  }
  return acquireAdmission(cancelled, signal).then((release) => ({ held: null, release }));
}
// CAP_PROFILE_BASE enables PER-USER persistent browser profiles. When set, each
// login runs in its own Chrome user-data-dir under this base, keyed by the
// caller's profileKey (the smore user id). This is what makes X's Castle
// anti-bot trust the login — a fresh ephemeral context looks like a bot and is
// throttled ("temporarily limited"), whereas a warmed, returning per-user
// profile passes — and it keeps every user's cookies + device identity
// isolated from each other. Unset (local dev) → ephemeral contexts, unchanged.
const PROFILE_BASE = (process.env.CAP_PROFILE_BASE || "").trim();
// CAP_EXTRA_CHROME_ARGS appends comma-separated flags to every Chrome launch.
// Lets us tune prod browser behavior and reproduce prod's GPU-less rendering
// locally (--use-gl=swiftshader,--disable-gpu) without a code change.
const EXTRA_CHROME_ARGS = (process.env.CAP_EXTRA_CHROME_ARGS || "")
  .split(",").map((s) => s.trim()).filter(Boolean);
// CAP_WEBGL_SPOOF gates the WebGL renderer string override. The string spoof is
// only safe when the renderer string would otherwise be a hard tell (SwiftShader)
// AND the engine doesn't cross-check rendered pixels. When the browser renders
// via a genuine Mesa driver (llvmpipe) the string is already plausible and a
// spoof would create a string/pixel INCONSISTENCY — so disable it on that path.
// Default on to preserve prior behavior; set "false" for the Mesa-llvmpipe path.
const WEBGL_SPOOF = String(process.env.CAP_WEBGL_SPOOF ?? "true").toLowerCase() !== "false";
// CapSolver Chrome extension (bundled at /opt/capsolver-extension). Requires
// headed Chrome (CAP_HEADLESS=false) and RECAPTCHA_SOLVER_API_KEY — the same
// key Reddit cold-start already uses via the API CapSolver client.
const CAPSOLVER_EXTENSION_DIR = (process.env.CAPSOLVER_EXTENSION_DIR || "/opt/capsolver-extension").trim();
const CAPSOLVER_API_KEY = (process.env.RECAPTCHA_SOLVER_API_KEY || process.env.CAPSOLVER_API_KEY || "").trim();
const CAPSOLVER_EXTENSION_ENABLED =
  Boolean(CAPSOLVER_API_KEY) &&
  !HEADLESS &&
  fs.existsSync(path.join(CAPSOLVER_EXTENSION_DIR, "manifest.json"));
const CAPSOLVER_SOLVE_TIMEOUT_MS = Math.max(
  30000,
  parseInt(process.env.CAPSOLVER_SOLVE_TIMEOUT_MS || "90000", 10) || 90000,
);

// LinkedIn (and later peers) park the live checkpoint browser so PIN submit
// does not re-drive username/password — that minting a second email is the
// "submit pin → new pin → UI stall" loop. Holds are process-local + TTL-bound.
/** @type {Map<string, { context: any, page: any, close: () => Promise<void>, expiresAt: number, proxyUrl?: string }>} */
const challengeHolds = new Map();
const freshLoginFlights = new Map();
const linkedinQueryIDCache = new Map();
const LINKEDIN_QUERY_CACHE_MAX = 128;
const LINKEDIN_QUERY_POSITIVE_TTL_MS = 6 * 60 * 60 * 1000;
const LINKEDIN_QUERY_NEGATIVE_TTL_MS = 5 * 60 * 1000;
const LINKEDIN_QUERY_DISCOVERY_TIMEOUT_MS = 25000;
const LINKEDIN_QUERY_DISCOVERY_MAX_BYTES = 2 * 1024 * 1024;
const LINKEDIN_QUERY_DISCOVERY_MAX_BUNDLES = 8;

function challengeHoldKey(platform, profileKey) {
  return `${platform}:${sanitizeProfileKey(profileKey || "anon")}`;
}

function closeBounded(session, reason = "normal") {
  if (!session) return Promise.resolve();
  if (session.closePromise) return session.closePromise;
  session.closePromise = (async () => {
    let timer;
    try {
      await Promise.race([
        Promise.resolve().then(() => session.rawClose()),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error("browser_close_timeout")), SESSION_CLOSE_TIMEOUT_MS);
        }),
      ]);
      session.closed = true;
      trackedSessions.delete(session);
    } catch (error) {
      telemetry("session_cleanup_failed", { reason });
      currentLoginBudget()?.markIncomplete();
      try { session.browserProcess?.kill("SIGKILL"); } catch {}
      throw error;
    } finally {
      clearTimeout(timer);
    }
  })();
  return session.closePromise;
}

async function releaseChallengeHold(platform, profileKey, reason = "released") {
  const key = challengeHoldKey(platform, profileKey);
  const held = challengeHolds.get(key);
  if (!held) return;
  // Drop the map entry synchronously so capacity frees before any await,
  // and duplicate releases are no-ops (lifecycle double-cleanup tests).
  challengeHolds.delete(key);
  clearTimeout(held.timer);
  try {
    await Promise.race([
      Promise.resolve(held.close(reason)).catch(() => {}),
      new Promise((resolve) => setTimeout(resolve, SESSION_CLOSE_TIMEOUT_MS)),
    ]);
  } catch {}
  telemetry("challenge_hold_released", { reason });
  dispatchAdmissions();
}

function takeChallengeHold(platform, profileKey) {
  const key = challengeHoldKey(platform, profileKey);
  const held = challengeHolds.get(key);
  if (!held) return null;
  challengeHolds.delete(key);
  clearTimeout(held.timer);
  if (Date.now() > held.expiresAt) {
    Promise.resolve(held.close("expired")).catch(() => {});
    dispatchAdmissions();
    return null;
  }
  // A live hold remains capacity-consuming while its verification request
  // resumes it. Its eventual close/park transition dispatches queued work.
  return held;
}

async function parkChallengeHold(platform, profileKey, session, ttlMs = CHALLENGE_HOLD_TTL_MS) {
  const key = challengeHoldKey(platform, profileKey);
  const previous = challengeHolds.get(key);
  if (previous) {
    // Await prior close before registering the replacement (main LinkedIn tests).
    challengeHolds.delete(key);
    clearTimeout(previous.timer);
    try {
      await Promise.race([
        Promise.resolve(previous.close("replaced")).catch(() => {}),
        new Promise((resolve) => setTimeout(resolve, SESSION_CLOSE_TIMEOUT_MS)),
      ]);
    } catch {}
    dispatchAdmissions();
  }
  // No prior hold → register synchronously before the first await point so
  // un-awaited callers (lifecycle admission tests) still see capacity held.
  const held = {
    context: session.context,
    page: session.page,
    close: session.close,
    proxyUrl: session.proxyUrl,
    expiresAt: Date.now() + ttlMs,
    timer: null,
  };
  held.timer = setTimeout(() => {
    if (challengeHolds.get(key) !== held) return;
    void releaseChallengeHold(platform, profileKey, "challenge_ttl");
    telemetry("challenge_hold_expired");
  }, ttlMs);
  held.timer.unref?.();
  challengeHolds.set(key, held);
  telemetry("challenge_hold_parked", { ttlMs });
}
// Pinning navigator.userAgent only stays safe while it matches the REAL
// browser. With CAP_BROWSER_CHANNEL=chrome we drive actual Google Chrome, which
// emits sec-ch-ua client-hint headers for its true version that CANNOT be
// overridden from context.userAgent. When Chrome auto-updates (e.g. 138 → 149)
// a hard-pinned UA string drifts out of sync with those client hints, and X's
// Castle / similar bot engines flag the mismatch as automation — the login
// then 4xxs with "We've temporarily limited your login" at the username step.
// So: only override the UA for the bundled-Chromium fallback (no real channel),
// where Playwright would otherwise leak a "HeadlessChrome" token. With a real
// channel we leave the UA untouched so navigator.userAgent and sec-ch-ua agree
// and the version tracks Chrome automatically. See #444 follow-up (X detection).
const UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36";
const CONTEXT_OPTS = (BROWSER_CHANNEL || BROWSER_EXECUTABLE)
  ? { viewport: { width: 1280, height: 900 }, locale: "en-US" }
  : { userAgent: UA, viewport: { width: 1280, height: 900 }, locale: "en-US" };

function logLoginEvent(event, data = {}) {
  const safe = {
    event,
    platform: data.platform,
    profileKey: data.profileKey
      ? crypto.createHash("sha256").update(String(data.profileKey)).digest("hex").slice(0, 10)
      : undefined,
    proxy: Boolean(data.proxyUrl),
    ok: data.ok,
    status: data.status,
    finalUrl: data.finalUrl,
    failureType: data.failureType,
    rateLimited: data.rateLimited,
    captcha: data.captcha,
    hints: Array.isArray(data.hints) ? data.hints.slice(0, 8) : undefined,
    error: data.error,
    hasUserAgent: data.hasUserAgent,
    cookieNames: data.cookieNames,
  };
  console.log("social-login", JSON.stringify(Object.fromEntries(Object.entries(safe).filter(([, v]) => v !== undefined))));
}

function launchOptions(proxyUrl, { stealth = false, loadCapsolverExt = false } = {}) {
  const args = [];
  const ignoreDefaultArgs = [];
  // Docker/Linux runs as root and needs no-sandbox; local macOS Chrome does not.
  // The --no-sandbox flag is what triggers Chrome's visible "unsupported
  // command-line flag" infobar, which Reddit rejects — so strip it on macOS.
  if (process.platform === "linux" && process.env.CAP_NO_SANDBOX !== "false") {
    args.unshift("--no-sandbox");
  } else {
    // Playwright injects --no-sandbox by default even when we do not pass it.
    // On local macOS e2e this surfaces the warning bar, so explicitly strip it.
    ignoreDefaultArgs.push("--no-sandbox");
  }
  // Stealth recipes (X) need the automation signal hidden or X's anti-bot edge
  // blocks at the username step. Unlike --no-sandbox, --disable-blink-features
  // does NOT raise Chrome's unsupported-flag infobar, so it is safe alongside
  // the macOS Reddit path; it is gated per-recipe (not per-OS) to keep the
  // Reddit browser pristine. Also drop --enable-automation (the infobar +
  // navigator.webdriver source) Playwright adds by default.
  if (stealth && process.env.CAP_DISABLE_BLINK_FLAGS !== "false") {
    args.push("--disable-blink-features=AutomationControlled");
    ignoreDefaultArgs.push("--enable-automation");
  } else if (process.platform === "linux" && process.env.CAP_DISABLE_BLINK_FLAGS !== "false") {
    args.push("--disable-blink-features=AutomationControlled");
  }
  if (EXTRA_CHROME_ARGS.length) args.push(...EXTRA_CHROME_ARGS);
  // CapSolver MV3 extension auto-solves LinkedIn FunCaptcha / checkpoint
  // captchas. Do NOT load it for Reddit: Reddit uses Enterprise reCAPTCHA and
  // the extension's V3-click mode interferes with the warmed-profile path that
  // previously worked. Opt in per-recipe via loadCapsolverExt.
  if (CAPSOLVER_EXTENSION_ENABLED && loadCapsolverExt) {
    ignoreDefaultArgs.push("--disable-extensions");
    args.push(`--disable-extensions-except=${CAPSOLVER_EXTENSION_DIR}`);
    args.push(`--load-extension=${CAPSOLVER_EXTENSION_DIR}`);
  }
  return {
    headless: HEADLESS,
    ...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH && !BROWSER_CHANNEL
      ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH }
      : {}),
    ...(BROWSER_CHANNEL ? { channel: BROWSER_CHANNEL } : {}),
    ...(ignoreDefaultArgs.length ? { ignoreDefaultArgs } : {}),
    proxy: parseProxy(proxyUrl),
    args,
  };
}

function sanitizeProfileKey(key) {
  return String(key || "").replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 128);
}

// withProfileLock serializes logins that share a persistent profile. Chrome
// exclusively locks a user-data-dir, so two concurrent logins for the same
// user must queue rather than crash on the lock.
const profileChains = new Map();
const CHROME_SINGLETON_FILES = ["SingletonLock", "SingletonCookie", "SingletonSocket"];

function staleProfileLockError(err) {
  const message = String(err?.message || err || "");
  return (
    message.includes("SingletonLock") ||
    message.includes("ProcessSingleton") ||
    message.includes("profile appears to be in use") ||
    message.includes("user data directory is already in use")
  );
}

function clearStaleProfileLocks(dir) {
  const singletonLock = path.join(dir, "SingletonLock");
  try {
    const owner = fs.readlinkSync(singletonLock);
    const match = owner.match(/^(.*)-(\d+)$/);
    if (match?.[1] !== os.hostname()) {
      throw new AdmissionError("profile_busy", "browser profile is owned by another host");
    }
    if (match) {
      try {
        process.kill(Number(match[2]), 0);
        throw new AdmissionError("profile_busy", "browser profile is owned by a live process");
      } catch (err) {
        if (err?.code !== "ESRCH") throw err;
      }
    }
  } catch (err) {
    if (err?.code !== "ENOENT" && err?.code !== "EINVAL") throw err;
  }
  for (const name of CHROME_SINGLETON_FILES) {
    const lockPath = path.join(dir, name);
    try {
      fs.unlinkSync(lockPath);
    } catch (err) {
      if (err?.code !== "ENOENT") throw err;
    }
  }
}

async function launchPersistentContextWithRecovery(dir, launch) {
  try {
    return await launch();
  } catch (err) {
    if (!staleProfileLockError(err)) throw err;
    clearStaleProfileLocks(dir);
    return launch();
  }
}

function withProfileLock(profileKey, fn) {
  if (!profileKey || !PROFILE_BASE) return fn();
  const prev = profileChains.get(profileKey) || Promise.resolve();
  const next = prev.then(fn, fn);
  const settled = next.then(() => {}, () => {});
  profileChains.set(profileKey, settled);
  settled.finally(() => {
    if (profileChains.get(profileKey) === settled) profileChains.delete(profileKey);
  });
  return next;
}

// webglSpoofInit hides the SwiftShader WebGL fingerprint. GPU-less containers
// (prod runs headful Chrome under Xvfb with no GPU) fall back to software
// rendering, whose UNMASKED_VENDOR/RENDERER report "SwiftShader" — a hard
// datacenter/bot signal. X's Castle risk engine challenges it ("temporarily
// limited") even on a fresh real-GPU-less profile, while the SAME login on a
// real GPU passes (verified). We override the two WebGL debug params to a real
// GPU consistent with the platform's UA (Apple on macOS, Mesa Intel on Linux,
// Intel D3D on Windows) so the renderer string no longer screams software.
// Runs before page scripts via addInitScript. Applied only to stealth sessions
// (X); Reddit's reCAPTCHA is gated on profile trust, not this signal.
function webglSpoofInit() {
  const ua = navigator.userAgent || "";
  let vendor = "Google Inc. (Intel)";
  let renderer =
    "ANGLE (Intel, Mesa Intel(R) UHD Graphics (CML GT2), OpenGL 4.6 (Core Profile) Mesa 23.2.1)";
  if (/Macintosh|Mac OS X/.test(ua)) {
    vendor = "Google Inc. (Apple)";
    renderer = "ANGLE (Apple, ANGLE Metal Renderer: Apple M1 Pro, Unspecified Version)";
  } else if (/Windows/.test(ua)) {
    vendor = "Google Inc. (Intel)";
    renderer = "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)";
  }
  const patch = (proto) => {
    if (!proto || !proto.getParameter) return;
    const orig = proto.getParameter;
    proto.getParameter = function (p) {
      if (p === 37445) return vendor; // UNMASKED_VENDOR_WEBGL
      if (p === 37446) return renderer; // UNMASKED_RENDERER_WEBGL
      return orig.call(this, p);
    };
  };
  try { patch(window.WebGLRenderingContext && window.WebGLRenderingContext.prototype); } catch {}
  try { patch(window.WebGL2RenderingContext && window.WebGL2RenderingContext.prototype); } catch {}
}

// openLoginSession returns { context, page, close }. With a profileKey and
// PROFILE_BASE configured it launches a PERSISTENT per-user Chrome profile
// (warmed cookies + a stable device identity); otherwise it falls back to an
// ephemeral context. The webdriver flag is hidden in both cases; stealth
// sessions additionally mask the SwiftShader WebGL renderer.
async function openLoginSession({ proxyUrl, profileKey, stealth = false, loadCapsolverExt = false }) {
  const budget = currentLoginBudget();
  const options = () => ({
    ...launchOptions(proxyUrl, { stealth, loadCapsolverExt }),
    ...(BROWSER_EXECUTABLE ? { executablePath: BROWSER_EXECUTABLE } : {}),
    timeout: budget ? budget.timeout(30_000) : 30_000,
  });
  const launch = async (fn) => {
    budget?.use("browser");
    const browser = await fn();
    if (budget?.signal.aborted) {
      await browser.close();
      budget.check();
    }
    return browser;
  };
  let session;
  if (profileKey && PROFILE_BASE) {
    const dir = path.join(PROFILE_BASE, sanitizeProfileKey(profileKey));
    fs.mkdirSync(dir, { recursive: true });
    const context = await launchPersistentContextWithRecovery(dir, () =>
      launch(() => chromium.launchPersistentContext(dir, { ...options(), ...CONTEXT_OPTS })),
    );
    session = trackSession({ context, persistent: true, rawClose: () => context.close() });
  } else {
    const browser = await launch(() => chromium.launch(options()));
    session = trackSession({ persistent: false, rawClose: () => browser.close() });
    try { session.context = await browser.newContext(CONTEXT_OPTS); }
    catch (error) { await session.close(); throw error; }
  }
  try {
    budget?.check();
    const hideWebdriver = () => Object.defineProperty(navigator, "webdriver", { get: () => undefined });
    await session.context.addInitScript(hideWebdriver);
    if (stealth && WEBGL_SPOOF) await session.context.addInitScript(webglSpoofInit);
    session.page = session.context.pages()[0] || await session.context.newPage();
    budget?.check();
    return session;
  } catch (error) {
    await session.close();
    throw error;
  }
}

function trackSession(session) {
  session.closed = false;
  session.close = (reason) => closeBounded(session, reason);
  trackedSessions.add(session);
  currentLoginBudget()?.bind(() => session.close("cancelled"));
  telemetry("session_opened");
  return session;
}

function totpNow(secret) {
  if (!secret) return "";
  const b32 = secret.toUpperCase().replace(/\s+/g, "").replace(/=+$/, "");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of b32) {
    const idx = alphabet.indexOf(ch);
    if (idx >= 0) bits += idx.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  const key = Buffer.from(bytes);
  const buf = Buffer.alloc(8);
  buf.writeBigInt64BE(BigInt(Math.floor(Date.now() / 1000 / 30)));
  const hmac = crypto.createHmac("sha1", key).update(buf).digest();
  const off = hmac[hmac.length - 1] & 0xf;
  const code =
    ((hmac[off] & 0x7f) << 24) |
    ((hmac[off + 1] & 0xff) << 16) |
    ((hmac[off + 2] & 0xff) << 8) |
    (hmac[off + 3] & 0xff);
  return (code % 1000000).toString().padStart(6, "0");
}

// jwtSub extracts the "sub" claim from a JWT (e.g. Reddit's token_v2 cookie)
// without verifying the signature. Reddit issues a token_v2 for LOGGED-OUT
// sessions too, whose sub is "loid" (logged-out id); an authenticated user
// token carries the user id instead. Used to tell a real login from the
// anonymous app token. Returns "" when the value isn't a decodable JWT.
function jwtSub(jwt) {
  try {
    const part = String(jwt || "").split(".")[1];
    if (!part) return "";
    const json = Buffer.from(part.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    return JSON.parse(json).sub || "";
  } catch {
    return "";
  }
}

// isAuthenticatedRedditToken reports whether a token_v2 cookie value belongs to
// a LOGGED-IN user (vs Reddit's anonymous logged-out app token whose sub is
// "loid"). This is the single source of truth for "did the Reddit login
// actually authenticate" — used both by the live login wait loop and by tests.
function isAuthenticatedRedditToken(tokenV2) {
  const sub = jwtSub(tokenV2);
  return sub !== "" && sub !== "loid";
}

export { jwtSub, isAuthenticatedRedditToken };

function parseProxy(raw) {
  if (!raw) return undefined;
  const u = new URL(raw);
  return {
    server: `${u.protocol}//${u.hostname}:${u.port || (u.protocol === 'https:' ? '443' : u.protocol === 'socks5:' ? '1080' : '80')}`,
    username: decodeURIComponent(u.username || ""),
    password: decodeURIComponent(u.password || ""),
  };
}

async function fillFirst(page, selectors, value) {
  for (const sel of selectors) {
    const el = page.locator(sel).first();
    if (await el.count().catch(() => 0)) {
      try {
        await el.waitFor({ state: "visible", timeout: 10000 });
        await el.fill(value);
        return true;
      } catch {}
    }
  }
  return false;
}

// typeFirst enters a value with human-like per-character delays instead of an
// instant fill(). Some risk engines (Reddit's in particular) flag the
// zero-latency value injection that fill() produces as a bot and block the
// login ("An error occurred. Please ... try a different web browser"). Typing
// char-by-char clears that check. Verified e2e: instant fill is blocked, slow
// typing authenticates.
async function typeFirst(page, selectors, value) {
  for (const sel of selectors) {
    const el = page.locator(sel).first();
    if (await el.count().catch(() => 0)) {
      try {
        await el.waitFor({ state: "visible", timeout: 10000 });
        await el.click();
        for (const ch of String(value)) {
          await page.keyboard.type(ch, { delay: 55 + Math.random() * 95 });
        }
        return true;
      } catch {}
    }
  }
  return false;
}

async function clickByText(page, names, beforeSubmit = () => {}) {
  for (const name of names) {
    const btn = page.getByRole("button", { name }).first();
    if (await btn.count().catch(() => 0)) {
      beforeSubmit();
      try {
        await btn.click({ timeout: 8000 });
        return true;
      } catch { currentLoginBudget()?.check(); }
    }
  }
  return false;
}

const META = {
  instagram: {
    url: "https://www.instagram.com/accounts/login/",
    userSel: ['input[name="username"]', 'input[name="email"]'],
    passSel: ['input[name="password"]', 'input[name="pass"]'],
    submit: [/^log in$/i],
    successCookies: ["sessionid", "ds_user_id"],
    session: (g) => ({ sessionid: g("sessionid"), ds_user_id: g("ds_user_id"), csrftoken: g("csrftoken") }),
    hintRe: /incorrect|wasn|couldn|suspicious|unusual|try again|disabled|challenge|confirm/i,
  },
  facebook: {
    url: "https://www.facebook.com/login/",
    userSel: ['input[name="email"]', "#email"],
    passSel: ['input[name="pass"]', "#pass"],
    submit: [/^log in$/i, /^log into facebook$/i],
    successCookies: ["c_user", "xs"],
    session: (g) => ({ c_user: g("c_user"), xs: g("xs") }),
    hintRe: /incorrect|wrong|couldn|suspicious|unusual|try again|disabled|checkpoint|confirm/i,
  },
};

// codeEntryRe matches the email/SMS verification step Instagram/Facebook
// interpose from unfamiliar IPs (e.g. residential-proxy egress).
const codeEntryRe = /codeentry|two_factor|two-factor|checkpoint|challenge|confirmemail|security code|verification code|enter the code/i;

async function isCodeEntry(page) {
  if (codeEntryRe.test(page.url())) return true;
  const body = await page.locator("body").innerText().catch(() => "");
  return /enter the (\d|six)|confirmation code|security code|verification code|we sent|check your email/i.test(body);
}

async function submitCode(page, code) {
  const sels = [
    'input[name="verificationCode"]',
    'input[name="security_code"]',
    'input[name="confirmationCode"]',
    'input[autocomplete="one-time-code"]',
    'input[name="email"]', // IG codeentry reuses generic single field in some variants
    'input[type="tel"]',
    'input[type="text"]',
  ];
  if (!(await fillFirst(page, sels, code))) return false;
  if (!(await clickByText(page, [/^confirm$/i, /^continue$/i, /^submit$/i, /^next$/i, /^log in$/i]))) {
    const sub = page.locator('button[type="submit"], input[type="submit"]').first();
    if (await sub.count().catch(() => 0)) await sub.click({ timeout: 8000 }).catch(() => {});
    else await page.keyboard.press("Enter").catch(() => {});
  }
  return true;
}

async function loginMeta(platform, { username, password, verificationCode }, proxyUrl, profileKey) {
  const cfg = META[platform];
  const { context, page, close } = await openLoginSession({ proxyUrl, profileKey });
  try {
    await page.goto(cfg.url, { waitUntil: "domcontentloaded", timeout: 60000 });
    await page.waitForTimeout(2000);
    await clickByText(page, [/allow all cookies/i, /accept all/i, /only allow essential/i]);
    await page.waitForSelector(cfg.userSel.join(", "), { timeout: 30000 }).catch(() => {});
    if (!(await fillFirst(page, cfg.userSel, username))) throw new Error("username field not found");
    if (!(await fillFirst(page, cfg.passSel, password))) throw new Error("password field not found");
    if (!(await clickByText(page, cfg.submit, credentialSubmission))) {
      const sub = page.locator('button[type="submit"], input[type="submit"]').first();
      if (await sub.count().catch(() => 0)) { credentialSubmission(); await sub.click({ timeout: 8000 }).catch(() => {}); }
      else { credentialSubmission(); await page.keyboard.press("Enter").catch(() => {}); }
    }

    const has = async () => {
      const cks = await context.cookies();
      return cfg.successCookies.every((n) => cks.find((c) => c.name === n));
    };

    // Wait for either success cookies or a verification-code challenge.
    let ok = false;
    let challenge = false;
    const settle = Date.now() + 12000;
    while (Date.now() < settle) {
      if (await has()) { ok = true; break; }
      if (await isCodeEntry(page)) { challenge = true; break; }
      await page.waitForTimeout(1000);
    }

    // If Instagram/Facebook interposed an email/SMS code challenge, submit the
    // supplied code (read from the user's Gmail by the caller). Without a code
    // we can't proceed, so report it so the caller can collect one.
    if (!ok && challenge) {
      if (!verificationCode) {
        const cookies = await context.cookies();
        const body = await page.locator("body").innerText().catch(() => "");
        return {
          ok: false,
          challenge: true,
          finalUrl: page.url(),
          cookies: Object.fromEntries(cookies.map((c) => [c.name, c.value])),
          session: {},
          hints: ["verification_code_required"],
          challengeMethod: "email_sms_in_app",
          maskedDestination: extractMaskedDestination(body),
        };
      }
      await submitCode(page, verificationCode);
      const deadline = Date.now() + 25000;
      while (Date.now() < deadline) {
        if (await has()) { ok = true; break; }
        await page.waitForTimeout(1500);
      }
    } else if (!ok) {
      // No challenge detected yet; keep waiting for cookies a bit longer.
      const deadline = Date.now() + 23000;
      while (Date.now() < deadline) {
        if (await has()) { ok = true; break; }
        await page.waitForTimeout(1500);
      }
    }

    const cookies = await context.cookies();
    const map = Object.fromEntries(cookies.map((c) => [c.name, c.value]));
    const g = (n) => map[n] || null;
    let hints = [];
    if (!ok) {
      const body = await page.locator("body").innerText().catch(() => "");
      hints = body.split("\n").filter((l) => cfg.hintRe.test(l)).slice(0, 6);
      if ((await isCodeEntry(page)) && !hints.includes("verification_code_required")) hints.push("verification_code_required");
    }
    const finalBody = await page.locator("body").innerText().catch(() => "");
    return {
      ok,
      challenge: !ok && hints.includes("verification_code_required"),
      finalUrl: page.url(),
      cookies: map,
      session: cfg.session(g),
      hints,
      challengeMethod: hints.includes("verification_code_required") ? "email_sms_in_app" : "",
      maskedDestination: extractMaskedDestination(finalBody),
    };
  } finally {
    await close();
  }
}

// X's "temporarily limited your login" anti-automation throttle. Detected
// explicitly so the caller can tell the user to retry later instead of
// surfacing a generic credential failure.
const X_RATE_LIMIT_RE = /temporarily limited your login|try again later/i;
// X's new-device confirmation-code screen. Detected by on-screen copy so the
// challenge is recognized even when the input selector varies by flow variant.
const X_CODE_CHALLENGE_RE = /security code|sent you a code|enter the code|confirmation code|check your email|we sent|verification code/i;

function extractMaskedDestination(text) {
  const s = String(text || "").replace(/\s+/g, " ");
  const email = s.match(/[A-Za-z0-9._%+-]?\*{2,}[A-Za-z0-9._%+-]*@[A-Za-z0-9*.-]+\.[A-Za-z*]{2,}/);
  if (email) return email[0];
  const phone = s.match(/(?:\+\d{1,3}\s*)?(?:\*|x|X){2,}[\s-]?(?:\d{2,4})/);
  if (phone) return phone[0];
  return "";
}

// Only proxy-tunnel failures are safe reasons to rotate a sticky residential
// session. Target/UI timeouts, resets, captcha and JS challenges may happen on
// a healthy egress and must not burn a new sticky IP.
function isHardProxyTunnelError(value) {
  const msg = String(value || "").toLowerCase();
  return /err_tunnel_connection_failed|err_proxy_connection_failed|proxy connect|proxyconnect|tunneling socket could not be established|connect(?::|\s+)(?:502|503|504)\b/.test(msg);
}

function classifyFailure(out, status) {
  if (out?.rateLimited || status === 429) return "rate_limited";
  const hints = (out?.hints || []).join("\n").toLowerCase();
  const err = String(out?.error || "").toLowerCase();
  const finalUrl = String(out?.finalUrl || "").toLowerCase();
  if (out?.captcha || hints.includes("captcha_required")) return "captcha_required";
  if (hints.includes("verification_code_required")) return "verification_required";
  // Wrong/expired PIN copy often contains "invalid" / "isn't valid" — keep it
  // as a re-promptable challenge, not a hard credential rejection.
  if (
    /verification code|check the code|enter the (?:pin|code)|finish signing in please enter the verification/i.test(
      hints,
    )
  ) {
    return "verification_required";
  }
  // UI / form failures are not proxy failures — don't alias them.
  if (/username field not found|password field not found|login form/.test(err)) return "login_failed";
  if (isHardProxyTunnelError(err)) {
    return "proxy_error";
  }
  // Only real wrong-password copy — bare HTTP 401 is NOT enough (every failed
  // browser login returns 401, including silent Reddit reCAPTCHA rejects).
  if (/incorrect username or password|wrong email or password|invalid credentials/.test(hints)) {
    return "invalid_credentials";
  }
  // Reddit silent risk / captcha reject: still on /login/ with empty wrong-password hints.
  if (/reddit\.com\/login/.test(finalUrl) && !out?.ok) {
    return "captcha_required";
  }
  return out?.ok ? "" : "login_failed";
}

// classifyThrownLoginError maps recipe exceptions to a failureType. Historically
// every thrown error was labeled proxy_error, which hid LinkedIn UI/authwall
// failures behind a misleading retryable proxy signal.
function classifyThrownLoginError(err) {
  const msg = String(err?.message || err || "").toLowerCase();
  if (isHardProxyTunnelError(msg)) {
    return "proxy_error";
  }
  if (/incorrect|wrong email or password|invalid credentials/.test(msg)) return "invalid_credentials";
  if (/captcha|are you a robot/.test(msg)) return "captcha_required";
  return "login_failed";
}

function attachLoginMeta(out, { proxyUrl, status }) {
  // Preserve explicit actionable failureTypes (e.g. login_in_progress) instead of
  // overwriting them with the generic HTTP-status classifier.
  const explicitFailure = String(out.failureType || "").trim();
  out.status = out.ok ? "verified" : (explicitFailure || classifyFailure(out, status));
  out.failureType = out.ok ? "" : out.status;
  // Recipes report an explicit code prompt through this hint. Preserve it as
  // an actionable challenge so the service can bind and return continuation.
  if (!out.ok && out.hints?.includes("verification_code_required")) {
    out.challenge = true;
  }
  out.proxyPresent = Boolean(proxyUrl);
  if (out.failureType === "verification_required") {
    out.challengeMethod = out.challengeMethod || "email_sms_in_app";
  }
  logLoginEvent("login_result", {
    ok: out.ok,
    status: out.status,
    proxyUrl,
    hasUserAgent: Boolean(out.session?.user_agent),
    cookieNames: Object.keys(out.cookies || {}),
  });
  return out;
}

// xType enters text with real per-character keystrokes. X's login UI is a React
// SPA that only enables the "Continue"/"Log in" button — and records the
// behavioral keystroke signals its anti-bot edge expects — on real input
// events. page.fill() sets the value without firing those, so the button stays
// effectively dead. Clear first, then type.
async function xType(locator, value) {
  await locator.click({ timeout: 8000 }).catch(() => {});
  try { await locator.fill(""); } catch {}
  await locator.pressSequentially(value, { delay: 55 });
}

// humanWarm simulates a returning user idling on a page: small mouse moves,
// a scroll or two, and randomized dwell. This lets cf_clearance / device
// identity cookies accrue and supplies the input cadence X's anti-bot edge
// looks for, so the subsequent login isn't flagged as a cold automation run.
async function humanWarm(page) {
  const dwell = 4000 + Math.floor(Math.random() * 3500);
  const start = Date.now();
  try {
    const vp = page.viewportSize() || { width: 1280, height: 800 };
    while (Date.now() - start < dwell) {
      const x = 80 + Math.floor(Math.random() * (vp.width - 160));
      const y = 80 + Math.floor(Math.random() * (vp.height - 160));
      await page.mouse.move(x, y, { steps: 4 + Math.floor(Math.random() * 6) }).catch(() => {});
      if (Math.random() < 0.5) {
        await page.mouse.wheel(0, 200 + Math.floor(Math.random() * 400)).catch(() => {});
      }
      await page.waitForTimeout(500 + Math.floor(Math.random() * 900));
    }
  } catch {}
}

// xField returns the first visible input matching `selector`, preferring the
// modal layer (#layers) but falling back to the base page. X's onboarding SPA
// renders the username step inside #layers, but later subtasks
// (login_enter_password, the confirmation-code challenge) render the form on the
// base page outside #layers — scoping only to the modal there silently finds
// nothing, so the step is skipped and the login stalls. Returns null if neither
// scope yields a visible field within the timeouts.
async function xField(page, modal, selector, timeoutMs) {
  let f = modal.locator(selector).first();
  try { await f.waitFor({ state: "visible", timeout: timeoutMs }); return f; } catch {}
  f = page.locator(selector).first();
  try { await f.waitFor({ state: "visible", timeout: 4000 }); return f; } catch {}
  return null;
}

// xClick clicks the first enabled button in `scope` matching any pattern,
// falling back to Enter (which submits the focused field in X's flow).
async function xClick(page, scope, patterns, beforeSubmit = () => {}) {
  // Try the modal scope first, then the base page (later subtasks render the
  // submit button outside #layers), then fall back to Enter on the focused
  // field — which submits the current step in X's flow.
  for (const root of [scope, page]) {
    for (const re of patterns) {
      const btn = root.getByRole("button", { name: re }).first();
      if (await btn.count().catch(() => 0)) {
        if (await btn.isDisabled().catch(() => false)) continue;
        beforeSubmit();
        try { await btn.click({ timeout: 8000 }); return true; } catch { currentLoginBudget()?.check(); }
      }
    }
  }
  beforeSubmit();
  try { await page.keyboard.press("Enter"); return true; } catch { currentLoginBudget()?.check(); }
  return false;
}

async function runProfileHarvest(platform, proxyUrl, profileKey, signal) {
  if (!["x", "reddit"].includes(platform)) throw new Error("unsupported profile harvest");
  const cancelled = () => Boolean(signal?.aborted);
  const release = await acquireAdmission(cancelled, signal);
  try {
    if (cancelled()) throw new AdmissionError("request_cancelled", "profile harvest cancelled");
    return await withProfileLock(profileKey, () => harvestProfile(platform, proxyUrl, profileKey));
  } finally {
    release();
  }
}

async function harvestX(proxyUrl, profileKey, signal) {
  return runProfileHarvest("x", proxyUrl, profileKey, signal);
}

async function harvestProfile(platform, proxyUrl, profileKey) {
  const { context, page, close } = await openLoginSession({ proxyUrl, profileKey, stealth: platform === "x" });
  try {
    const url = platform === "x" ? "https://x.com/home" : "https://www.reddit.com/";
    // A failed navigation must not return stale cookies as a successful harvest.
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: currentLoginBudget()?.timeout(60000) ?? 60000 });
    await loginSleep(1500);
    const cookies = await context.cookies();
    const userAgent = await page.evaluate(() => navigator.userAgent);
    if (platform === "reddit") {
      const map = redditCookieMap(cookies);
      const ok = Boolean(map.reddit_session && isAuthenticatedRedditToken(map.token_v2));
      const result = redditLoginResult(cookies, page.url(), { ok, hints: ok ? [] : ["logged_out"] });
      result.session.user_agent = userAgent;
      result.failureType = ok ? undefined : "logged_out";
      result.retryable = false;
      return result;
    }
    const map = Object.fromEntries(cookies.filter((cookie) => {
      const domain = cookie.domain.replace(/^\./, "");
      return domain === "x.com" || domain.endsWith(".x.com") || domain === "twitter.com" || domain.endsWith(".twitter.com");
    }).map((cookie) => [cookie.name, cookie.value]));
    const ok = Boolean(map.auth_token && map.ct0);
    return {
      ok, finalUrl: page.url(), cookies: map,
      session: { auth_token: map.auth_token || null, ct0: map.ct0 || null, user_agent: userAgent },
      hints: ok ? [] : ["logged_out"], failureType: ok ? undefined : "logged_out", retryable: false,
    };
  } finally {
    await close();
  }
}

async function loginX({ username, password, verificationCode, challengeHold }, proxyUrl, profileKey) {
  if (challengeHold) return finishXLogin(challengeHold, verificationCode, proxyUrl);
  if (verificationCode) throw new Error("challenge browser is required for code continuation");
  const session = await openLoginSession({ proxyUrl, profileKey, stealth: true });
  const { context, page, close } = session;
  // Set when X presents its new-device confirmation-code challenge but no code
  // is available yet — surfaced as verification_code_required so the agent
  // collects one via the in-chat social_two_factor card.
  let handedOff = false;
  try {
    // Warm a persistent profile first: visiting x.com logged-out lets cf_clearance
    // and the Castle device identity accrue so the subsequent login looks like a
    // returning user rather than a cold automation session. X's anti-bot edge
    // shows "We've temporarily limited your login" at the username step when the
    // session looks freshly automated (no warm cookies, instant deep-link to the
    // login flow, no human input cadence). To get past it we (1) dwell on the
    // logged-out home page with real mouse movement + scroll so cf_clearance and
    // device signals accrue, then (2) reach the login form by CLICKING the
    // "Sign in" affordance like a human, falling back to a direct nav only if the
    // link can't be found.
    let reachedLogin = false;
    await page.goto("https://x.com/", { waitUntil: "domcontentloaded", timeout: currentLoginBudget()?.timeout(60000) ?? 60000 });
    const existing = await context.cookies(["https://x.com"]);
    if (existing.some(c => c.name === "auth_token") && existing.some(c => c.name === "ct0") &&
        !/\/i\/(?:flow|jf)\/|\/login/.test(page.url()) && !(await xVisibleCodeField(page))) {
      handedOff = true;
      return await finishXLogin(session, "", proxyUrl);
    }
    await humanWarm(page);

    // Try to enter the flow organically via the "Sign in" link/button.
    for (const re of [/^sign in$/i, /^log in$/i]) {
      const link = page.getByRole("link", { name: re }).first();
      const btn = page.getByRole("button", { name: re }).first();
      const target = (await link.count().catch(() => 0)) ? link : (await btn.count().catch(() => 0)) ? btn : null;
      if (!target) continue;
      try {
        await target.click({ timeout: 6000 });
        await page.waitForTimeout(1500 + Math.floor(Math.random() * 1200));
        reachedLogin = /\/i\/flow\/login|\/login/.test(page.url()) ||
          (await page.locator("#layers").locator('input').count().catch(() => 0)) > 0;
        if (reachedLogin) break;
      } catch {}
    }

    // Fallback: direct navigation (still warmed, just not click-driven).
    if (!reachedLogin) {
      await page.goto("https://x.com/i/flow/login", { waitUntil: "domcontentloaded", timeout: 60000 });
    }

    // X serves the login form inside the modal layer (#layers). The base page
    // behind the backdrop carries a duplicate (pointer-blocked) copy of the
    // same inputs, so every interaction must be scoped to the modal or clicks
    // get intercepted by the <div data-testid="mask"> overlay.
    const modal = page.locator("#layers");
    const bodyText = () => page.locator("body").innerText().catch(() => "");

    // Step 1 — username/email. The current flow redirects to
    // /i/jf/onboarding/web and labels the field name="username_or_email"; older
    // variants use name="text". Accept both.
    const userSel = 'input[name="username_or_email"], input[name="text"], input[autocomplete~="username"], input[type="text"]';
    let userField = modal.locator(userSel).first();
    try {
      await userField.waitFor({ state: "visible", timeout: 45000 });
    } catch {
      // Fallback: no modal layer (old single-page flow) — use page scope.
      userField = page.locator(userSel).first();
      try {
        await userField.waitFor({ state: "visible", timeout: 15000 });
      } catch {
        throw new Error("username field not found");
      }
    }
    // Small human beat before the first keystroke so the username step isn't
    // entered the instant the field renders.
    await page.mouse.move(200 + Math.random() * 300, 200 + Math.random() * 200, { steps: 5 }).catch(() => {});
    await page.waitForTimeout(600 + Math.floor(Math.random() * 700));
    await xType(userField, username);
    await xClick(page, modal, [/^next$/i, /^continue$/i, /^log in$/i]);
    await page.waitForTimeout(2500);

    let limited = X_RATE_LIMIT_RE.test(await bodyText());

    // Optional interstitial: X asks to re-enter the username/email/phone to
    // confirm identity (ocf subtask).
    if (!limited) {
      const ocf = modal.locator('input[data-testid="ocfEnterTextTextInput"]').first();
      if (await ocf.count().catch(() => 0)) {
        try {
          await ocf.waitFor({ state: "visible", timeout: 4000 });
          await xType(ocf, username);
          await xClick(page, modal, [/^next$/i, /^continue$/i]);
          await page.waitForTimeout(1800);
        } catch {}
      }
    }

    // Step 2 — password. In the new flow this is a distinct step that only
    // appears after the username step is accepted. The login_enter_password
    // subtask renders on the base page (outside #layers), so search both.
    if (!limited) {
      const pwField = await xField(page, modal, 'input[name="password"], input[type="password"]', 12000);
      if (pwField) {
        await xType(pwField, password);
        await xClick(page, modal, [/^log in$/i, /^login$/i, /^continue$/i, /^next$/i], credentialSubmission);
        await page.waitForTimeout(3000);
      }
      limited = limited || X_RATE_LIMIT_RE.test(await bodyText());
    }

    handedOff = true;
    return await finishXLogin(session, "", proxyUrl);
  } finally {
    if (!handedOff) await close();
  }
}

const X_CODE_SELECTOR = 'input[name="code"], input[name="text"], input[data-testid="ocfEnterTextTextInput"], input[name="verfication_code"], input[autocomplete="one-time-code"], input[inputmode="numeric"]';

async function xVisibleCodeField(page) {
  const fields = page.locator(X_CODE_SELECTOR);
  for (let i = 0; i < await fields.count(); i++) {
    const field = fields.nth(i);
    if (await field.isVisible()) return field;
  }
  return null;
}

// A code continuation only touches the retained page. No login navigation,
// browser launch, password fill or password submission is permitted here.
async function finishXLogin(session, verificationCode, proxyUrl) {
  const { context, page, close } = session;
  let parked = false;
  try {
    const modal = page.locator("#layers");
    const bodyText = () => page.locator("body").innerText();
    let codeField = await xVisibleCodeField(page);
    if (verificationCode) {
      if (!codeField) throw new Error("challenge page is no longer available");
      await xType(codeField, String(verificationCode).trim());
      await xClick(page, modal, [/^next$/i, /^verify$/i, /^log in$/i, /^continue$/i]);
      await page.waitForTimeout(1500);
    }
    const deadline = Math.min(Date.now() + 30000, currentLoginBudget()?.deadline ?? Infinity);
    for (;;) {
      currentLoginBudget()?.check();
      const body = await bodyText();
      const rateLimited = X_RATE_LIMIT_RE.test(body);
      codeField = await xVisibleCodeField(page);
      const codeRequired = Boolean(codeField) || X_CODE_CHALLENGE_RE.test(body);
      const cookies = await context.cookies(["https://x.com"]);
      const map = Object.fromEntries(cookies.map((c) => [c.name, c.value]));
      // Stale auth cookies on a challenge/login page never establish success.
      const ok = !rateLimited && !codeRequired && !/\/i\/(?:flow|jf)\/|\/login/.test(page.url()) && Boolean(map.auth_token && map.ct0);
      if (ok || rateLimited || codeRequired || Date.now() >= deadline) {
        parked = !ok && !rateLimited && codeRequired;
        return {
          ok, rateLimited, finalUrl: page.url(), cookies: ok ? map : {},
          session: ok ? { auth_token: map.auth_token, ct0: map.ct0, user_agent: await page.evaluate(() => navigator.userAgent) } : {},
          hints: parked ? ["verification_code_required"] : rateLimited ? ["rate_limited"] : ["login_failed"],
          challengeMethod: parked ? "verification_code" : "",
          maskedDestination: parked ? extractMaskedDestination(body) : "",
          ...(parked ? { browserHold: Object.assign(session, { proxyUrl }) } : {}),
        };
      }
      await loginSleep(250);
    }
  } finally {
    if (!parked) await close();
  }
}

async function prewarmX(proxyUrl, profileKey, signal) {
  return withProfileLock(profileKey, async () => {
    if (signal?.aborted) throw signal.reason || new Error("prewarm aborted");
    const { page, close, persistent } = await openLoginSession({ proxyUrl, profileKey, stealth: true });
    const abort = () => { void close("prewarm_aborted"); };
    signal?.addEventListener("abort", abort, { once: true });
    try {
      await page.goto("https://x.com/", { waitUntil: "domcontentloaded", timeout: 60000 });
      await humanWarm(page);
      return { persistent, finalUrl: page.url() };
    } finally {
      signal?.removeEventListener("abort", abort);
      await close("prewarm_complete");
    }
  });
}

const LINKEDIN_CODE_RE = /verification code|security code|enter (?:the |your )?(?:pin|code)|we (?:sent|emailed|texted).{0,80}(?:code|pin)|check your (?:email|phone|messages)/i;
const LINKEDIN_INVALID_RE = /wrong email or password|incorrect (?:email|password)|password you provided is incorrect|couldn.t find a linkedin account/i;
const LINKEDIN_CAPTCHA_RE = /captcha|are you a robot|security verification|quick security check/i;

// CapSolver expects proxy as scheme:host:port:user:pass (same residential
// egress as the headed Chrome session when available).
function capsolverProxyString(proxyUrl) {
  if (!proxyUrl) return "";
  try {
    const u = new URL(proxyUrl);
    const scheme = (u.protocol || "http:").replace(":", "") || "http";
    const host = u.hostname;
    const port = u.port || (scheme === "https" ? "443" : "80");
    const user = decodeURIComponent(u.username || "");
    const pass = decodeURIComponent(u.password || "");
    if (!host) return "";
    if (user) return `${scheme}:${host}:${port}:${user}:${pass}`;
    return `${scheme}:${host}:${port}`;
  } catch {
    return "";
  }
}

async function capsolverCreateAndPollSolution(task) {
  if (!CAPSOLVER_API_KEY) throw new Error("capsolver api key missing");
  const budget = currentLoginBudget();
  budget?.use("solver");
  const controller = new AbortController();
  const signal = budget ? AbortSignal.any([controller.signal, budget.signal]) : controller.signal;
  const timer = setTimeout(() => controller.abort(), budget ? budget.timeout(CAPSOLVER_SOLVE_TIMEOUT_MS) : CAPSOLVER_SOLVE_TIMEOUT_MS);
  timer.unref?.();
  try {
  const createResp = await fetch("https://api.capsolver.com/createTask", {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ clientKey: CAPSOLVER_API_KEY, task }),
    signal,
  });
  const created = await createResp.json().catch(() => ({}));
  if (!createResp.ok || created.errorId || !created.taskId) {
    throw new Error(
      `capsolver createTask failed: ${created.errorCode || createResp.status} ${created.errorDescription || ""}`.trim(),
    );
  }
  const deadline = Math.min(Date.now() + CAPSOLVER_SOLVE_TIMEOUT_MS, budget?.deadline ?? Infinity);
  while (Date.now() < deadline) {
    await loginSleep(3000);
    const pollResp = await fetch("https://api.capsolver.com/getTaskResult", {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ clientKey: CAPSOLVER_API_KEY, taskId: created.taskId }),
      signal,
    });
    const res = await pollResp.json().catch(() => ({}));
    if (!pollResp.ok || res.errorId) {
      throw new Error(
        `capsolver getTaskResult failed: ${res.errorCode || pollResp.status} ${res.errorDescription || ""}`.trim(),
      );
    }
    if (res.status === "ready") {
      const token = String(res.solution?.gRecaptchaResponse || "").trim();
      if (!token) throw new Error("capsolver returned empty gRecaptchaResponse");
      return {
        token,
        userAgent: String(res.solution?.userAgent || "").trim(),
        // isSession mode may return CapSolver cookies (e.g. recaptcha-ca-t).
        cookies: res.solution?.cookies && typeof res.solution.cookies === "object"
          ? res.solution.cookies
          : null,
      };
    }
    if (res.status === "failed") throw new Error("capsolver solve failed");
  }
  throw new Error("capsolver solve timed out");
  } finally {
    clearTimeout(timer);
  }
}

async function capsolverCreateAndPoll(task) {
  const solved = await capsolverCreateAndPollSolution(task);
  return solved.token;
}

async function capsolverSolveLinkedInRecaptcha({ websiteURL, websiteKey, proxyUrl }) {
  const proxy = capsolverProxyString(proxyUrl);
  const task = proxy
    ? { type: "ReCaptchaV2Task", websiteURL, websiteKey, proxy }
    : { type: "ReCaptchaV2TaskProxyLess", websiteURL, websiteKey };
  console.log(JSON.stringify({
    event: "linkedin_captcha_api_solve_start",
    type: task.type,
    websiteKey: websiteKey.slice(0, 12),
    proxy: Boolean(proxy),
  }));
  const token = await capsolverCreateAndPoll(task);
  console.log(JSON.stringify({
    event: "linkedin_captcha_api_solve_ready",
    type: task.type,
    tokenLen: token.length,
  }));
  return token;
}

async function extractLinkedInRecaptchaChallenge(page) {
  return page.evaluate(() => {
    const siteKey =
      document.querySelector('input[name="captchaSiteKey"]')?.value ||
      document.querySelector("[data-sitekey]")?.getAttribute("data-sitekey") ||
      "";
    const tokenInput = document.querySelector('input[name="captchaUserResponseToken"]');
    const form = document.querySelector('form#captcha-challenge, form[action*="challenge/verify"]');
    const codeEl = document.querySelector("#captchaInternalPath");
    let internalPath = "/checkpoint/challenge/captchaInternal";
    if (codeEl) {
      const raw = (codeEl.textContent || "").replace(/[^\w./-]/g, "");
      if (raw.includes("checkpoint")) internalPath = raw.startsWith("/") ? raw : `/${raw}`;
    }
    return {
      siteKey: String(siteKey || "").trim(),
      pageUrl: location.href,
      hasForm: Boolean(form),
      hasTokenInput: Boolean(tokenInput),
      internalPath,
      iframeSrc: document.querySelector("#captcha-internal")?.getAttribute("src") || "",
    };
  });
}

async function ensureLinkedInCaptchaIframe(page) {
  await page.evaluate(() => {
    const iframe = document.querySelector("#captcha-internal");
    if (!iframe) return;
    if ((iframe.getAttribute("src") || "").trim()) return;
    const codeEl = document.querySelector("#captchaInternalPath");
    let path = "/checkpoint/challenge/captchaInternal";
    if (codeEl) {
      const raw = (codeEl.textContent || "").replace(/[^\w./-]/g, "");
      if (raw.includes("checkpoint")) path = raw.startsWith("/") ? raw : `/${raw}`;
    }
    iframe.setAttribute("src", path);
  }).catch(() => {});
}

async function injectLinkedInCaptchaTokenAndSubmit(page, token) {
  const submitted = await page.evaluate((tok) => {
    const setVal = (el, value) => {
      if (!el) return;
      el.value = value;
      el.dispatchEvent(new Event("input", { bubbles: true }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
    };
    setVal(document.querySelector('input[name="captchaUserResponseToken"]'), tok);
    for (const el of document.querySelectorAll(
      'textarea[name="g-recaptcha-response"], #g-recaptcha-response, textarea.g-recaptcha-response',
    )) {
      setVal(el, tok);
    }
    const form = document.querySelector('form#captcha-challenge, form[action*="challenge/verify"]');
    if (form) {
      form.submit();
      return "form_submit";
    }
    return "token_only";
  }, token);
  console.log(JSON.stringify({ event: "linkedin_captcha_token_injected", submitted }));
  return submitted;
}

// dumpLinkedInCaptchaProbe writes widget fingerprints (no cookies/secrets) so we
// can map LinkedIn checkpoint pages onto CapSolver task types.
async function dumpLinkedInCaptchaProbe(page) {
  const probe = await page.evaluate(() => {
    const attrs = (el) => {
      if (!el || !el.getAttributeNames) return null;
      const out = {};
      for (const n of el.getAttributeNames()) {
        const v = el.getAttribute(n) || "";
        if (/cookie|token|password|li_at|session/i.test(n)) continue;
        out[n] = v.slice(0, 240);
      }
      return out;
    };
    const iframes = [...document.querySelectorAll("iframe")].slice(0, 12).map((f) => ({
      src: (f.getAttribute("src") || "").slice(0, 300),
      title: (f.getAttribute("title") || "").slice(0, 120),
      id: f.id || "",
      name: f.name || "",
    }));
    const scripts = [...document.querySelectorAll("script[src]")]
      .map((s) => s.getAttribute("src") || "")
      .filter((src) => /arkose|funcaptcha|recaptcha|hcaptcha|captcha|challenge/i.test(src))
      .slice(0, 20);
    const pkeyEl =
      document.querySelector("[data-pkey], [data-sitekey], #arkose, .arkose-challenge, #captcha-internal, .g-recaptcha");
    const html = (document.documentElement?.outerHTML || "").slice(0, 12000)
      // Drop obvious session material from the debug probe dump.
      .replace(/li_at[=:][^&\s"'<>]{8,}/gi, "li_at=REDACTED")
      .replace(/JSESSIONID[=:][^&\s"'<>]{4,}/gi, "JSESSIONID=REDACTED")
      .replace(/csrfToken" value="[^"]*"/gi, 'csrfToken" value="REDACTED"')
      .replace(/name="csrfToken"[^>]*value="[^"]*"/gi, 'name="csrfToken" value="REDACTED"')
      .replace(/name="challengeData"[^>]*value="[^"]*"/gi, 'name="challengeData" value="REDACTED"')
      .replace(/name="challengeId"[^>]*value="[^"]*"/gi, 'name="challengeId" value="REDACTED"');
    return {
      url: location.href,
      title: document.title,
      bodySnippet: (document.body && document.body.innerText ? document.body.innerText : "").slice(0, 800),
      iframes,
      scripts,
      pkeyEl: attrs(pkeyEl),
      hasArkose: Boolean(window.ArkoseEnforcement || window.arkoseLabsClientApi || document.querySelector("[data-pkey]")),
      hasGrecaptcha: Boolean(window.grecaptcha),
      hasHcaptcha: Boolean(window.hcaptcha),
      fcTokenPresent: Boolean(document.querySelector("[name='fc-token'], #fc-token, input[name*='arkose' i]")),
      formAction: document.querySelector("form")?.getAttribute("action") || "",
      htmlHead: html,
    };
  });
  fs.writeFileSync("/tmp/linkedin-captcha-probe.json", JSON.stringify(probe, null, 2));
  await page.screenshot({ path: "/tmp/linkedin-captcha-probe.png", fullPage: true }).catch(() => {});
  console.log(JSON.stringify({
    event: "linkedin_captcha_probe",
    url: probe.url,
    hasArkose: probe.hasArkose,
    hasGrecaptcha: probe.hasGrecaptcha,
    iframes: (probe.iframes || []).length,
    scripts: probe.scripts,
  }));
}

async function waitForCapSolverLinkedInCaptcha(context, page, { hasSession, bodyText, proxyUrl }) {
  // LinkedIn's captchaV2 checkpoint embeds a Google reCAPTCHA site key in
  // captchaSiteKey but often never paints the widget (spinner-only). Prefer
  // CapSolver's API token (Reddit-parity) + form inject; keep the extension
  // wait as a fallback for FunCaptcha/image variants.
  console.log(JSON.stringify({
    event: "linkedin_captcha_solve_wait",
    extension: CAPSOLVER_EXTENSION_ENABLED,
    api: Boolean(CAPSOLVER_API_KEY),
    timeoutMs: CAPSOLVER_SOLVE_TIMEOUT_MS,
  }));
  await dumpLinkedInCaptchaProbe(page).catch(() => {});
  await ensureLinkedInCaptchaIframe(page);
  const deadline = Date.now() + CAPSOLVER_SOLVE_TIMEOUT_MS;
  let finalBody = "";
  let apiAttempted = false;
  let apiSucceeded = false;
  while (Date.now() < deadline) {
    if (await hasSession()) {
      return { ok: true, captcha: false, needsVerification: false, invalid: false, finalBody };
    }
    finalBody = await bodyText();
    const fieldVisible = Boolean(await linkedinPinField(page));
    const screen = classifyLinkedInScreen(finalBody, fieldVisible);
    if (screen === "verification_required") {
      return { ok: false, captcha: false, needsVerification: true, invalid: false, finalBody };
    }
    if (screen === "invalid_credentials") {
      return { ok: false, captcha: false, needsVerification: false, invalid: true, finalBody };
    }
    if (screen !== "captcha") {
      // Left the captcha page (feed redirect, consent, etc.) — keep polling
      // the caller loop for session cookies.
      return { ok: false, captcha: false, needsVerification: false, invalid: false, finalBody, progressed: true };
    }

    if (!apiSucceeded && CAPSOLVER_API_KEY) {
      try {
        const challenge = await extractLinkedInRecaptchaChallenge(page);
        if (challenge.siteKey) {
          apiAttempted = true;
          const token = await capsolverSolveLinkedInRecaptcha({
            websiteURL: challenge.pageUrl || page.url(),
            websiteKey: challenge.siteKey,
            proxyUrl,
          });
          await injectLinkedInCaptchaTokenAndSubmit(page, token);
          apiSucceeded = true;
          // LinkedIn posts the token then redirects (feed, PIN, or another
          // checkpoint). Wait for the captcha shell to clear before re-checking.
          await page.waitForFunction(() => {
            const body = document.body?.innerText || "";
            const onChallenge = /checkpoint\/challenge/i.test(location.href);
            if (!onChallenge) return true;
            if (/verification code|enter (?:the |your )?(?:pin|code)|we (?:sent|emailed)/i.test(body)) {
              return true;
            }
            return !/quick security check/i.test(body);
          }, { timeout: 25000 }).catch(() => {});
          await page.waitForTimeout(1500);
          continue;
        }
        if (!apiAttempted) {
          console.log(JSON.stringify({ event: "linkedin_captcha_api_skip", reason: "no_sitekey_yet" }));
        }
      } catch (err) {
        apiAttempted = true;
        console.log(JSON.stringify({
          event: "linkedin_captcha_api_solve_error",
          error: String(err?.message || err).slice(0, 240),
        }));
      }
    }
    await page.waitForTimeout(2000);
  }
  return { ok: false, captcha: true, needsVerification: false, invalid: false, finalBody };
}

function classifyLinkedInScreen(body, codeFieldVisible = false) {
  if (LINKEDIN_INVALID_RE.test(body)) return "invalid_credentials";
  // LinkedIn's PIN checkpoints can be wrapped in a generic "quick security
  // check" / "security verification" shell. A visible PIN field is the
  // stronger signal: preserve the recoverable verification flow instead of
  // classifying the shell as a CAPTCHA and losing the submitted OTP.
  if (codeFieldVisible || LINKEDIN_CODE_RE.test(body)) return "verification_required";
  if (LINKEDIN_CAPTCHA_RE.test(body)) return "captcha";
  return "pending";
}

// shouldReuseLinkedInSession is true when a persisted browser profile already
// has LinkedIn auth cookies and the login form is not present (LinkedIn
// redirected an authenticated session away from /login).
function shouldReuseLinkedInSession({ hasLiAt, hasJSessionID, usernameFieldFound, challengeScreen }) {
  return Boolean(hasLiAt && hasJSessionID && !usernameFieldFound && !challengeScreen);
}

// LinkedIn-only cookie export (Reddit parity). The shared Chrome profile also
// holds X/Twitter/ad cookies; dumping the whole jar and reseeding them onto
// .linkedin.com makes Voyager search redirect-loop while /feed/ still passes.
function linkedinSessionCookieMap(cookies) {
  return Object.fromEntries(
    (cookies || [])
      .filter((c) => String(c.domain || "").includes("linkedin.com"))
      .map((c) => [c.name, c.value]),
  );
}

function linkedinSessionResult(pageUrl, cookies, queryDiscovery = null) {
  const map = linkedinSessionCookieMap(cookies);
  const result = {
    ok: true,
    captcha: false,
    finalUrl: pageUrl,
    cookies: map,
    session: { li_at: map.li_at || null, JSESSIONID: map.JSESSIONID || null },
    hints: [],
    challengeMethod: "",
    maskedDestination: "",
  };
  if (queryDiscovery?.voyagerQueryIDs && Object.keys(queryDiscovery.voyagerQueryIDs).length) {
    result.voyagerQueryIDs = queryDiscovery.voyagerQueryIDs;
    result.voyagerQueryIDMeta = queryDiscovery.meta;
  }
  return result;
}

const LINKEDIN_QUERY_PATTERNS = Object.freeze({
  search: /\bvoyagerSearchDashClusters\.[a-f0-9]{32}\b/g,
  profile: /\bvoyagerIdentityDashProfiles\.[a-f0-9]{32}\b/g,
});

function extractLinkedInVoyagerQueryIDs(texts) {
  const found = {};
  for (const text of texts || []) {
    if (typeof text !== "string") continue;
    const search = !found.search && text.match(LINKEDIN_QUERY_PATTERNS.search)?.[0];
    const profile = !found.profile && text.match(LINKEDIN_QUERY_PATTERNS.profile)?.[0];
    if (search) found.search = search;
    if (profile) found.profile = profile;
    if (found.search && found.profile) break;
  }
  return found;
}

function linkedinQueryCacheGet(profileKey) {
  const key = crypto.createHash("sha256").update(String(profileKey || "anon")).digest("hex");
  const entry = linkedinQueryIDCache.get(key);
  if (!entry || entry.expiresAt <= Date.now()) {
    linkedinQueryIDCache.delete(key);
    return null;
  }
  return { hit: true, value: entry.value };
}

function linkedinQueryCachePut(profileKey, value) {
  const key = crypto.createHash("sha256").update(String(profileKey || "anon")).digest("hex");
  if (linkedinQueryIDCache.size >= LINKEDIN_QUERY_CACHE_MAX && !linkedinQueryIDCache.has(key)) {
    linkedinQueryIDCache.delete(linkedinQueryIDCache.keys().next().value);
  }
  const positive = Boolean(value?.voyagerQueryIDs && Object.keys(value.voyagerQueryIDs).length);
  linkedinQueryIDCache.set(key, {
    value,
    expiresAt: Date.now() + (positive ? LINKEDIN_QUERY_POSITIVE_TTL_MS : LINKEDIN_QUERY_NEGATIVE_TTL_MS),
  });
}

async function discoverLinkedInVoyagerQueryIDs(page, profileKey, fetchImpl = fetch) {
  const cached = linkedinQueryCacheGet(profileKey);
  if (cached) return cached.value;
  const startedAt = Date.now();
  const deadline = startedAt + LINKEDIN_QUERY_DISCOVERY_TIMEOUT_MS;
  let bytes = 0;
  const texts = [];
  const sources = new Set();
  const resourceURLs = [];
  let activeSearchQueryIDs = {};
  const add = (text, source) => {
    if (typeof text !== "string" || bytes >= LINKEDIN_QUERY_DISCOVERY_MAX_BYTES) return;
    const bounded = text.slice(0, LINKEDIN_QUERY_DISCOVERY_MAX_BYTES - bytes);
    bytes += Buffer.byteLength(bounded);
    texts.push(bounded);
    sources.add(source);
  };
  try {
    if (!/^https:\/\/([a-z0-9-]+\.)*linkedin\.com\/feed(?:\/|[?#]|$)/i.test(page.url())) {
      return null;
    }
    const captureResources = async (source) => {
      const snapshot = await page.evaluate(() => ({
        resources: performance.getEntriesByType("resource").map((entry) => entry.name),
      }));
      resourceURLs.push(...(snapshot.resources || []));
      add((snapshot.resources || []).join("\n"), source);
      return snapshot.resources || [];
    };
    await captureResources("resources");
    if (typeof page.goto === "function") {
      const remaining = deadline - Date.now();
      if (remaining > 0) {
        await page.goto("https://www.linkedin.com/search/results/content/?keywords=software", {
          waitUntil: "domcontentloaded",
          timeout: remaining,
        }).catch(() => {});
        if (typeof page.waitForTimeout === "function") {
          await page.waitForTimeout(Math.min(1000, Math.max(0, deadline - Date.now())));
        }
        const activeResources = await captureResources("search_resources").catch(() => []);
        activeSearchQueryIDs = extractLinkedInVoyagerQueryIDs(activeResources);
      }
    }
    const bundleURLs = [...new Set(resourceURLs)].filter((raw) => {
      try {
        const url = new URL(raw, page.url());
        return url.protocol === "https:" &&
          /(^|\.)(?:linkedin|licdn)\.com$/i.test(url.hostname) &&
          /\.js(?:[?#]|$)/i.test(url.href);
      } catch {
        return false;
      }
    }).slice(0, LINKEDIN_QUERY_DISCOVERY_MAX_BUNDLES);
    for (const url of bundleURLs) {
      if (Date.now() >= deadline || bytes >= LINKEDIN_QUERY_DISCOVERY_MAX_BYTES) break;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), Math.max(1, deadline - Date.now()));
      try {
        const response = await fetchImpl(url, { signal: controller.signal, credentials: "omit" });
        const length = Number(response.headers?.get?.("content-length") || 0);
        if (!response.ok || (length && length > LINKEDIN_QUERY_DISCOVERY_MAX_BYTES - bytes)) continue;
        const reader = response.body?.getReader?.();
        if (!reader) continue;
        const chunks = [];
        let received = 0;
        while (received < LINKEDIN_QUERY_DISCOVERY_MAX_BYTES - bytes) {
          const { done, value } = await reader.read();
          if (done) break;
          received += value.byteLength;
          if (received > LINKEDIN_QUERY_DISCOVERY_MAX_BYTES - bytes) {
            await reader.cancel();
            chunks.length = 0;
            break;
          }
          chunks.push(value);
        }
        if (chunks.length) add(Buffer.concat(chunks).toString("utf8"), "bundle");
      } catch {} finally {
        clearTimeout(timer);
      }
    }
    const voyagerQueryIDs = {
      ...extractLinkedInVoyagerQueryIDs(texts),
      ...activeSearchQueryIDs,
    };
    const value = Object.keys(voyagerQueryIDs).length ? {
      voyagerQueryIDs,
      meta: { discoveredAt: new Date().toISOString(), sources: [...sources].sort() },
    } : null;
    linkedinQueryCachePut(profileKey, value);
    return value;
  } catch {
    linkedinQueryCachePut(profileKey, null);
    return null;
  }
}

async function linkedInSuccessfulSessionResult(page, context, profileKey) {
  const discovery = await discoverLinkedInVoyagerQueryIDs(page, profileKey).catch(() => null);
  return linkedinSessionResult(page.url(), await context.cookies(), discovery);
}

const LINKEDIN_USER_SEL = [
  "#username",
  'input[name="session_key"]',
  'input[autocomplete="username"]',
  'input[id*="username" i]',
  'input[type="email"]',
  'input[name="email"]',
  'input[aria-label*="Email" i]',
  'input[aria-label*="phone" i]',
];
const LINKEDIN_PASS_SEL = [
  "#password",
  'input[name="session_password"]',
  'input[type="password"]',
  'input[autocomplete="current-password"]',
  'input[aria-label*="Password" i]',
];

async function dismissLinkedInConsent(page) {
  // LinkedIn/OneTrust often overlays the login form until consent is accepted.
  await clickByText(page, [
    /^accept$/i,
    /^accept all$/i,
    /^accept all cookies$/i,
    /^agree$/i,
    /^i agree$/i,
    /^allow all cookies$/i,
    /^only allow essential cookies$/i,
    /^reject non-essential$/i,
    /^ok$/i,
    /^got it$/i,
  ]);
  for (const sel of [
    "#onetrust-accept-btn-handler",
    'button[action-type="ACCEPT"]',
    'button[data-control-name="ga-cookie.consent.accept.v4"]',
    'button[aria-label*="Accept" i]',
  ]) {
    const btn = page.locator(sel).first();
    if ((await btn.count().catch(() => 0)) > 0) {
      await btn.click({ timeout: 3000 }).catch(() => {});
    }
  }
}

async function linkedinPageSnippet(page) {
  const body = (await page.locator("body").innerText().catch(() => "")).replace(/\s+/g, " ").slice(0, 400);
  const title = await page.title().catch(() => "");
  return `url=${page.url()} title="${title}" body="${body}"`;
}

async function linkedinUsernameVisible(page) {
  for (const sel of LINKEDIN_USER_SEL) {
    const el = page.locator(sel).first();
    if ((await el.count().catch(() => 0)) > 0 && (await el.isVisible().catch(() => false))) return true;
  }
  return false;
}

const LINKEDIN_PIN_SEL =
  'input[autocomplete="one-time-code"], input[name*="pin" i], input[name*="code" i], input[inputmode="numeric"]';

async function linkedinPinField(page) {
  const field = page.locator(LINKEDIN_PIN_SEL).first();
  const visible =
    (await field.count().catch(() => 0)) > 0 && (await field.isVisible().catch(() => false));
  return visible ? field : null;
}

async function submitLinkedInPinOnPage(page, code) {
  const field = await linkedinPinField(page);
  if (!field) return false;
  await field.fill(String(code).trim());
  if (!(await clickByText(page, [/^submit$/i, /^verify$/i, /^continue$/i, /^next$/i]))) {
    const submit = page.locator('button[type="submit"], input[type="submit"]').first();
    if (await submit.count().catch(() => 0)) await submit.click({ timeout: 8000 }).catch(() => {});
  }
  return true;
}

async function waitLinkedInPinOutcome(context, page, { codeSubmitted }) {
  const bodyText = () => page.locator("body").innerText().catch(() => "");
  const hasSession = async () => {
    const cookies = await context.cookies();
    return cookies.some((c) => c.name === "li_at") && cookies.some((c) => c.name === "JSESSIONID");
  };
  let ok = false;
  let needsVerification = false;
  let invalid = false;
  let captcha = false;
  let finalBody = "";
  const deadline = Date.now() + 45000;
  while (Date.now() < deadline) {
    if (await hasSession()) {
      ok = true;
      break;
    }
    finalBody = await bodyText();
    const fieldVisible = Boolean(await linkedinPinField(page));
    const screen = classifyLinkedInScreen(finalBody, fieldVisible);
    invalid = screen === "invalid_credentials";
    captcha = screen === "captcha";
    if (invalid || captcha) break;
    if (screen === "verification_required") {
      needsVerification = true;
      if (codeSubmitted) {
        // Wrong/expired PIN — keep the page so the newest code can be tried.
        break;
      }
    }
    await page.waitForTimeout(1500);
  }
  return { ok, needsVerification, invalid, captcha, finalBody };
}

function linkedinChallengeResult({ ok, needsVerification, invalid, captcha, finalBody, page, cookies, codeSubmitted }) {
  const map = linkedinSessionCookieMap(cookies);
  const hints = [];
  if (!ok) {
    const pinFailed =
      codeSubmitted || /verification code|check the code|enter the verification code/i.test(finalBody || "");
    if (needsVerification || pinFailed) {
      needsVerification = true;
      hints.push("verification_code_required");
      if (pinFailed && codeSubmitted) {
        hints.push("That verification code didn't work — enter the newest code and try again.");
      }
    } else if (invalid) hints.push("incorrect email or password");
    else if (captcha) hints.push("captcha_required");
    else {
      hints.push(
        ...(finalBody || "")
          .split("\n")
          .map((l) => l.trim())
          .filter((l) => /wrong|incorrect|challenge|checkpoint|verify|code/i.test(l))
          .slice(0, 6),
      );
    }
  }
  return {
    ok,
    captcha: !ok && captcha,
    finalUrl: page.url(),
    cookies: map,
    session: { li_at: map.li_at || null, JSESSIONID: map.JSESSIONID || null },
    hints,
    challengeMethod: needsVerification ? "email_sms" : "",
    maskedDestination: needsVerification ? extractMaskedDestination(finalBody || "") : "",
  };
}

// Resume a parked LinkedIn checkpoint with the user-supplied PIN. Must not
// re-submit email/password — that emails a second code and invalidates this one.
async function resumeLinkedInChallengeHold(held, code, profileKey) {
  const { context, page, close, proxyUrl } = held;
  let parkAgain = false;
  try {
    const submitted = await submitLinkedInPinOnPage(page, code);
    if (!submitted) {
      // Hold went stale (page navigated away). Close and force a fresh login.
      return {
        ok: false,
        captcha: false,
        finalUrl: page.url(),
        cookies: {},
        session: {},
        hints: ["verification_code_required", "Challenge session expired — sign in again for a new code."],
        challengeMethod: "email_sms",
        maskedDestination: "",
      };
    }
    const outcome = await waitLinkedInPinOutcome(context, page, { codeSubmitted: true });
    if (outcome.ok) {
      await page.goto("https://www.linkedin.com/feed/", { waitUntil: "domcontentloaded", timeout: 45000 }).catch(() => {});
      return linkedInSuccessfulSessionResult(page, context, profileKey);
    }
    if (outcome.needsVerification) parkAgain = true;
    return {
      ...linkedinChallengeResult({
      ...outcome,
      page,
      cookies: await context.cookies(),
      codeSubmitted: true,
      }),
      ...(parkAgain ? { browserHold: { context, page, close, proxyUrl } } : {}),
    };
  } finally {
    if (!parkAgain) await close().catch(() => {});
  }
}

// loginLinkedIn mints the browser session consumed by linkedin-go. LinkedIn
// commonly routes unfamiliar devices through /checkpoint/challenge; only a
// real email/SMS PIN prompt is recoverable by the shared verification phase.
async function loginLinkedIn({ username, password, verificationCode, challengeHold }, proxyUrl, profileKey) {
  const code = String(verificationCode || "").trim();
  if (code && challengeHold) {
    const held = challengeHold || takeChallengeHold("linkedin", profileKey);
    if (held) return resumeLinkedInChallengeHold(held, code, profileKey);
  }
  // Drop any parked checkpoint before launching a new Chrome — the hold keeps
  // the persistent profile open, which would SingletonLock a fresh launch.

  const { context, page, close } = await openLoginSession({
    proxyUrl,
    profileKey,
    stealth: true,
    loadCapsolverExt: true,
  });
  const bodyText = () => page.locator("body").innerText().catch(() => "");
  // Auth cookies alone are not enough: a stale li_at can linger on an active
  // captcha checkpoint and falsely mark the login verified (feed then 302-loops).
  const hasSession = async () => {
    const cookies = await context.cookies();
    const authed =
      cookies.some((c) => c.name === "li_at") && cookies.some((c) => c.name === "JSESSIONID");
    if (!authed) return false;
    const url = page.url();
    // Any checkpoint URL is incomplete auth — captcha, PIN, or a loading
    // shell can still carry stale li_at from a prior attempt.
    if (/checkpoint\/challenge|\/checkpoint\/lg\//i.test(url)) return false;
    if (/\/login|authwall/i.test(url)) return false;
    return true;
  };
  let park = false;
  try {
    // Warm like the X recipe: cold deep-links to /login often land on an
    // authwall / consent shell with no username field. Dwell on the guest home
    // first, dismiss cookies, then enter the login form.
    await page.goto("https://www.linkedin.com/", { waitUntil: "domcontentloaded", timeout: 60000 }).catch(() => {});
    await dismissLinkedInConsent(page);
    await humanWarm(page);
    await dismissLinkedInConsent(page);

    // PIN-only resume without a hold: if the warmed profile still shows the
    // checkpoint field, submit the code and skip password (avoids a new email).
    if (code) {
      const pinField = await linkedinPinField(page);
      if (pinField || /checkpoint\/challenge/i.test(page.url())) {
        if (pinField || (await linkedinPinField(page))) {
          await submitLinkedInPinOnPage(page, code);
          const outcome = await waitLinkedInPinOutcome(context, page, { codeSubmitted: true });
          if (outcome.ok) {
            await page.goto("https://www.linkedin.com/feed/", { waitUntil: "domcontentloaded", timeout: 45000 }).catch(() => {});
            return linkedInSuccessfulSessionResult(page, context, profileKey);
          }
          if (outcome.needsVerification) park = true;
          return {
            ...linkedinChallengeResult({
            ...outcome,
            page,
            cookies: await context.cookies(),
            codeSubmitted: true,
            }),
            ...(park ? { browserHold: { context, page, close, proxyUrl } } : {}),
          };
        }
      }
    }

    let reachedLogin = await linkedinUsernameVisible(page);
    if (!reachedLogin) {
      for (const re of [/^sign in$/i, /^log in$/i]) {
        const link = page.getByRole("link", { name: re }).first();
        const btn = page.getByRole("button", { name: re }).first();
        const target =
          (await link.count().catch(() => 0)) ? link : (await btn.count().catch(() => 0)) ? btn : null;
        if (!target) continue;
        try {
          await target.click({ timeout: 6000 });
          await page.waitForTimeout(1200 + Math.floor(Math.random() * 800));
          await dismissLinkedInConsent(page);
          if (await linkedinUsernameVisible(page)) {
            reachedLogin = true;
            break;
          }
        } catch {}
      }
    }
    if (!reachedLogin) {
      for (const url of [
        "https://www.linkedin.com/login",
        "https://www.linkedin.com/uas/login",
        "https://www.linkedin.com/checkpoint/lg/sign-in-another-account",
      ]) {
        await page.goto(url, { waitUntil: "domcontentloaded", timeout: 60000 }).catch(() => {});
        await dismissLinkedInConsent(page);
        await page.waitForTimeout(800 + Math.floor(Math.random() * 700));
        if (await linkedinUsernameVisible(page)) {
          reachedLogin = true;
          break;
        }
      }
    }

    // Warmed persistent profiles often redirect away from /login. Prefer the
    // existing session cookies over requiring username/password fields.
    const cookiesAfterGoto = await context.cookies();
    const cookieMap = linkedinSessionCookieMap(cookiesAfterGoto);
    const usernameFieldFound = await linkedinUsernameVisible(page);
    const bodyText = await page.locator("body").innerText().catch(() => "");
    const screen = classifyLinkedInScreen(bodyText, false);
    if (
      shouldReuseLinkedInSession({
        hasLiAt: Boolean(cookieMap.li_at),
        hasJSessionID: Boolean(cookieMap.JSESSIONID),
        usernameFieldFound,
        challengeScreen: screen !== "pending",
      })
    ) {
      await page.goto("https://www.linkedin.com/feed/", { waitUntil: "domcontentloaded", timeout: 45000 }).catch(() => {});
      return linkedInSuccessfulSessionResult(page, context, profileKey);
    }

    await page.waitForSelector(LINKEDIN_USER_SEL.join(", "), { timeout: 45000 }).catch(() => {});
    await dismissLinkedInConsent(page);
    // Prefer human-like typing; fall back to fill if keystrokes fail.
    if (!(await typeFirst(page, LINKEDIN_USER_SEL, username)) &&
        !(await fillFirst(page, LINKEDIN_USER_SEL, username))) {
      throw new Error(`username field not found (${await linkedinPageSnippet(page)})`);
    }
    if (!(await typeFirst(page, LINKEDIN_PASS_SEL, password)) &&
        !(await fillFirst(page, LINKEDIN_PASS_SEL, password))) {
      throw new Error(`password field not found (${await linkedinPageSnippet(page)})`);
    }
    if (!(await clickByText(page, [/^sign in$/i, /^log in$/i], credentialSubmission))) {
      const submit = page.locator('button[type="submit"], input[type="submit"]').first();
      if (await submit.count().catch(() => 0)) { credentialSubmission(); await submit.click({ timeout: 8000 }).catch(() => {}); }
      else { credentialSubmission(); await page.keyboard.press("Enter").catch(() => {}); }
    }

    let ok = false;
    let needsVerification = false;
    let invalid = false;
    let captcha = false;
    let finalBody = "";
    let codeSubmitted = false;
    const deadline = Date.now() + 45000;
    while (Date.now() < deadline) {
      if (await hasSession()) { ok = true; break; }
      finalBody = await bodyText();
      const fieldVisible = Boolean(await linkedinPinField(page));
      const screen = classifyLinkedInScreen(finalBody, fieldVisible);
      invalid = screen === "invalid_credentials";
      captcha = screen === "captcha";
      if (captcha) {
        if (CAPSOLVER_EXTENSION_ENABLED || CAPSOLVER_API_KEY) {
          const solved = await waitForCapSolverLinkedInCaptcha(context, page, {
            hasSession,
            bodyText,
            proxyUrl,
          });
          if (solved.ok) {
            ok = true;
            captcha = false;
            break;
          }
          if (solved.needsVerification) {
            needsVerification = true;
            captcha = false;
            finalBody = solved.finalBody || finalBody;
            break;
          }
          if (solved.invalid) {
            invalid = true;
            captcha = false;
            finalBody = solved.finalBody || finalBody;
            break;
          }
          if (solved.progressed) {
            captcha = false;
            finalBody = solved.finalBody || finalBody;
            continue;
          }
          captcha = true;
          finalBody = solved.finalBody || finalBody;
        } else {
          await dumpLinkedInCaptchaProbe(page).catch(() => {});
        }
      }
      if (invalid || captcha) break;
      const isPIN = screen === "verification_required";
      if (isPIN) {
        if (!code) { needsVerification = true; break; }
        if (!codeSubmitted && fieldVisible) {
          await submitLinkedInPinOnPage(page, code);
          codeSubmitted = true;
        }
      }
      await page.waitForTimeout(1500);
    }

    if (!ok && needsVerification && !code) {
      park = true;
    } else if (!ok && codeSubmitted) {
      const stillPin =
        Boolean(await linkedinPinField(page)) ||
        classifyLinkedInScreen(finalBody, Boolean(await linkedinPinField(page))) === "verification_required";
      if (stillPin) {
        park = true;
        needsVerification = true;
      }
    }

    // Prove the session against /feed before claiming verified — captcha token
    // inject can mint li_at while still parked on the checkpoint URL.
    if (ok) {
      await page.goto("https://www.linkedin.com/feed/", {
        waitUntil: "domcontentloaded",
        timeout: 45000,
      }).catch(() => {});
      await page.waitForTimeout(1200);
      finalBody = await bodyText();
      const fieldVisible = Boolean(await linkedinPinField(page));
      const screen = classifyLinkedInScreen(finalBody, fieldVisible);
      if (!(await hasSession()) || /\/login|authwall/i.test(page.url()) || screen === "captcha") {
        ok = false;
        captcha = screen === "captcha";
        if (screen === "verification_required") {
          needsVerification = true;
          if (!code) {
            park = true;
          }
        }
      } else if (screen === "verification_required") {
        ok = false;
        needsVerification = true;
        if (!code) {
          park = true;
        }
      }
    }

    if (ok) return linkedInSuccessfulSessionResult(page, context, profileKey);
    return {
      ...linkedinChallengeResult({
      ok,
      needsVerification,
      invalid,
      captcha,
      finalBody,
      page,
      cookies: await context.cookies(),
      codeSubmitted,
      }),
      ...(park ? { browserHold: { context, page, close, proxyUrl } } : {}),
    };
  } finally {
    if (!park) await close();
  }
}

// TikTok's email/SMS confirmation-code challenge, recognized by on-screen copy.
// Deliberately narrower than the drag/slide CAPTCHA copy so the two never
// alias: a CAPTCHA must stay captcha_required (unrecoverable via OTP), while a
// code challenge surfaces verification_code_required so the shared
// social_two_factor / Settings verification follow-up collects the code.
const TIKTOK_CODE_CHALLENGE_RE = /verification code|\d-digit code|we sent .{0,40}code|code (was )?sent|check your (email|messages|phone)/i;
const TIKTOK_CAPTCHA_RE = /verify to continue|drag the|slide to|puzzle|rotate|captcha|security check/i;

async function loginTikTok({ username, password, verificationCode }, proxyUrl, profileKey) {
  const { context, page, close } = await openLoginSession({ proxyUrl, profileKey });
  try {
    await page.goto("https://www.tiktok.com/login/phone-or-email/email", { waitUntil: "domcontentloaded", timeout: 60000 });
    await page.waitForTimeout(2500);
    await page.waitForSelector('input[name="username"], input[type="text"]', { timeout: 30000 }).catch(() => {});
    if (!(await fillFirst(page, ['input[name="username"]', 'input[type="text"]'], username)))
      throw new Error("username field not found");
    if (!(await fillFirst(page, ['input[type="password"]', 'input[name="password"]'], password)))
      throw new Error("password field not found");
    if (!(await clickByText(page, [/^log in$/i, /^login$/i], credentialSubmission))) {
      const sub = page.locator('button[type="submit"]').first();
      if (await sub.count().catch(() => 0)) { credentialSubmission(); await sub.click({ timeout: 8000 }).catch(() => {}); }
    }
    const has = async () => {
      const cks = await context.cookies();
      return cks.find((c) => c.name === "sessionid") && cks.find((c) => c.name === "tt_csrf_token");
    };
    const codeSel =
      'input[autocomplete="one-time-code"], input[name="code"], input[placeholder*="code" i], input[inputmode="numeric"]';
    const deadline = Date.now() + 45000;
    let ok = false;
    let captcha = false;
    let needsVerification = false;
    let codeSubmitted = false;
    let finalBody = "";
    while (Date.now() < deadline) {
      if (await has()) { ok = true; break; }
      const body = await page.locator("body").innerText().catch(() => "");
      finalBody = body;
      const codeField = page.locator(codeSel).first();
      const hasCodeField =
        (await codeField.count().catch(() => 0)) > 0 && (await codeField.isVisible().catch(() => false));
      if ((hasCodeField || TIKTOK_CODE_CHALLENGE_RE.test(body)) && !TIKTOK_CAPTCHA_RE.test(body)) {
        const code = verificationCode && String(verificationCode).trim();
        if (!code) {
          // No code on hand: stop here so the Go layer returns
          // verification_required and the OTP card collects one. The warmed
          // persistent profile keeps the device identity across the retry.
          needsVerification = true;
          break;
        }
        if (!codeSubmitted && hasCodeField) {
          await codeField.fill(code).catch(() => {});
          if (!(await clickByText(page, [/^verify$/i, /^submit$/i, /^next$/i, /^log in$/i, /^continue$/i]))) {
            const sub = page.locator('button[type="submit"]').first();
            if (await sub.count().catch(() => 0)) await sub.click({ timeout: 8000 }).catch(() => {});
          }
          codeSubmitted = true;
        }
      } else if (TIKTOK_CAPTCHA_RE.test(body)) {
        captcha = true;
      }
      await page.waitForTimeout(1500);
    }
    const cookies = await context.cookies();
    const map = Object.fromEntries(cookies.map((c) => [c.name, c.value]));
    let hints = [];
    if (!ok) {
      const body = finalBody || (await page.locator("body").innerText().catch(() => ""));
      hints = body.split("\n").filter((l) => /incorrect|wrong|couldn|too many|try again|captcha|verify|security|code/i.test(l)).slice(0, 6);
      if (needsVerification) hints.push("verification_code_required");
      else if (captcha) hints.push("captcha_required");
    }
    return {
      ok,
      captcha: !ok && captcha,
      finalUrl: page.url(),
      cookies: map,
      session: { sessionid: map.sessionid || null, tt_csrf_token: map.tt_csrf_token || null, msToken: map.msToken || null, ttwid: map.ttwid || null },
      hints,
      challengeMethod: needsVerification ? "email_sms_in_app" : "",
      maskedDestination: needsVerification ? extractMaskedDestination(finalBody) : "",
    };
  } finally {
    await close();
  }
}

// Reddit's public reCAPTCHA Enterprise site key (login action), scraped from
// google.com/recaptcha/enterprise.js?render=... on www.reddit.com/login.
const REDDIT_RECAPTCHA_SITE_KEY = "6LfirrMoAAAAAHZOipvza4kpp_VtTwLNuXVwURNQ";
// Default 3 fits under smore-agents REDDIT_LOGIN_TIMEOUT (240s) with ~60s
// CapSolver mints; override via REDDIT_CAPSOLVER_ATTEMPTS when lease is longer.
const REDDIT_CAPSOLVER_ATTEMPTS = Math.min(
  10,
  Math.max(1, parseInt(process.env.REDDIT_CAPSOLVER_ATTEMPTS || "3", 10) || 3),
);

function redditCookieMap(cookies) {
  const map = {};
  for (const c of cookies) {
    const domain = c.domain.replace(/^\./, "");
    if (domain === "reddit.com" || domain.endsWith(".reddit.com")) map[c.name] = c.value;
  }
  return map;
}

function redditLoginResult(contextCookies, pageUrl, { ok = false, hints = [] } = {}) {
  const map = redditCookieMap(contextCookies);
  return {
    ok,
    finalUrl: pageUrl || "https://www.reddit.com/login/",
    cookies: map,
    session: { reddit_session: map.reddit_session || null, token_v2: map.token_v2 || null, loid: map.loid || null },
    hints,
    captcha: hints.includes("captcha_required"),
    challengeMethod: hints.includes("verification_code_required") ? "totp" : "",
  };
}

async function capsolverSolveRedditEnterprise() {
  const task = {
    type: "ReCaptchaV3EnterpriseTaskProxyLess",
    websiteURL: "https://www.reddit.com/login",
    websiteKey: REDDIT_RECAPTCHA_SITE_KEY,
    pageAction: "login",
    isEnterprise: true,
    minScore: 0.9,
    isSession: true,
  };
  console.log(JSON.stringify({
    event: "reddit_captcha_api_solve_start",
    type: task.type,
    websiteKey: REDDIT_RECAPTCHA_SITE_KEY.slice(0, 12),
  }));
  const solved = await capsolverCreateAndPollSolution(task);
  console.log(JSON.stringify({
    event: "reddit_captcha_api_solve_ready",
    type: task.type,
    tokenLen: solved.token.length,
    hasUserAgent: Boolean(solved.userAgent),
  }));
  return solved;
}

async function applyCapsolverSessionCookies(context, cookies) {
  if (!cookies || typeof cookies !== "object") return;
  const entries = Array.isArray(cookies)
    ? cookies
    : Object.entries(cookies).map(([name, value]) => ({ name, value }));
  const toAdd = [];
  for (const entry of entries) {
    const name = String(entry?.name || "").trim();
    const value = String(entry?.value ?? entry?.[1] ?? "").trim();
    if (!name || !value) continue;
    toAdd.push({
      name,
      value,
      domain: ".reddit.com",
      path: "/",
      httpOnly: false,
      secure: true,
      sameSite: "None",
    });
  }
  if (toAdd.length) await context.addCookies(toAdd).catch(() => {});
}

// CapSolver-backed shreddit login (parity with smore's pure-Go path). Mint an
// Enterprise v3 token, then POST /svc/shreddit/account/login through the same
// residential-proxied browser context so cookies stick for the Go client.
async function loginRedditViaCapSolver(context, page, { username, password, otp }) {
  let lastSoft = "";
  for (let attempt = 1; attempt <= REDDIT_CAPSOLVER_ATTEMPTS; attempt++) {
    currentLoginBudget()?.check();
    currentLoginBudget()?.require("credential");
    if (attempt > 1) {
      const pause = 1500 + (attempt - 2) * 400 + Math.floor(Math.random() * 2000);
      console.log(JSON.stringify({
        event: "reddit_capsolver_retry_wait",
        attempt,
        attempts: REDDIT_CAPSOLVER_ATTEMPTS,
        pauseMs: pause,
      }));
      await loginSleep(pause);
    }
    let solved;
    try {
      solved = await capsolverSolveRedditEnterprise();
    } catch (err) {
      currentLoginBudget()?.check();
      if (err?.code === "attempts_exhausted") throw err;
      lastSoft = String(err?.message || err);
      console.log(JSON.stringify({
        event: "reddit_capsolver_mint_failed",
        attempt,
        attempts: REDDIT_CAPSOLVER_ATTEMPTS,
        failureType: "solver_error",
      }));
      continue;
    }
    await applyCapsolverSessionCookies(context, solved.cookies);

    const cookies = await context.cookies();
    const csrf = cookies.find((c) => c.name === "csrf_token" && c.domain.includes("reddit"))?.value;
    if (!csrf) {
      lastSoft = "csrf_token missing after login page prime";
      console.log(JSON.stringify({ event: "reddit_capsolver_missing_csrf", attempt }));
      continue;
    }

    const body = new URLSearchParams({
      username: String(username || ""),
      password: String(password || ""),
      otp: String(otp || ""),
      dest: "https://www.reddit.com",
      csrf_token: csrf,
      recaptcha_token: solved.token,
    });
    const headers = {
      "content-type": "application/x-www-form-urlencoded",
      origin: "https://www.reddit.com",
      referer: "https://www.reddit.com/login/",
      accept: "text/vnd.reddit.partial+html, application/json",
      "accept-language": "en-US,en;q=0.9",
    };
    if (solved.userAgent) headers["user-agent"] = solved.userAgent;

    let resp;
    let raw = "";
    try {
      // Prefer form encoding so Playwright sets the body correctly; keep the
      // explicit content-type header for shreddit's faceplate-form contract.
      credentialSubmission();
      resp = await context.request.post("https://www.reddit.com/svc/shreddit/account/login", {
        headers,
        form: Object.fromEntries(body.entries()),
        timeout: 60000,
        failOnStatusCode: false,
      });
      raw = await resp.text().catch(() => "");
    } catch (err) {
      currentLoginBudget()?.check();
      if (err?.code === "attempts_exhausted") throw err;
      if (isHardProxyTunnelError(err?.message)) throw err;
      lastSoft = String(err?.message || err);
      console.log(JSON.stringify({
        event: "reddit_capsolver_post_failed",
        attempt,
        failureType: "transport_error",
      }));
      continue;
    }

    const status = resp.status();
    const errMatch = /"errors"\s*:\s*\[\s*\[\s*"([A-Z_]+)"/.exec(raw);
    const errCode = errMatch?.[1] || "";
    const low = raw.toLowerCase();
    console.log(JSON.stringify({
      event: "reddit_capsolver_login_post",
      attempt,
      status,
      errCode: errCode || null,
      bodyLen: raw.length,
    }));

    if (errCode === "WRONG_PASSWORD" || errCode === "INCORRECT_USERNAME_PASSWORD") {
      return redditLoginResult(await context.cookies(), page.url(), {
        hints: ["incorrect username or password"],
      });
    }
    if (errCode === "RATELIMIT" || status === 429) {
      return redditLoginResult(await context.cookies(), page.url(), {
        hints: ["try again later", "you did this too many times"],
      });
    }
    if (
      errCode.includes("OTP") ||
      /two-factor|2fa|verification code|otp/i.test(raw)
    ) {
      return redditLoginResult(await context.cookies(), page.url(), {
        hints: ["verification_code_required"],
      });
    }
    if (errCode) {
      lastSoft = `reddit login failed (${errCode})`;
      continue;
    }

    // Navigate home so Reddit finishes minting an authenticated token_v2 on
    // top of reddit_session (parity with browser post-login).
    await page.goto("https://www.reddit.com/", { waitUntil: "domcontentloaded", timeout: 60000 }).catch(() => {});
    const deadline = Math.min(Date.now() + 20000, currentLoginBudget()?.deadline ?? Infinity);
    while (Date.now() < deadline) {
      const cks = await context.cookies();
      const session = cks.find((c) => c.name === "reddit_session" && c.domain.includes("reddit"));
      const token = cks.find((c) => c.name === "token_v2" && c.domain.includes("reddit"));
      if (session?.value && token && isAuthenticatedRedditToken(token.value)) {
        console.log(JSON.stringify({
          event: "reddit_capsolver_login_ok",
          attempt,
          attempts: REDDIT_CAPSOLVER_ATTEMPTS,
        }));
        return redditLoginResult(cks, page.url(), { ok: true });
      }
      await page.waitForTimeout(1000);
    }

    const after = await context.cookies();
    const hasSession = after.some((c) => c.name === "reddit_session" && c.domain.includes("reddit") && c.value);
    if (!hasSession) {
      lastSoft = `login did not establish a session (status ${status})`;
      console.log(JSON.stringify({
        event: "reddit_capsolver_soft_reject",
        attempt,
        status,
        failureType: "login_rejected",
      }));
      continue;
    }
    // Session cookie present but token_v2 still anonymous — treat as soft
    // risk reject and retry with a fresh CapSolver token.
    lastSoft = "reddit_session without authenticated token_v2";
  }

  console.log(JSON.stringify({
    event: "reddit_capsolver_exhausted",
    attempts: REDDIT_CAPSOLVER_ATTEMPTS,
    failureType: "captcha_required",
  }));
  return redditLoginResult(await context.cookies(), page.url(), {
    hints: ["captcha_required", lastSoft].filter(Boolean),
  });
}

// loginReddit drives Reddit's web login. Prefer CapSolver Enterprise token +
// shreddit POST (smore parity) when RECAPTCHA_SOLVER_API_KEY is set — cold
// browser-only profiles routinely fail silent Enterprise risk checks. Without
// CapSolver, fall back to the warmed-profile in-page click path.
// Returns the reddit_session + token_v2 cookies the Go client reuses.
async function loginReddit({ username, password, totpSecret, verificationCode }, proxyUrl, profileKey) {
  const { context, page, close, persistent } = await openLoginSession({ proxyUrl, profileKey });
  try {
    const bodyText = () => page.locator("body").innerText().catch(() => "");
    if (persistent) {
      await page.goto("https://www.reddit.com/", { waitUntil: "domcontentloaded", timeout: 60000 }).catch(() => {});
      await page.waitForTimeout(4000);
    }
    // A warmed persistent profile may still carry a prior (possibly expired)
    // Reddit auth session. Since reddit.go re-mints on every cold start, clear
    // the auth/session cookies so we always log in fresh and never report a
    // stale token_v2 as success — while preserving device-trust cookies
    // (cf_clearance, Castle/device ids) that make the profile look returning.
    const redditAuthCookies = ["token_v2", "reddit_session", "loid", "session", "session_tracker"];
    for (const domain of [".reddit.com", "reddit.com", ".www.reddit.com", "www.reddit.com"]) {
      for (const name of redditAuthCookies) {
        await context.clearCookies({ name, domain }).catch(() => {});
      }
    }
    // Verify the critical cookie is actually gone — if clearCookies silently
    // no-op'd (attribute mismatch), the stale token_v2 would be reported as a
    // successful fresh login.
    const staleCookies = (await context.cookies()).filter(
      (c) => c.name === "token_v2" && c.domain.includes("reddit")
    );
    if (staleCookies.length > 0) {
      // Prefer surgical wipe: drop auth cookies by filtering, keep cf_clearance /
      // device-trust. Nuclear clearCookies() destroys returning-profile trust.
      const keep = (await context.cookies()).filter(
        (c) => !(c.domain.includes("reddit") && redditAuthCookies.includes(c.name)),
      );
      await context.clearCookies().catch(() => {});
      if (keep.length > 0) {
        await context.addCookies(keep).catch(() => {});
      }
    }
    await page.goto("https://www.reddit.com/login/", { waitUntil: "domcontentloaded", timeout: 60000 });
    // Reddit fronts /login/ with a JS verification interstitial; wait for the
    // real username field rather than racing a fixed timeout.
    await page.waitForSelector('input[name="username"]', { state: "visible", timeout: 45000 });

    const otp = totpSecret ? totpNow(totpSecret) : String(verificationCode || "").trim();
    if (CAPSOLVER_API_KEY) {
      return await loginRedditViaCapSolver(context, page, { username, password, otp });
    }

    if (!(await typeFirst(page, ['input[name="username"]'], username))) throw new Error("username field not found");
    if (!(await typeFirst(page, ['input[name="password"]'], password))) throw new Error("password field not found");
    if (!(await clickByText(page, [/^log in$/i, /^login$/i], credentialSubmission))) {
      const sub = page.locator('button[type="submit"]').first();
      if (await sub.count().catch(() => 0)) { credentialSubmission(); await sub.click({ timeout: 8000 }).catch(() => {}); }
      else { credentialSubmission(); await page.keyboard.press("Enter").catch(() => {}); }
    }

    // token_v2 is what the Go client hard-requires (the bearer). BUT Reddit
    // sets a token_v2 cookie even for LOGGED-OUT sessions — an anonymous app
    // bearer whose JWT sub is "loid". Its mere presence is NOT login success:
    // returning it yields a token that 401s on user REST (/api/v1/me → empty)
    // and Matrix whoami (M_UNKNOWN_TOKEN) — exactly the #444 failure. Treat the
    // login as successful only when token_v2 is an AUTHENTICATED user token
    // (sub present and != "loid"). This is cookie-name independent and robust
    // to Reddit setting/replacing the anon token on every page load.
    const has = async () => {
      const c = (await context.cookies()).find((ck) => ck.name === "token_v2");
      return c ? isAuthenticatedRedditToken(c.value) : false;
    };
    // Optional 2FA: Reddit prompts for a 6-digit authenticator code after
    // password when the account has TOTP enabled. The connect card no longer
    // collects a TOTP secret; callers may still pass totpSecret or a live
    // verificationCode from the follow-up prompt. When an OTP field appears
    // with neither available, surface verification_code_required so the Go
    // layer returns verification_required and the client/agent collects a code.
    const otpSel = 'input[name="otp"]:visible, input[autocomplete="one-time-code"]:visible, input[name="verificationCode"]:visible';
    const canDo2FA = Boolean(totpSecret || verificationCode);
    // A pasted code is single-use; a stored secret can mint a fresh code each
    // attempt. Re-submit (with a newly computed TOTP) at most once per ~15s so a
    // code that expired mid-window, or a submit delayed by reCAPTCHA, gets
    // another chance instead of consuming the only attempt.
    let last2FAAt = 0;
    let needsVerification = false;
    let ok = false;
    // Wait long enough for the post-submit redirect + reCAPTCHA + the user
    // token_v2 to replace the anonymous one. The old 35s budget was effectively
    // never used because the loop broke immediately on the anon token.
    const deadline = Math.min(Date.now() + 60000, currentLoginBudget()?.deadline ?? Infinity);
    while (Date.now() < deadline) {
      if (await has()) { ok = true; break; }
      // Only bail on genuine terminal failures. Do NOT treat "verify you are
      // human" as fatal: Reddit shows that copy while the in-page reCAPTCHA is
      // still running, which the warmed profile is meant to clear.
      const body = await bodyText();
      if (/incorrect username or password|you did this too many times|try again later/i.test(body)) break;
      // Wrong pasted code (no stored secret to mint a fresh one): ask again
      // rather than treating it as a terminal credential failure.
      if (/wrong.*(code|token)/i.test(body) && !totpSecret) {
        needsVerification = true;
        break;
      }
      const otpField = page.locator(otpSel).first();
      const otpVisible = Boolean(await otpField.count().catch(() => 0));
      if (otpVisible && !canDo2FA) {
        // OTP challenge with no code/secret yet — stop waiting and ask the user.
        needsVerification = true;
        break;
      }
      const canRetry2FA = totpSecret ? Date.now() - last2FAAt > 15000 : last2FAAt === 0;
      if (canDo2FA && canRetry2FA && otpVisible) {
        // Prefer a freshly computed TOTP from the stored secret over a
        // possibly-stale pasted code; fall back to the pasted code only when
        // no secret is available.
        const code = totpSecret ? totpNow(totpSecret) : verificationCode;
        await otpField.fill(code).catch(() => {});
        if (!(await clickByText(page, [/^log in$/i, /^login$/i, /^verify$/i, /^continue$/i, /^submit$/i]))) {
          await page.keyboard.press("Enter").catch(() => {});
        }
        last2FAAt = Date.now();
      }
      await page.waitForTimeout(1500);
    }

    const cks = await context.cookies();
    let hints = [];
    if (!ok) {
      const body = await bodyText();
      if (needsVerification) {
        hints.push("verification_code_required");
      }
      const more = body.split("\n").map((l) => l.trim()).filter((l) => l && /incorrect|wrong|too many|try again|verify|captcha|locked|code/i.test(l)).slice(0, 6);
      hints = [...new Set([...hints, ...more])];
      // Silent Enterprise reCAPTCHA / risk reject: still on /login/, no auth
      // token_v2, and no wrong-password copy. Surface captcha_required so the
      // UI asks to retry rather than claiming the password is wrong.
      const stillLogin = /reddit\.com\/login/i.test(page.url());
      const anon = cks.find((c) => c.name === "token_v2" && c.domain.includes("reddit"));
      const wrongPassword = /incorrect username or password/i.test(body);
      if (
        !needsVerification &&
        !wrongPassword &&
        (stillLogin || (anon && !isAuthenticatedRedditToken(anon.value)))
      ) {
        hints.push("captcha_required");
      }
    }
    return redditLoginResult(cks, page.url(), { ok, hints });
  } finally {
    await close();
  }
}

const BROWSER_LOGIN_RECIPES = {
  instagram: {
    run: ({ username, password, verificationCode }, proxyUrl, profileKey) =>
      loginMeta("instagram", { username, password, verificationCode }, proxyUrl, profileKey),
  },
  facebook: {
    run: ({ username, password, verificationCode }, proxyUrl, profileKey) =>
      loginMeta("facebook", { username, password, verificationCode }, proxyUrl, profileKey),
  },
  linkedin: {
    run: ({ username, password, verificationCode, challengeHold }, proxyUrl, profileKey) =>
      loginLinkedIn({ username, password, verificationCode, challengeHold }, proxyUrl, profileKey),
  },
  x: {
    run: ({ username, password, verificationCode, challengeHold }, proxyUrl, profileKey) =>
      loginX({ username, password, verificationCode, challengeHold }, proxyUrl, profileKey),
  },
  tiktok: {
    run: ({ username, password, verificationCode }, proxyUrl, profileKey) =>
      loginTikTok({ username, password, verificationCode }, proxyUrl, profileKey),
  },
  reddit: {
    run: ({ username, password, totpSecret, verificationCode }, proxyUrl, profileKey) =>
      loginReddit({ username, password, totpSecret, verificationCode }, proxyUrl, profileKey),
  },
};

export { classifyLinkedInScreen, isHardProxyTunnelError, shouldReuseLinkedInSession };
export const hasBrowserLoginRecipe = (platform) => Boolean(BROWSER_LOGIN_RECIPES[platform]);

async function runBrowserLogin(platform, input, proxyUrl, profileKey, signal) {
  const recipe = BROWSER_LOGIN_RECIPES[platform];
  if (!recipe) throw new Error("unknown platform " + platform);
  const code = String(input.verificationCode || "").trim();
  const profileFlightKey = `${platform}:${sanitizeProfileKey(profileKey)}`;
  const requestFingerprint = crypto.createHash("sha256").update(JSON.stringify({
    platform,
    username: String(input.username || ""),
    password: String(input.password || ""),
    totpSecret: String(input.totpSecret || ""),
    proxyUrl: String(proxyUrl || ""),
  })).digest("hex");
  if (!code && freshLoginFlights.has(profileFlightKey)) {
    const current = freshLoginFlights.get(profileFlightKey);
    if (current.fingerprint === requestFingerprint) {
      logLoginEvent("login_deduplicated", { platform, profileKey, credentialAttempted: false });
      return current.promise;
    }
    logLoginEvent("login_conflict", {
      platform, profileKey, failureType: "login_in_progress", credentialAttempted: false,
    });
    return {
      ok: false,
      failureType: "login_in_progress",
      retryable: true,
      credentialAttempted: false,
      hints: ["A different login attempt is already active for this profile."],
    };
  }
  const cancelled = () => Boolean(signal?.aborted);
  const admission = await acquireChallengeAdmission(platform, profileKey, code, cancelled, signal, input.challengeHold);
  if (cancelled()) {
    admission.release();
    throw new AdmissionError("request_cancelled", "request cancelled before browser login");
  }
  if (admission.held) input = { ...input, challengeHold: admission.held };
  const recipeFlight = withProfileLock(profileKey, () => {
    currentLoginBudget()?.check();
    if (input.challengeHold) currentLoginBudget()?.bind(() => input.challengeHold.close("cancelled"));
    return recipe.run(input, proxyUrl, profileKey).then((result) => {
      if (result.browserHold) {
        const hold = result.browserHold;
        if (!hold.capacityClose) {
          const close = hold.close;
          hold.capacityClose = true;
          hold.close = async (reason) => {
            try { await close(reason); }
            finally { serviceHolds.delete(hold); dispatchAdmissions(); }
          };
          hold.context?.once("close", () => { hold.closed = true; trackedSessions.delete(hold); serviceHolds.delete(hold); dispatchAdmissions(); });
        }
        serviceHolds.add(hold);
      }
      return result;
    });
  })
    .finally(admission.release);
  const flight = recipeFlight;
  if (!code) {
    freshLoginFlights.set(profileFlightKey, { fingerprint: requestFingerprint, promise: flight });
    flight.finally(() => {
      if (freshLoginFlights.get(profileFlightKey)?.promise === flight) freshLoginFlights.delete(profileFlightKey);
    }).catch(() => {});
  }
  return flight;
}

async function readiness() {
  const reasons = [];
  let processCount = -1;
  if (!accepting) reasons.push("admission_closed");
  if (process.platform === "linux" && !process.env.DISPLAY && !HEADLESS) reasons.push("display_unset");
  if (process.platform === "linux" && !HEADLESS) {
    try {
      await execFileAsync("xdpyinfo", [], { timeout: 1500, env: process.env });
    } catch {
      reasons.push("xvfb_unreachable");
    }
  }
  if (process.platform !== "win32") try {
    const { stdout } = await execFileAsync("ps", ["-e", "-o", "pid="], { timeout: 1500 });
    processCount = stdout.trim() ? stdout.trim().split(/\n/).length : 0;
    if (processCount >= MAX_PROCESSES) reasons.push("process_threshold");
  } catch {
    reasons.push("process_count_unavailable");
  }
  if (reasons.length) telemetry("health_failed", { reasons, processCount, maxProcesses: MAX_PROCESSES });
  return { ok: reasons.length === 0, reasons, processCount };
}

function loginHTTPStatus(out) {
  if (out.ok) return 200;
  if (out.rateLimited) return 429;
  if (out.failureType === "login_in_progress") return 409;
  if (out.failureType === "service_unavailable") return 503;
  return 401;
}

function drainRuntime({ closeServer = () => new Promise((resolve) => server.close(resolve)), timeoutMs = 25_000 } = {}) {
  if (drainPromise) return drainPromise;
  drainPromise = (async () => {
    const deadline = Date.now() + timeoutMs;
    draining = true;
    logLoginEvent("drain_start", { activeRequests, holds: challengeHolds.size });
    const serverClosed = Promise.resolve().then(closeServer).catch(() => {});
    while ((activeRequests > 0 || challengeHolds.size > 0) && Date.now() < deadline) {
      const holdClosures = Promise.all([...challengeHolds.keys()].map((key) => {
        const separator = key.indexOf(":");
        return releaseChallengeHold(key.slice(0, separator), key.slice(separator + 1));
      }));
      await Promise.race([
        holdClosures,
        new Promise((resolve) => setTimeout(resolve, Math.max(0, deadline - Date.now()))),
      ]);
      if (activeRequests === 0 && challengeHolds.size === 0) break;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    await Promise.race([serverClosed, new Promise((resolve) => setTimeout(resolve, Math.max(0, deadline - Date.now())))]);
    logLoginEvent("drain_complete", { activeRequests, holds: challengeHolds.size });
    return { activeRequests };
  })();
  return drainPromise;
}

export const __test = {
  extractLinkedInVoyagerQueryIDs,
  discoverLinkedInVoyagerQueryIDs,
  linkedinQueryIDCache,
  runBrowserLogin,
  loginLinkedIn,
  prewarmX,
  harvestX,
  runProfileHarvest,
  openLoginSession,
  loginRedditViaCapSolver,
  xClick,
  launchPersistentContextWithRecovery,
  parkChallengeHold,
  takeChallengeHold,
  releaseChallengeHold,
  drainRuntime,
  readiness,
  loginHTTPStatus,
  attachLoginMeta,
  serializeLoginResult(out, meta) {
    return JSON.stringify(attachLoginMeta({ ...out }, meta));
  },
  setRecipe(platform, run) {
    const previous = BROWSER_LOGIN_RECIPES[platform];
    BROWSER_LOGIN_RECIPES[platform] = { run };
    return () => { BROWSER_LOGIN_RECIPES[platform] = previous; };
  },
  reset() {
    accepting = true;
    shuttingDown = false;
    draining = false;
    activeRequests = 0;
    drainPromise = null;
    freshLoginFlights.clear();
  },
  state: () => ({ draining, activeRequests, holds: challengeHolds.size + serviceHolds.size, activeAdmissions }),
};
