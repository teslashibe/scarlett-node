import { __test as defaultRuntime, hasBrowserLoginRecipe } from "./runtime/legacy.js";
import { ServiceError, statusForLogin } from "./http/errors.js";
import { ProfileLocks, ProfileStore } from "./runtime/profiles.js";
import { parseProxyURL } from "./proxy/parse.js";
import { profileID } from "./runtime/profiles.js";
import { PlatformRegistry } from "./platforms/registry.js";
import { ChallengeStore } from "./runtime/challenges.js";
import { BrowserHoldRegistry } from "./runtime/browser-holds.js";
import { LoginBudget, loginBudgetScope } from "./runtime/login-budget.js";
import { isHardProxyTunnelError } from "./runtime/legacy.js";

const integer = (name, fallback, minimum = 1) =>
  Math.max(minimum, Number.parseInt(process.env[name] || `${fallback}`, 10) || fallback);

export class SocialLoginService {
  #sessions = new Map();
  #locks = new ProfileLocks();
  #registry = new PlatformRegistry();
  #challenges = new ChallengeStore();
  #browserHolds = new BrowserHoldRegistry();
  #profiles = new ProfileStore({ locks: this.#locks, challenges: this.#challenges });
  #prewarms = new Map();
  #runtime;
  #budgets = new Set();
  #draining = false;

  constructor({ runtime = defaultRuntime } = {}) {
    this.#runtime = runtime;
    this.#registry = new PlatformRegistry(runtime);
    this.#profiles.start();
  }

  platforms() {
    return this.#registry.names();
  }

  capabilities() {
    return { recovery_budget: 1, profile_harvest: ["x", "reddit"], interactive_x: 1 };
  }

  health() {
    return { status: "ok", profiles: this.#profiles.metrics() };
  }

  async ready() {
    const runtimeReady = await this.#runtime.readiness();
    const ready = !this.#draining && runtimeReady.ok;
    return {
      status: ready ? "ready" : (this.#draining ? "draining" : "unavailable"),
      sessions: this.#sessions.size,
      challenges: this.#challenges.size(),
      reasons: runtimeReady.reasons,
      profiles: this.#profiles.metrics(),
    };
  }

  async login(request, signal) {
    const budget = new LoginBudget(request.budget, [signal]);
    this.#budgets.add(budget);
    try {
      const response = await loginBudgetScope.run(budget, () => this.#login(request, budget));
      response.result.attempts = { ...budget.attempts };
      response.result.deadline_at = new Date(budget.deadline).toISOString();
      return response;
    } catch (error) {
      if (error instanceof ServiceError || error?.name === "AdmissionError") {
        error.details = { attempts: { ...budget.attempts }, deadline_at: new Date(budget.deadline).toISOString() };
        throw error;
      }
      const result = {
        ok: false,
        failureType: isHardProxyTunnelError(error?.message) ? "proxy_error" : "login_failed",
        retryable: true,
        attempts: { ...budget.attempts },
        deadline_at: new Date(budget.deadline).toISOString(),
      };
      this.#runtime.attachLoginMeta(result, { proxyUrl: request.proxy_url, status: 503 });
      return { status: 503, result };
    } finally {
      await budget.dispose();
      this.#budgets.delete(budget);
    }
  }

  async #login(request, budget) {
    const signal = budget.signal;
    budget.check();
    if (this.#draining) throw new ServiceError("shutting_down", "service is shutting down", 503);
    if (signal?.aborted) throw new ServiceError("request_cancelled", "request was cancelled", 499);
    const platform = String(request.platform || "");
    const recipe = this.#registry.get(platform);
    if (!recipe || !hasBrowserLoginRecipe(platform)) {
      throw new ServiceError("unsupported_platform", `unsupported platform: ${platform}`, 400);
    }
    const username = String(request.username || "");
    const password = String(request.password || "");
    const profileKey = String(request.profile_key || "");
    const challengeID = String(request.challenge_id || "");
    const verificationCode = String(request.verification_code || "");
    const harvest = !challengeID && !username && !password;
    if (!profileKey || (!challengeID && !harvest && (!username || !password))) {
      throw new ServiceError("invalid_request", "profile_key and either credentials, challenge_id, or harvest (empty credentials) are required", 400);
    }
    if (harvest && !["x", "reddit"].includes(platform)) {
      throw new ServiceError("unsupported_platform", `profile harvest unsupported for platform: ${platform}`, 400);
    }
    const proxy = parseProxyURL(request.proxy_url);
    const proxyURL = proxy?.url || "";
    const proxyLease = String(request.proxy_lease || "");
    const owner = {
      ownerToken: String(request.operation_owner || ""),
      connectionID: String(request.connection_id || ""),
      generation: String(request.generation || ""),
      revision: String(request.revision || ""),
      recoveryClaim: String(request.recovery_claim || ""),
    };
    if (Object.values(owner).some((value) => !value)) {
      throw new ServiceError("invalid_operation_owner", "complete operation owner binding is required", 400);
    }
    if (proxy && !proxyLease) {
      throw new ServiceError("invalid_request", "proxy_lease is required when proxy_url is set", 400);
    }
    if (challengeID && !verificationCode) {
      throw new ServiceError("invalid_request", "verification_code is required for continuation", 400);
    }
    let held;
    if (challengeID) {
      try {
        held = this.#challenges.claimContinuation(challengeID, { platform, profileKey, proxyLease, proxyURL, ...owner });
      } catch (error) {
        if (error.code === "attempts_exhausted") await this.#browserHolds.release(owner.ownerToken, "attempts_exhausted");
        throw error;
      }
    }
    if (!held && (this.#challenges.hasProfile(platform, profileKey) || this.#browserHolds.hasProfile(platform, profileKey))) {
      throw new ServiceError("profile_busy", "profile is awaiting challenge continuation", 409);
    }
    let releaseProfile;
    let browserHold;
    const session = Symbol("login");
    try {
      releaseProfile = this.#locks.acquire(platform, profileKey);
      await this.#profiles.admit(platform, profileKey);
      if (held) {
        budget.restore(held.budgetState);
        budget.follow(this.#challenges.signal(held.ownerToken));
        budget.capDeadline(held.expiresAt);
      }
      budget.check();
      if (held) {
        browserHold = this.#browserHolds.take(held.ownerToken);
        if (platform === "x" && !browserHold) throw new ServiceError("challenge_not_found", "challenge browser is missing or closed", 404);
      }
      const operation = harvest
        ? this.#runtime.runProfileHarvest(platform, proxyURL, profileID(platform, profileKey), signal)
        : recipe.login({
          username: held?.credentials.username || username,
          password: held?.credentials.password || password,
          totpSecret: held?.credentials.totpSecret || request.totp_secret,
          verificationCode,
          challengeHold: browserHold,
        }, proxyURL, profileID(platform, profileKey), signal);
      this.#sessions.set(session, operation);
      const result = await operation;
      budget.check();
      this.#runtime.attachLoginMeta(result, { proxyUrl: request.proxy_url, status: statusForLogin(result) });
      if (result.challenge) {
        try {
          result.challenge = this.#challenges.create(
            { platform, profileKey, proxyLease, proxyURL, ...owner },
            held?.credentials || { username, password },
            result,
            budget.deadline,
            budget.snapshot(),
          );
          if (result.browserHold) {
            const browser = result.browserHold;
            await this.#browserHolds.park(owner.ownerToken,
              { platform, profileKey }, browser,
              Math.max(1, Date.parse(result.challenge.expires_at) - Date.now()));
            if (!browser.serviceCloseBound && browser.context?.once) {
              browser.serviceCloseBound = true;
              browser.context.once("close", () => {
                if (!this.#browserHolds.hasOwner(owner.ownerToken)) return;
                this.#challenges.cancel(owner.ownerToken, { platform, profileKey, proxyLease, proxyURL, ...owner });
                void this.#browserHolds.release(owner.ownerToken, "browser_closed").catch(() => {});
              });
            }
            delete result.browserHold;
          }
        } catch (error) {
          this.#challenges.cancel(owner.ownerToken,
            { platform, profileKey, proxyLease, proxyURL, ...owner });
          await Promise.resolve(result.browserHold?.close("challenge_rejected")).catch(() => {});
          throw error;
        }
      } else if (challengeID) {
        this.#challenges.consume(challengeID);
        this.#challenges.settle(owner.ownerToken, "completed");
      }
      if (result.ok || challengeID || result.reused) this.#profiles.touch(platform, profileKey);
      return { status: statusForLogin(result), result };
    } catch (error) {
      if (challengeID) {
        this.#challenges.consume(challengeID);
        this.#challenges.settle(owner.ownerToken, signal?.aborted ? "cancelled" : "failed");
        await Promise.resolve(browserHold?.close("continuation_failed")).catch(() => {});
        await this.#browserHolds.release(owner.ownerToken, "continuation_failed").catch(() => {});
      }
      budget.check();
      if (error instanceof ServiceError) throw error;
      if (error?.name === "AdmissionError") {
        throw new ServiceError(error.code, error.message, error.statusCode);
      }
      throw error;
    } finally {
      this.#sessions.delete(session);
      releaseProfile?.();
    }
  }

  async prewarm(request, signal) {
    if (this.#draining) throw new ServiceError("shutting_down", "service is shutting down", 503);
    const forbidden = ["username", "password", "totp_secret", "verification_code"];
    if (forbidden.some((field) => Object.hasOwn(request, field))) {
      throw new ServiceError("credentials_forbidden", "prewarm requests cannot contain credentials", 400);
    }
    const platform = String(request.platform || "");
    const profileKey = String(request.profile_key || "");
    const proxyLease = String(request.proxy_lease || "");
    const generation = Number(request.proxy_generation);
    const connectionID = String(request.connection_id || "");
    const claim = String(request.claim || "");
    if (platform !== "x" || !profileKey || !proxyLease || !Number.isSafeInteger(generation) || generation < 0 || !connectionID || !claim) {
      throw new ServiceError("invalid_request", "complete x prewarm identity is required", 400);
    }
    const proxy = parseProxyURL(request.proxy_url);
    if (!proxy) throw new ServiceError("invalid_request", "proxy_url is required", 400);
    const key = `${platform}\0${profileKey}\0${generation}\0${proxyLease}\0${proxy.url}\0${connectionID}\0${claim}`;
    const existing = this.#prewarms.get(key);
    if (existing) {
      const value = await existing;
      if (Date.parse(value.expires_at) > Date.now()) return { ...value, reused: true };
      if (this.#prewarms.get(key) === existing) this.#prewarms.delete(key);
      else return { ...(await this.#prewarms.get(key)), reused: true };
    }
    if (this.#challenges.hasProfile(platform, profileKey) || this.#browserHolds.hasProfile(platform, profileKey)) {
      throw new ServiceError("profile_busy", "profile is awaiting challenge continuation", 409);
    }
    const operation = (async () => {
      await this.#profiles.admit(platform, profileKey);
      const result = await this.#runtime.prewarmX(proxy.url, profileID(platform, profileKey), signal);
      const warmedAt = new Date();
      return {
        platform, profile_key: profileKey, proxy_lease: proxyLease,
        proxy_generation: generation, connection_id: connectionID, claim,
        warmed_at: warmedAt.toISOString(),
        expires_at: new Date(warmedAt.getTime() + integer("SOCIAL_LOGIN_PREWARM_TTL_MS", 86_400_000)).toISOString(),
        reused: false,
        diagnostics: [result.persistent ? "persistent_profile" : "ephemeral_profile"],
      };
    })();
    this.#prewarms.set(key, operation);
    try {
      const value = await operation;
      const ttl = Math.max(1, Date.parse(value.expires_at) - Date.now());
      const timer = setTimeout(() => {
        if (this.#prewarms.get(key) === operation) this.#prewarms.delete(key);
      }, ttl);
      timer.unref?.();
      return value;
    } catch (error) {
      if (this.#prewarms.get(key) === operation) this.#prewarms.delete(key);
      throw error;
    }
  }

  challengeStatus(request) {
    return this.#challenges.status(String(request.operation_owner || ""), this.#challengeIdentity(request));
  }

  async cancelChallenge(request) {
    const ownerToken = String(request.operation_owner || "");
    const result = this.#challenges.cancel(ownerToken, this.#challengeIdentity(request));
    await this.#browserHolds.release(ownerToken, "cancelled");
    return result;
  }

  #challengeIdentity(request) {
    const proxy = parseProxyURL(request.proxy_url);
    return {
      platform: String(request.platform || ""),
      profileKey: String(request.profile_key || ""),
      proxyLease: String(request.proxy_lease || ""),
      proxyURL: proxy?.url || "",
      ownerToken: String(request.operation_owner || ""),
      connectionID: String(request.connection_id || ""),
      generation: String(request.generation || ""),
      revision: String(request.revision || ""),
      recoveryClaim: String(request.recovery_claim || ""),
    };
  }

  async erase(request) {
    if (this.#draining) throw new ServiceError("shutting_down", "service is shutting down", 503);
    const platform = String(request.platform || "");
    if (!this.#registry.get(platform)) {
      throw new ServiceError("unsupported_platform", `unsupported platform: ${platform}`, 400);
    }
    const profileKey = String(request.profile_key || "");
    if (!profileKey) throw new ServiceError("invalid_request", "profile_key is required", 400);
    const releaseGuard = this.#challenges.claimProfileForErase(platform, profileKey);
    try {
      this.#challenges.cancelProfile(platform, profileKey);
      await this.#browserHolds.releaseProfile(platform, profileKey, "profile_erased");
      return await this.#profiles.erase(platform, profileKey);
    } finally {
      releaseGuard();
    }
  }

  async shutdown(timeoutMs = integer("SOCIAL_LOGIN_SHUTDOWN_TIMEOUT_MS", 30_000)) {
    if (this.#draining) return;
    this.#draining = true;
    this.#profiles.close();
    this.#challenges.close();
    for (const budget of this.#budgets) budget.abort();
    const deadline = Date.now() + timeoutMs;
    await Promise.race([
      Promise.allSettled([
        this.#browserHolds.close(),
        ...this.#sessions.values(),
        this.#runtime.drainRuntime({ closeServer: async () => {}, timeoutMs }),
      ]),
      new Promise((resolve) => setTimeout(resolve, Math.max(0, deadline - Date.now()))),
    ]);
  }
}
