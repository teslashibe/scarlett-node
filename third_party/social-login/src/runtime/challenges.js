import crypto from "node:crypto";
import { ServiceError } from "../http/errors.js";
import { profileID } from "./profiles.js";
import { SystemClock } from "./clock.js";

const integer = (name, fallback, minimum = 1) =>
  Math.max(minimum, Number.parseInt(process.env[name] || `${fallback}`, 10) || fallback);

export class LoginOperationRegistry {
  #items = new Map();
  #ttlMs;
  #capacity;
  #maxAttempts;
  #maxResends;
  #operations = new Map();
  #profileGuards = new Set();
  #closed = false;
  #clock;

  constructor({
    ttlMs = integer("SOCIAL_LOGIN_CHALLENGE_TTL_MS", 10 * 60_000),
    capacity = integer("SOCIAL_LOGIN_MAX_CHALLENGES", 16),
    maxAttempts = integer("SOCIAL_LOGIN_MAX_OTP_ATTEMPTS", 5),
    maxResends = integer("SOCIAL_LOGIN_MAX_OTP_RESENDS", 3),
    clock = new SystemClock(),
  } = {}) {
    this.#ttlMs = ttlMs;
    this.#capacity = capacity;
    this.#maxAttempts = maxAttempts;
    this.#maxResends = maxResends;
    this.#clock = clock;
  }

  create(identity, credentials, result, deadline = Infinity, budgetState) {
    if (this.#closed) throw new ServiceError("shutting_down", "service is shutting down", 503);
    this.#purge();
    if (this.#profileGuards.has(profileID(identity.platform, identity.profileKey))) {
      throw new ServiceError("profile_erasing", "profile erasure is in progress", 409);
    }
    const ownerToken = String(identity.ownerToken || "");
    if (ownerToken.length < 32) throw new ServiceError("invalid_operation_owner", "opaque operation owner is required", 400);
    const prior = this.#operations.get(ownerToken);
    if (prior?.cancelRequested || ["cancelled", "expired"].includes(prior?.state)) {
      throw new ServiceError("operation_in_flight", "operation has not settled", 409);
    }
    if (prior?.challengeID) {
      const current = this.#items.get(prior.challengeID);
      if (current) this.#assertOwner(current, identity);
    }
    if (this.#items.size >= this.#capacity && !prior?.challengeID) {
      throw new ServiceError("challenge_capacity", "verification capacity is full", 503);
    }
    const resends = (prior?.resends || 0) + (prior ? 1 : 0);
    if (resends > this.#maxResends) throw new ServiceError("resends_exhausted", "verification resend budget exhausted", 429);
    if (prior?.challengeID) {
      const old = this.#items.get(prior.challengeID);
      if (old) {
        this.#clock.clearTimeout(old.timer);
        this.#items.delete(prior.challengeID);
      }
    }
    const id = crypto.randomBytes(32).toString("base64url");
    const expiresAt = Math.min(this.#clock.now() + this.#ttlMs, prior?.expiresAt ?? Infinity, deadline);
    const timer = this.#clock.setTimeout(() => this.#expire(id), Math.max(0, expiresAt - this.#clock.now()));
    this.#items.set(id, {
      ...identity,
      profileID: profileID(identity.platform, identity.profileKey),
      credentials,
      budgetState,
      expiresAt,
      timer,
      attempts: prior?.attempts || 0,
      resends,
    });
    const operation = prior || this.#newOperation(identity);
    Object.assign(operation, {
      challengeID: id, attempts: operation.attempts, resends, expiresAt, state: "challenged",
    });
    this.#operations.set(ownerToken, operation);
    return {
      id,
      expires_at: new Date(expiresAt).toISOString(),
      method: result.challengeMethod || "verification_code",
      ...(result.maskedDestination ? { masked_destination: result.maskedDestination } : {}),
    };
  }

  claimContinuation(id, identity) {
    if (this.#profileGuards.has(profileID(identity.platform, identity.profileKey))) {
      throw new ServiceError("profile_erasing", "profile erasure is in progress", 409);
    }
    const key = String(id || "");
    const held = this.#items.get(key);
    if (!held || held.expiresAt <= this.#clock.now()) {
      if (held) this.#expire(key);
      throw new ServiceError("challenge_not_found", "challenge is missing or expired; start a fresh login", 404);
    }
    if (held.platform !== identity.platform || held.profileKey !== identity.profileKey) {
      throw new ServiceError("challenge_identity_mismatch", "challenge identity does not match", 409);
    }
    if (held.proxyLease !== identity.proxyLease) {
      throw new ServiceError("proxy_lease_mismatch", "continuation must use the original proxy lease", 409);
    }
    if (held.proxyURL !== identity.proxyURL) {
      throw new ServiceError("proxy_identity_mismatch", "continuation must use the original proxy URL", 409);
    }
    if (held.ownerToken !== identity.ownerToken || held.connectionID !== identity.connectionID ||
        held.generation !== identity.generation || held.revision !== identity.revision ||
        held.recoveryClaim !== identity.recoveryClaim) {
      throw new ServiceError("operation_owner_mismatch", "challenge operation owner does not match", 409);
    }
    const operation = this.#operations.get(held.ownerToken);
    if (operation?.state === "in_flight") {
      throw new ServiceError("operation_in_flight", "operation continuation is already in flight", 409);
    }
    const attempts = (operation?.attempts || 0) + 1;
    if (attempts > this.#maxAttempts) {
      this.cancel(held.ownerToken, identity);
      throw new ServiceError("attempts_exhausted", "verification attempt budget exhausted", 429);
    }
    held.attempts = attempts;
    operation.attempts = attempts;
    operation.state = "in_flight";
    operation.settled = new Promise((resolve) => { operation.resolveSettlement = resolve; });
    return held;
  }

  get(id, identity) {
    return this.claimContinuation(id, identity);
  }

  consume(id) {
    const held = this.#items.get(id);
    if (!held) return;
    this.#clock.clearTimeout(held.timer);
    this.#items.delete(id);
    const operation = this.#operations.get(held.ownerToken);
    if (operation?.challengeID === id && operation.state !== "in_flight") {
      operation.challengeID = "";
      operation.state = "completed";
      operation.resolveSettlement?.();
      this.#operations.delete(held.ownerToken);
    }
  }

  status(ownerToken, identity) {
    const operation = this.#operations.get(String(ownerToken || ""));
    if (!operation) throw new ServiceError("challenge_not_found", "operation is missing or expired", 404);
    const held = this.#items.get(operation.challengeID);
    if (!held || held.expiresAt <= this.#clock.now()) {
      if (held) this.#expire(operation.challengeID);
      else if (operation.state !== "in_flight" && !operation.cancelRequested) this.#operations.delete(ownerToken);
      throw new ServiceError("challenge_not_found", "operation is missing or expired", 404);
    }
    this.#assertOwner(held, identity);
    return { active: true, expires_at: new Date(held.expiresAt).toISOString(), attempts: operation.attempts, resends: operation.resends };
  }

  cancel(ownerToken, identity) {
    const operation = this.#operations.get(String(ownerToken || ""));
    if (!operation) return { cancelled: true };
    const held = this.#items.get(operation.challengeID);
    if (held) this.#assertOwner(held, identity);
    if (held) {
      this.#clock.clearTimeout(held.timer);
      this.#items.delete(operation.challengeID);
    }
    if (operation.state === "in_flight") {
      operation.state = "cancelled";
      operation.cancelRequested = true;
      operation.abortController.abort("cancelled");
    } else {
      this.#operations.delete(ownerToken);
    }
    return { cancelled: true };
  }

  cancelProfile(platform, profileKey) {
    const id = profileID(platform, profileKey);
    const owners = new Set();
    for (const [challengeID, held] of this.#items) {
      if (held.platform !== platform || held.profileID !== id) continue;
      this.#clock.clearTimeout(held.timer);
      this.#items.delete(challengeID);
      owners.add(held.ownerToken);
    }
    for (const [ownerToken, operation] of this.#operations) {
      if (owners.has(ownerToken) || (operation.platform === platform && operation.profileID === id)) {
        const inFlight = operation.state === "in_flight";
        operation.cancelRequested = true;
        operation.state = "cancelled";
        operation.abortController.abort("profile_erased");
        if (!inFlight) this.#operations.delete(ownerToken);
      }
    }
    return { cancelled: owners.size };
  }

  claimProfileForErase(platform, profileKey) {
    const id = profileID(platform, profileKey);
    if (this.#profileGuards.has(id)) throw new ServiceError("profile_erasing", "profile erasure is in progress", 409);
    this.#profileGuards.add(id);
    return () => this.#profileGuards.delete(id);
  }

  guardProfile(platform, profileKey) {
    return this.claimProfileForErase(platform, profileKey);
  }

  settle(ownerToken, state = "failed") {
    const operation = this.#operations.get(ownerToken);
    if (!operation) return;
    operation.state = state;
    operation.resolveSettlement?.();
    if (operation.cancelRequested || ["completed", "failed"].includes(state)) this.#operations.delete(ownerToken);
  }

  signal(ownerToken) {
    return this.#operations.get(ownerToken)?.abortController.signal;
  }

  #assertOwner(held, identity) {
    for (const key of ["platform", "profileKey", "proxyLease", "proxyURL", "ownerToken", "connectionID", "generation", "revision", "recoveryClaim"]) {
      if (held[key] !== identity[key]) throw new ServiceError("operation_owner_mismatch", "operation owner does not match", 409);
    }
  }

  size() {
    this.#purge();
    return this.#items.size;
  }

  close() {
    this.#closed = true;
    for (const item of this.#items.values()) this.#clock.clearTimeout(item.timer);
    for (const operation of this.#operations.values()) {
      operation.state = "shutdown";
      operation.abortController.abort("shutdown");
      operation.resolveSettlement?.();
    }
    this.#items.clear();
    this.#operations.clear();
  }

  hasProfile(platform, profileKey) {
    return this.hasProfileID(platform, profileID(platform, profileKey));
  }

  hasProfileID(platform, id) {
    this.#purge();
    for (const operation of this.#operations.values()) {
      if ((!platform || operation.platform === platform) && operation.profileID === id) return true;
    }
    return false;
  }

  #purge() {
    const now = this.#clock.now();
    for (const [id, item] of this.#items) {
      if (item.expiresAt <= now) {
        this.#expire(id);
      }
    }
  }

  #expire(id) {
    const held = this.#items.get(id);
    if (!held) return;
    this.#clock.clearTimeout(held.timer);
    this.#items.delete(id);
    const operation = this.#operations.get(held.ownerToken);
    if (operation?.challengeID === id) {
      if (operation.state === "in_flight") {
        operation.state = "expired";
        operation.cancelRequested = true;
        operation.abortController.abort("expired");
      } else {
        this.#operations.delete(held.ownerToken);
      }
    }
  }

  #newOperation(identity) {
    return {
      ownerToken: identity.ownerToken,
      platform: identity.platform,
      profileKey: identity.profileKey,
      profileID: profileID(identity.platform, identity.profileKey),
      proxyLease: identity.proxyLease,
      proxyURL: identity.proxyURL,
      connectionID: identity.connectionID,
      generation: identity.generation,
      revision: identity.revision,
      recoveryClaim: identity.recoveryClaim,
      attempts: 0,
      resends: 0,
      state: "created",
      abortController: new AbortController(),
      expiryHandle: null,
      browserHold: null,
      settled: Promise.resolve(),
      resolveSettlement: null,
    };
  }
}

export { LoginOperationRegistry as ChallengeStore };
