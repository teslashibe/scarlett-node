import { ServiceError } from "../http/errors.js";
import { SystemClock } from "./clock.js";
import { profileID } from "./profiles.js";

export class BrowserHoldRegistry {
  #holds = new Map();
  #clock;
  #closeTimeoutMs;
  #closed = false;

  constructor({ clock = new SystemClock(), closeTimeoutMs = 10_000 } = {}) {
    this.#clock = clock;
    this.#closeTimeoutMs = closeTimeoutMs;
  }

  async park(ownerToken, identity, session, ttlMs) {
    if (this.#closed) {
      await Promise.resolve(session.close("shutdown")).catch(() => {});
      throw new ServiceError("shutting_down", "service is shutting down", 503);
    }
    const prior = this.#holds.get(ownerToken);
    if (prior) await this.release(ownerToken, "replaced");
    if (this.#closed) {
      await Promise.resolve(session.close("shutdown")).catch(() => {});
      throw new ServiceError("shutting_down", "service is shutting down", 503);
    }
    const hold = {
      ownerToken,
      platform: identity.platform,
      profileID: profileID(identity.platform, identity.profileKey),
      session,
      expiresAt: this.#clock.now() + ttlMs,
      timer: null,
    };
    hold.timer = this.#clock.setTimeout(() => void this.release(ownerToken, "expired"), ttlMs);
    this.#holds.set(ownerToken, hold);
  }

  take(ownerToken) {
    const hold = this.#holds.get(ownerToken);
    if (!hold) return null;
    this.#holds.delete(ownerToken);
    this.#clock.clearTimeout(hold.timer);
    if (hold.expiresAt <= this.#clock.now() || hold.session.closed) {
      void this.#close(hold, "expired");
      return null;
    }
    return hold.session;
  }

  async release(ownerToken, reason = "released") {
    const hold = this.#holds.get(ownerToken);
    if (!hold) return;
    if (hold.releasePromise) return hold.releasePromise;
    this.#clock.clearTimeout(hold.timer);
    hold.releasePromise = (async () => {
      try {
        await this.#close(hold, reason);
        this.#holds.delete(ownerToken);
      } catch (error) {
        hold.timer = null;
        hold.releasePromise = null;
        throw error;
      }
    })();
    return hold.releasePromise;
  }

  async releaseProfile(platform, profileKey, reason = "profile_erased") {
    const id = profileID(platform, profileKey);
    const owners = [...this.#holds.values()]
      .filter((hold) => hold.platform === platform && hold.profileID === id)
      .map((hold) => hold.ownerToken);
    const results = await Promise.allSettled(owners.map((owner) => this.release(owner, reason)));
    if (results.some((result) => result.status === "rejected")) {
      throw new ServiceError("profile_in_use", "browser session did not close before erasure deadline", 409);
    }
  }

  hasOwner(ownerToken) {
    return this.#holds.has(ownerToken);
  }

  hasProfile(platform, profileKey) {
    return this.hasProfileID(platform, profileID(platform, profileKey));
  }

  hasProfileID(platform, id) {
    return [...this.#holds.values()].some(
      (hold) => (!platform || hold.platform === platform) && hold.profileID === id,
    );
  }

  get size() {
    return this.#holds.size;
  }

  async close() {
    this.#closed = true;
    await Promise.all([...this.#holds.keys()].map((owner) => this.release(owner, "shutdown")));
  }

  async #close(hold, reason) {
    let timeout;
    try {
      await Promise.race([
        Promise.resolve(hold.session.close(reason)),
        new Promise((_, reject) => {
          timeout = this.#clock.setTimeout(
            () => reject(new ServiceError("browser_close_timeout", "browser session close timed out", 504)),
            this.#closeTimeoutMs,
          );
        }),
      ]);
    } finally {
      this.#clock.clearTimeout(timeout);
    }
  }
}
