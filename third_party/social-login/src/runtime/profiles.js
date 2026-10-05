import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { ServiceError } from "../http/errors.js";

const SAFE_KEY = /^[A-Za-z0-9_-]{1,128}$/;
const METADATA_FILE = ".social-login-profile.json";
const integer = (name, fallback, minimum = 1) =>
  Math.max(minimum, Number.parseInt(process.env[name] || `${fallback}`, 10) || fallback);

export function sanitizeProfileKey(value) {
  const key = String(value || "");
  if (!SAFE_KEY.test(key)) {
    throw new ServiceError("invalid_profile_key", "profile_key must be 1-128 opaque safe characters", 400);
  }
  return key;
}

export function profileID(platform, profileKey) {
  const key = sanitizeProfileKey(profileKey);
  return crypto.createHash("sha256").update(`${platform}\0${key}`).digest("hex");
}

export function profileDirectory(base, platform, profileKey) {
  if (!base) throw new ServiceError("profiles_unavailable", "persistent profiles are not configured", 503);
  const dir = path.join(base, platform, profileID(platform, profileKey));
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

export class ProfileLocks {
  #active = new Set();

  acquire(platform, profileKey) {
    const id = `${platform}:${profileID(platform, profileKey)}`;
    if (this.#active.has(id)) {
      throw new ServiceError("profile_busy", "profile is already in use", 409);
    }
    this.#active.add(id);
    let released = false;
    return () => {
      if (!released) this.#active.delete(id);
      released = true;
    };
  }

  active(platform, profileKey) {
    return this.#active.has(`${platform}:${profileID(platform, profileKey)}`);
  }

  activeID(platform, id) {
    if (platform) return this.#active.has(`${platform}:${id}`);
    for (const key of this.#active) {
      if (key.endsWith(`:${id}`)) return true;
    }
    return false;
  }
}

export class ProfileStore {
  #base;
  #locks;
  #challenges;
  #timer;
  #running = false;
  #cleanupPromise;
  #admissionQueue = Promise.resolve();
  #stats = { evictions: 0, rejected_creations: 0, cleanup_failures: 0 };
  #snapshot = { profile_count: 0, profile_bytes: 0, ...this.#stats };

  constructor({ locks, challenges, base = (process.env.CAP_PROFILE_BASE || "").trim() } = {}) {
    this.#base = base ? path.resolve(base) : "";
    this.#locks = locks;
    this.#challenges = challenges;
    if (this.#base) fs.mkdirSync(this.#base, { recursive: true, mode: 0o700 });
  }

  start() {
    if (!this.#base) return;
    void this.cleanup();
    this.#timer = setInterval(
      () => void this.cleanup(),
      integer("SOCIAL_LOGIN_PROFILE_CLEANUP_INTERVAL_MS", 60 * 60_000),
    );
    this.#timer.unref?.();
  }

  close() {
    clearInterval(this.#timer);
  }

  metrics() {
    return { ...this.#snapshot };
  }

  directory(platform, profileKey) {
    if (!this.#base) throw new ServiceError("profiles_unavailable", "persistent profiles are not configured", 503);
    return this.#profilePath(profileID(platform, profileKey));
  }

  async admit(platform, profileKey) {
    if (!this.#base) return profileID(platform, profileKey);
    const previous = this.#admissionQueue;
    let release;
    this.#admissionQueue = new Promise((resolve) => { release = resolve; });
    await previous;
    try {
    const id = profileID(platform, profileKey);
    const dir = path.join(this.#base, id);
    if (fs.existsSync(dir)) {
      const metadata = this.#readMetadata(dir, platform, id);
      metadata.platform = platform;
      metadata.profile_id = id;
      metadata.approximate_bytes = this.#directoryBytes(dir);
      this.#writeMetadata(dir, metadata);
      if (metadata.approximate_bytes > this.#maxProfileBytes()) {
        throw new ServiceError("profile_capacity", "profile exceeds configured storage capacity", 507);
      }
      return id;
    }
    const failures = this.#stats.cleanup_failures;
    await this.cleanup({ requiredBytes: this.#maxProfileBytes(), requiredProfiles: 1 });
    if (this.#stats.cleanup_failures !== failures) {
      this.#stats.rejected_creations++;
      this.#snapshot = { ...this.#snapshot, ...this.#stats };
      throw new ServiceError("profile_capacity", "profile capacity could not be verified", 507);
    }
    const current = this.#snapshot;
    if (current.profile_count >= this.#maxProfiles()
      || current.profile_bytes + this.#maxProfileBytes() > this.#maxVolumeBytes()) {
      this.#stats.rejected_creations++;
      this.#refreshSnapshot();
      throw new ServiceError("profile_capacity", "no safe profile capacity is available", 507);
    }
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(dir, ".platform"), platform, { mode: 0o600 });
    const now = new Date().toISOString();
    this.#writeMetadata(dir, {
      version: 1,
      platform,
      profile_id: id,
      created_at: now,
      last_used_at: now,
      approximate_bytes: 0,
      lifecycle_status: "active",
    });
    try {
      this.#refreshSnapshot();
    } catch (error) {
      fs.rmSync(dir, { recursive: true, force: true });
      throw error;
    }
    return id;
    } finally {
      release();
    }
  }

  touch(platform, profileKey) {
    if (!this.#base) return;
    const id = profileID(platform, profileKey);
    const dir = path.join(this.#base, id);
    if (!fs.existsSync(dir)) return;
    const metadata = this.#readMetadata(dir, platform, id);
    metadata.last_used_at = new Date().toISOString();
    metadata.lifecycle_status = metadata.approximate_bytes > this.#maxProfileBytes()
      ? "over_capacity"
      : "active";
    metadata.approximate_bytes = this.#directoryBytes(dir);
    this.#writeMetadata(dir, metadata);
    this.#refreshSnapshot();
  }

  async erase(platform, profileKey) {
    const id = profileID(platform, profileKey);
    if (!this.#base) return { erased: true };
    const previous = this.#admissionQueue;
    let releaseQueue;
    this.#admissionQueue = new Promise((resolve) => { releaseQueue = resolve; });
    await previous;
    let releaseChallengeGuard;
    let release;
    try {
      releaseChallengeGuard = this.#challenges?.guardProfile(platform, profileKey);
      release = this.#locks?.acquire(platform, profileKey);
      this.#challenges?.cancelProfile(platform, profileKey);
      fs.rmSync(this.#profilePath(id), { recursive: true, force: true });
      this.#refreshSnapshot();
      return { erased: true };
    } finally {
      release?.();
      releaseChallengeGuard?.();
      releaseQueue();
    }
  }

  async cleanup({ requiredBytes = 0, requiredProfiles = 0 } = {}) {
    if (!this.#base) return this.metrics();
    if (this.#running) {
      await this.#cleanupPromise;
      if (requiredBytes || requiredProfiles) {
        return this.cleanup({ requiredBytes, requiredProfiles });
      }
      return this.metrics();
    }
    this.#running = true;
    this.#cleanupPromise = (async () => {
      try {
      const deadline = Date.now() + integer("SOCIAL_LOGIN_PROFILE_CLEANUP_TIMEOUT_MS", 5_000);
      const entries = this.#profiles(deadline);
      const retentionCutoff = Date.now() - integer("SOCIAL_LOGIN_PROFILE_RETENTION_DAYS", 90) * 86_400_000;
      const candidates = entries
        .filter((item) => !item.protected)
        .sort((a, b) => a.lastUsed - b.lastUsed || a.id.localeCompare(b.id));
      let count = entries.length;
      let bytes = entries.reduce((sum, item) => sum + item.bytes, 0);
      for (const item of candidates) {
        if (Date.now() >= deadline) break;
        if (this.#protected(item.platform, undefined, item.id)) continue;
        const expired = item.lastUsed < retentionCutoff;
        const overCapacity = count + requiredProfiles > this.#maxProfiles()
          || bytes + requiredBytes > this.#maxVolumeBytes();
        if (!expired && !overCapacity) break;
        fs.rmSync(item.dir, { recursive: true, force: true });
        count--;
        bytes -= item.bytes;
        this.#stats.evictions++;
      }
      this.#snapshot = { profile_count: count, profile_bytes: bytes, ...this.#stats };
      return this.metrics();
      } catch {
        this.#stats.cleanup_failures++;
        this.#snapshot = { ...this.#snapshot, ...this.#stats };
        return this.metrics();
      } finally {
        this.#running = false;
      }
    })();
    return this.#cleanupPromise;
  }

  #profiles(deadline) {
    const result = [];
    const limit = Math.max(
      integer("SOCIAL_LOGIN_PROFILE_CLEANUP_MAX_ENTRIES", 2_000),
      this.#maxProfiles() + 1,
    );
    const names = fs.readdirSync(this.#base, { withFileTypes: true })
      .filter((entry) => entry.isDirectory() && /^[a-f0-9]{64}$/.test(entry.name))
      .map((entry) => entry.name)
      .sort();
    if (names.length > limit) {
      throw new Error("profile cleanup entry limit exceeded");
    }
    for (const id of names) {
      if (Date.now() >= deadline) break;
      const dir = path.join(this.#base, id);
      const metadata = this.#readMetadata(dir, this.#legacyPlatform(dir), id);
      const bytes = this.#directoryBytes(dir, deadline);
      metadata.approximate_bytes = bytes;
      metadata.lifecycle_status = this.#protected(metadata.platform, undefined, id) ? "protected" : "inactive";
      this.#writeMetadata(dir, metadata);
      result.push({
        id,
        platform: metadata.platform,
        dir,
        bytes,
        lastUsed: Date.parse(metadata.last_used_at) || 0,
        protected: metadata.lifecycle_status === "protected",
      });
    }
    if (result.length !== names.length) {
      throw new Error("profile cleanup deadline exceeded");
    }
    return result;
  }

  #profilePath(id) {
    const target = path.resolve(this.#base, id);
    if (path.dirname(target) !== this.#base || !/^[a-f0-9]{64}$/.test(path.basename(target))) {
      throw new ServiceError("invalid_profile_key", "profile path is invalid", 400);
    }
    return target;
  }

  #legacyPlatform(dir) {
    try {
      const marker = fs.readFileSync(path.join(dir, ".platform"), "utf8").trim();
      return SAFE_KEY.test(marker) ? marker : "";
    } catch {
      return "";
    }
  }

  #protected(platform, profileKey, id = "") {
    return profileKey
      ? this.#locks?.active(platform, profileKey) || this.#challenges?.hasProfile(platform, profileKey)
      : this.#locks?.activeID(platform, id) || this.#challenges?.hasProfileID(platform, id);
  }

  #readMetadata(dir, platform, id) {
    try {
      const parsed = JSON.parse(fs.readFileSync(path.join(dir, METADATA_FILE), "utf8"));
      if (parsed.profile_id === id && (!parsed.platform || SAFE_KEY.test(parsed.platform))) return parsed;
    } catch {}
    const timestamp = fs.statSync(dir).birthtime.toISOString();
    return {
      version: 1, platform, profile_id: id, created_at: timestamp, last_used_at: timestamp,
      approximate_bytes: 0, lifecycle_status: "inactive",
    };
  }

  #writeMetadata(dir, metadata) {
    const target = path.join(dir, METADATA_FILE);
    const temporary = `${target}.${process.pid}.tmp`;
    fs.writeFileSync(temporary, JSON.stringify(metadata), { mode: 0o600 });
    fs.renameSync(temporary, target);
  }

  #directoryBytes(dir, deadline = Infinity) {
    let bytes = 0;
    let visited = 0;
    const maximum = integer("SOCIAL_LOGIN_PROFILE_SCAN_MAX_ENTRIES", 20_000);
    const pending = [dir];
    while (pending.length && visited < maximum && Date.now() < deadline) {
      const current = pending.pop();
      for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
        if (++visited > maximum) break;
        const child = path.join(current, entry.name);
        if (entry.isDirectory()) pending.push(child);
        else if (entry.isFile()) bytes += fs.statSync(child).size;
      }
    }
    if (pending.length || visited >= maximum || Date.now() >= deadline) {
      throw new Error("profile scan bound exceeded");
    }
    return bytes;
  }

  #refreshSnapshot() {
    const deadline = Date.now() + integer("SOCIAL_LOGIN_PROFILE_CLEANUP_TIMEOUT_MS", 5_000);
    const profiles = this.#profiles(deadline);
    this.#snapshot = {
      profile_count: profiles.length,
      profile_bytes: profiles.reduce((sum, item) => sum + item.bytes, 0),
      ...this.#stats,
    };
  }

  #maxProfileBytes() { return integer("SOCIAL_LOGIN_MAX_PROFILE_BYTES", 1024 * 1024 * 1024); }
  #maxVolumeBytes() { return integer("SOCIAL_LOGIN_MAX_VOLUME_BYTES", 8 * 1024 * 1024 * 1024); }
  #maxProfiles() { return integer("SOCIAL_LOGIN_MAX_PROFILES", 1_000); }
}
