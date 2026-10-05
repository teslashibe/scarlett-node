import assert from "node:assert/strict";
import test from "node:test";
import { ChallengeStore } from "../src/runtime/challenges.js";
import { FakeClock } from "./fake-clock.js";

const identity = (ownerToken = "o".repeat(43)) => ({
  platform: "x", profileKey: "profile", proxyLease: "lease", proxyURL: "http://proxy",
  ownerToken, connectionID: "connection", generation: "2", revision: "7", recoveryClaim: "claim",
});

test("challenge owner binding rejects stale generation and owner", () => {
  const store = new ChallengeStore();
  try {
  const challenge = store.create(identity(), { username: "u", password: "p" }, {});
  assert.throws(() => store.get(challenge.id, { ...identity(), generation: "3" }),
    (error) => error.code === "operation_owner_mismatch");
  assert.throws(() => store.get(challenge.id, identity("x".repeat(43))),
    (error) => error.code === "operation_owner_mismatch");
  } finally { store.close(); }
});

test("attempt budget cannot reset by resend or replacement", () => {
  const store = new ChallengeStore({ maxAttempts: 2, maxResends: 2 });
  try {
  let challenge = store.create(identity(), { username: "u", password: "p" }, {});
  store.get(challenge.id, identity());
  challenge = store.create(identity(), { username: "u", password: "p" }, {});
  store.get(challenge.id, identity());
  challenge = store.create(identity(), { username: "u", password: "p" }, {});
  assert.throws(() => store.get(challenge.id, identity()), (error) => error.code === "attempts_exhausted");
  } finally { store.close(); }
});

test("resend invalidates old challenge and aggregate budget is bounded", () => {
  const store = new ChallengeStore({ maxResends: 1 });
  try {
  const first = store.create(identity(), { username: "u", password: "p" }, {});
  store.create(identity(), { username: "u", password: "p" }, {});
  assert.throws(() => store.get(first.id, identity()), (error) => error.code === "challenge_not_found");
  assert.throws(() => store.create(identity(), { username: "u", password: "p" }, {}),
    (error) => error.code === "resends_exhausted");
  } finally { store.close(); }
});

test("cancel is owner-bound and idempotent", () => {
  const store = new ChallengeStore();
  try {
  store.create(identity(), { username: "u", password: "p" }, {});
  assert.throws(() => store.cancel("o".repeat(43), { ...identity(), revision: "8" }),
    (error) => error.code === "operation_owner_mismatch");
  assert.deepEqual(store.cancel("o".repeat(43), identity()), { cancelled: true });
  assert.deepEqual(store.cancel("o".repeat(43), identity()), { cancelled: true });
  } finally { store.close(); }
});

test("replacement retains cumulative owner operation budgets", () => {
  const store = new ChallengeStore({ maxAttempts: 2, maxResends: 2 });
  try {
  const first = store.create(identity(), { username: "u", password: "p" }, {});
  store.get(first.id, identity());
  const replacement = store.create(identity(), { username: "u", password: "p" }, {});
  assert.equal(store.status("o".repeat(43), identity()).attempts, 1);
  store.get(replacement.id, identity());
  const secondReplacement = store.create(identity(), { username: "u", password: "p" }, {});
  assert.throws(() => store.get(secondReplacement.id, identity()),
    (error) => error.code === "attempts_exhausted");
  } finally { store.close(); }
});

test("consume only deletes the currently live owner challenge", () => {
  const store = new ChallengeStore();
  try {
  const first = store.create(identity(), { username: "u", password: "p" }, {});
  const replacement = store.create(identity(), { username: "u", password: "p" }, {});
  store.consume(first.id);
  assert.equal(store.status("o".repeat(43), identity()).active, true);
  store.consume(replacement.id);
  assert.throws(() => store.status("o".repeat(43), identity()),
    (error) => error.code === "challenge_not_found");
  } finally { store.close(); }
});

test("expiry cleans owner operation and permits a fresh budget", () => {
  const clock = new FakeClock();
  const store = new ChallengeStore({ ttlMs: 5, maxAttempts: 1, maxResends: 1, clock });
  try {
  const challenge = store.create(identity(), { username: "u", password: "p" }, {});
  store.get(challenge.id, identity());
  clock.advance(5);
  assert.throws(() => store.status("o".repeat(43), identity()),
    (error) => error.code === "challenge_not_found");
  store.settle("o".repeat(43), "expired");
  const fresh = store.create(identity(), { username: "u", password: "p" }, {});
  assert.doesNotThrow(() => store.get(fresh.id, identity()));
  } finally { store.close(); }
});

test("profile cancellation removes all owners and rejects stale continuations", () => {
  const store = new ChallengeStore();
  try {
  const first = store.create(identity("a".repeat(43)), { username: "u", password: "p" }, {});
  const second = store.create(identity("b".repeat(43)), { username: "u", password: "p" }, {});
  assert.deepEqual(store.cancelProfile("x", "profile"), { cancelled: 2 });
  assert.throws(() => store.get(first.id, identity("a".repeat(43))),
    (error) => error.code === "challenge_not_found");
  assert.throws(() => store.get(second.id, identity("b".repeat(43))),
    (error) => error.code === "challenge_not_found");
  } finally { store.close(); }
});

test("managed challenge credentials never retain TOTP", () => {
  const store = new ChallengeStore();
  try {
  const challenge = store.create(identity(), { username: "u", password: "p" }, {});
  const held = store.get(challenge.id, identity());
  assert.deepEqual(held.credentials, { username: "u", password: "p" });
  assert.equal("totpSecret" in held.credentials, false);
  } finally { store.close(); }
});

test("profile erase guard rejects continuation and replacement races", () => {
  const store = new ChallengeStore();
  try {
  const challenge = store.create(identity(), { username: "u", password: "p" }, {});
  const release = store.guardProfile("x", "profile");
  assert.throws(() => store.get(challenge.id, identity()), (error) => error.code === "profile_erasing");
  assert.throws(() => store.create(identity(), { username: "u", password: "p" }, {}),
    (error) => error.code === "profile_erasing");
  store.cancelProfile("x", "profile");
  release();
  assert.throws(() => store.get(challenge.id, identity()), (error) => error.code === "challenge_not_found");
  } finally { store.close(); }
});

test("stale owner binding cannot replace the live challenge", () => {
  const store = new ChallengeStore();
  try {
    const live = store.create(identity(), { username: "u", password: "p" }, {});
    assert.throws(() => store.create({ ...identity(), revision: "8" }, { username: "u", password: "p" }, {}),
      (error) => error.code === "operation_owner_mismatch");
    assert.equal(store.status("o".repeat(43), identity()).active, true);
    assert.doesNotThrow(() => store.get(live.id, identity()));
  } finally { store.close(); }
});

test("replacement succeeds at capacity without increasing occupancy", () => {
  const store = new ChallengeStore({ capacity: 1 });
  try {
    store.create(identity(), { username: "u", password: "p" }, {});
    assert.doesNotThrow(() => store.create(identity(), { username: "u", password: "p" }, {}));
    assert.equal(store.size(), 1);
  } finally { store.close(); }
});

test("synchronous expiry clears operation budget", () => {
  const clock = new FakeClock();
  const store = new ChallengeStore({ ttlMs: 5, maxAttempts: 1, clock });
  try {
    const challenge = store.create(identity(), { username: "u", password: "p" }, {});
    store.get(challenge.id, identity());
    clock.advance(5);
    assert.throws(() => store.get(challenge.id, identity()), (error) => error.code === "challenge_not_found");
    store.settle("o".repeat(43), "expired");
    const fresh = store.create(identity(), { username: "u", password: "p" }, {});
    assert.doesNotThrow(() => store.get(fresh.id, identity()));
  } finally { store.close(); }
});

test("status never reports an expired challenge active", () => {
  const clock = new FakeClock();
  const store = new ChallengeStore({ ttlMs: 5, clock });
  try {
    store.create(identity(), { username: "u", password: "p" }, {});
    clock.advance(5);
    assert.throws(() => store.status("o".repeat(43), identity()),
      (error) => error.code === "challenge_not_found");
  } finally { store.close(); }
});

test("continuation claim is atomic and preserves cumulative budget while in flight", () => {
  const store = new ChallengeStore({ maxAttempts: 2 });
  try {
    const challenge = store.create(identity(), { username: "u", password: "p" }, {});
    store.claimContinuation(challenge.id, identity());
    assert.throws(() => store.claimContinuation(challenge.id, identity()),
      (error) => error.code === "operation_in_flight");
    assert.equal(store.status("o".repeat(43), identity()).attempts, 1);
  } finally { store.close(); }
});

test("cancel during in-flight continuation tombstones budget until settlement", () => {
  const store = new ChallengeStore({ maxAttempts: 1 });
  const challenge = store.create(identity(), { username: "u", password: "p" }, {});
  store.claimContinuation(challenge.id, identity());
  store.cancel("o".repeat(43), identity());
  assert.throws(() => store.create(identity(), { username: "u", password: "p" }, {}),
    (error) => error.code === "operation_in_flight");
  store.settle("o".repeat(43), "cancelled");
  assert.doesNotThrow(() => store.create(identity(), { username: "u", password: "p" }, {}));
  store.close();
});

test("expiry during in-flight continuation tombstones until settlement", () => {
  const clock = new FakeClock();
  const store = new ChallengeStore({ ttlMs: 5, maxAttempts: 1, clock });
  const challenge = store.create(identity(), { username: "u", password: "p" }, {});
  store.claimContinuation(challenge.id, identity());
  clock.advance(5);
  assert.throws(() => store.create(identity(), { username: "u", password: "p" }, {}),
    (error) => error.code === "operation_in_flight");
  store.settle("o".repeat(43), "expired");
  assert.doesNotThrow(() => store.create(identity(), { username: "u", password: "p" }, {}));
  store.close();
});
