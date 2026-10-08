import test from "node:test";
import assert from "node:assert/strict";
import { failureNotice, updatedBanner, updateErrorText, updateSummary, updateToast, validVersion, type UpdateStatus } from "../src/update.ts";
import type { Snapshot } from "../src/model.ts";

const status = (change: Partial<UpdateStatus> = {}): UpdateStatus => ({
  version: "0.1.13", mode: "notify", phase: "idle", required: false, can_install: true, snoozed: false, stale: false, ...change,
});
const notes = { title: "Faster proofs", date: "2026-10-12", highlights: ["One", "Two", "Three", "Four"] };
const snapshot = (observation: Snapshot["observation"] = {}): Snapshot => ({
  runtime_available: true, accounts_available: true, helper_available: true, codex_login_available: true,
  paired: true, supervised: true, login_pending: false, accounts: [], observation,
});
const actions = (u: UpdateStatus, dismissed = "") => updateToast(u, undefined, dismissed)?.buttons.map((b) => b.action);

test("Notify mode offers Update now, What's new and Later with up to three highlights", () => {
  const toast = updateToast(status({ phase: "available", latest: "0.1.14", notes }), undefined, "");
  assert.equal(toast?.title, "Scarlett Node 0.1.14 is available");
  assert.equal(toast?.detail, "Faster proofs");
  assert.deepEqual(toast?.highlights, ["One", "Two", "Three"]);
  assert.deepEqual(toast?.buttons.map((b) => b.action), ["install", "notes", "later"]);
  assert.equal(toast?.version, "0.1.14");
  assert.equal(toast?.level, "info");
  // Later hides this version only; a newer one appears again.
  assert.equal(updateToast(status({ phase: "available", latest: "0.1.14" }), undefined, "0.1.14"), null);
  assert.ok(updateToast(status({ phase: "available", latest: "0.1.15" }), undefined, "0.1.14"));
  assert.equal(updateToast(status({ phase: "available", latest: "0.1.14", snoozed: true }), undefined, ""), null);
  // A build that cannot verify the release links the download page instead.
  assert.deepEqual(actions(status({ phase: "available", latest: "0.1.14", can_install: false })), ["download", "notes", "later"]);
});

test("Automatic mode shows no available toast, only countdown, progress and problems", () => {
  assert.equal(updateToast(status({ mode: "automatic", phase: "ready", latest: "0.1.14" }), undefined, ""), null);
  const countdown = updateToast(status({ mode: "automatic", phase: "scheduled", latest: "0.1.14", install_at: 61_000 }), undefined, "", 1_000);
  assert.equal(countdown?.title, "Installing Scarlett Node 0.1.14 when current jobs finish");
  assert.equal(countdown?.detail, "Starts in 60 s");
  assert.deepEqual(countdown?.buttons.map((b) => b.action), ["later", "notes"]);
  assert.equal(updateToast(status({ phase: "downloading", latest: "0.1.14", progress: 45 }), undefined, "")?.title, "Downloading Scarlett Node 0.1.14 · 45 %");
  assert.deepEqual(actions(status({ phase: "downloading", latest: "0.1.14", progress: 45 })), ["cancel"]);
  const draining = updateToast(status({ phase: "draining", latest: "0.1.14", in_flight: 2 }), undefined, "");
  assert.equal(draining?.title, "Finishing 2 accepted jobs before updating");
  assert.match(draining?.detail ?? "", /never interrupted/);
  assert.equal(updateToast(status({ phase: "draining", latest: "0.1.14", in_flight: 1 }), undefined, "")?.title, "Finishing 1 accepted job before updating");
  assert.deepEqual(actions(status({ phase: "installing", latest: "0.1.14" })), []);
});

test("Required updates are persistent alerts", () => {
  const required = updateToast(status({ phase: "available", latest: "0.1.14", required: true }), undefined, "0.1.14");
  assert.equal(required?.level, "required");
  assert.equal(required?.title, "Update required");
  assert.match(required?.detail ?? "", /0\.1\.13 no longer receives new jobs; jobs it already accepted still finish\. Install 0\.1\.14/);
  assert.deepEqual(required?.buttons.map((b) => b.action), ["install", "notes"]);
  const automatic = updateToast(status({ mode: "automatic", phase: "ready", latest: "0.1.14", required: true }), undefined, "");
  assert.match(automatic?.detail ?? "", /installs 0\.1\.14 as soon as it is ready/);
  assert.deepEqual(automatic?.buttons.map((b) => b.action), ["notes"]);
});

test("Errors name a fixed reason and always offer the download page", () => {
  const toast = updateToast(status({ phase: "error", latest: "0.1.14", error: "signature_invalid" }), undefined, "");
  assert.equal(toast?.title, "Scarlett Node 0.1.14 was not installed");
  assert.match(toast?.detail ?? "", /signature check/);
  assert.deepEqual(toast?.buttons.map((b) => b.action), ["download", "notes", "later"]);
  assert.deepEqual(actions(status({ phase: "error", latest: "0.1.14", error: "network" })), ["download", "retry", "notes", "later"]);
  assert.equal(updateErrorText("<script>"), "The update could not be installed");
  assert.match(updateErrorText("translocated"), /Applications/);
});

test("Without the native updater the coordinator notice still links the download page", () => {
  const s = snapshot({ latest_release: "0.1.14", update_available: true });
  assert.deepEqual(updateToast(undefined, s, "")?.buttons.map((b) => b.action), ["download", "later"]);
  assert.equal(updateToast(undefined, s, "0.1.14"), null);
  assert.equal(updateToast(undefined, snapshot({ latest_release: "0.1.14", update_required: true }), "0.1.14")?.level, "required");
  // The coordinator announced a release the manifest has not listed for an hour.
  const stale = updateToast(status({ stale: true }), snapshot({ latest_release: "0.1.15" }), "");
  assert.deepEqual(stale?.buttons.map((b) => b.action), ["download", "later"]);
});

test("The updated banner and failure notice", () => {
  assert.equal(updatedBanner(status()), null);
  const banner = updatedBanner(status({ updated: { version: "0.1.13", notes, offer_automatic: true } }));
  assert.equal(banner?.title, "Updated to Scarlett Node 0.1.13");
  assert.deepEqual(banner?.highlights, ["One", "Two", "Three"]);
  assert.equal(banner?.offerAutomatic, true);
  assert.equal(updatedBanner(status({ mode: "automatic", updated: { version: "0.1.13", offer_automatic: true } }))?.offerAutomatic, false);
  assert.equal(updatedBanner(status({ updated: { version: "<b>1</b>", offer_automatic: false } })), null);
  const rolled = failureNotice(status({ failure: { version: "0.1.14", reason: "node_exited", rolled_back: true } }));
  assert.equal(rolled?.title, "Scarlett Node 0.1.14 could not start");
  assert.match(rolled?.detail ?? "", /restored 0\.1\.13.*skip 0\.1\.14/);
  assert.match(failureNotice(status({ failure: { version: "0.1.14", reason: "not_writable", rolled_back: false } }))?.detail ?? "", /can't replace itself/);
});

test("Settings summary and version checks", () => {
  assert.equal(updateSummary(undefined), "Checking for updates");
  assert.equal(updateSummary(status()), "Version 0.1.13 · Up to date");
  assert.equal(updateSummary(status({ latest: "0.1.14" })), "Version 0.1.13 · 0.1.14 available");
  assert.equal(updateSummary(status({ latest: "0.1.14", required: true })), "Version 0.1.13 · Update required: 0.1.14");
  assert.match(updateSummary(status({ checked_at: Date.UTC(2026, 9, 8, 10, 42) })), /^Version 0\.1\.13 · Up to date · checked /);
  for (const bad of ["", "1.2", "1.2.3/../x", "<b>1.2.3</b>", 3]) assert.equal(validVersion(bad), false);
  assert.equal(validVersion("0.1.14-rc.1"), true);
});
