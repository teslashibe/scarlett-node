import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { relayResumeConfirmation } from "../src/relay-resume.ts";
import { layout } from "../src/layout.ts";

class Control extends EventTarget {
  hidden = false;
  focused = false;
  focus() { this.focused = true; }
}
function fixture() {
  const banner = new EventTarget();
  const resume = new Control();
  const confirm = new Control();
  const cancel = new Control();
  const prompt = { hidden: false };
  let resumed = 0;
  const confirmation = relayResumeConfirmation({ banner, resume, confirm, cancel, prompt, onConfirm: () => resumed++ });
  const click = (control: Control) => control.dispatchEvent(new Event("click"));
  const shown = () => ({ resume: !resume.hidden, confirm: !confirm.hidden, cancel: !cancel.hidden, prompt: !prompt.hidden });
  return { banner, resume, confirm, cancel, confirmation, click, shown, resumed: () => resumed };
}
const idle = { resume: true, confirm: false, cancel: false, prompt: false };
const asking = { resume: false, confirm: true, cancel: true, prompt: true };
const none = { resume: false, confirm: false, cancel: false, prompt: false };

test("Resume relay asks inside the banner and resumes only once confirmed", () => {
  const f = fixture();
  f.confirmation.render(true);
  assert.deepEqual(f.shown(), idle);
  f.click(f.resume);
  assert.deepEqual(f.shown(), asking);
  assert.equal(f.cancel.focused, true);
  assert.equal(f.resumed(), 0);
  // Polling re-renders the banner while the question is open.
  f.confirmation.render(true);
  assert.deepEqual(f.shown(), asking);
  f.click(f.confirm);
  assert.equal(f.resumed(), 1);
  assert.deepEqual(f.shown(), idle);
  // A stale confirm click does not resume again.
  f.click(f.confirm);
  assert.equal(f.resumed(), 1);
});
test("Keep paused and Escape leave relay paused", () => {
  for (const how of ["keep", "escape"]) {
    const f = fixture();
    f.confirmation.render(true);
    f.click(f.resume);
    if (how === "keep") f.click(f.cancel);
    else {
      const event = Object.assign(new Event("keydown", { cancelable: true }), { key: "Escape" });
      f.banner.dispatchEvent(event);
      assert.equal(event.defaultPrevented, true);
    }
    assert.deepEqual(f.shown(), idle, how);
    assert.equal(f.resume.focused, true, how);
    assert.equal(f.resumed(), 0, how);
  }
});
test("A halt that clears while asking ends the question", () => {
  const f = fixture();
  f.confirmation.render(true);
  f.click(f.resume);
  f.confirmation.render(false);
  assert.deepEqual(f.shown(), none);
  f.click(f.confirm);
  f.click(f.resume);
  assert.equal(f.resumed(), 0);
  assert.deepEqual(f.shown(), none);
  // A later halt starts at the first step again.
  f.confirmation.render(true);
  assert.deepEqual(f.shown(), idle);
});
test("The app asks with its own controls: the macOS webview shows no native dialogs", () => {
  const main = readFileSync(new URL("../src/main.ts", import.meta.url), "utf8");
  assert.doesNotMatch(main, /\b(confirm|alert|prompt)\(/);
  const banner = /<section id="relay-banner"[^>]*>(.*?)<\/section>/.exec(layout)?.[1] ?? "";
  for (const id of ["relay-resume", "relay-cancel", "relay-confirm", "relay-confirm-detail"]) assert.match(banner, new RegExp(`id="${id}"`));
  // Labels and headings carry no closing period.
  for (const label of banner.matchAll(/<(?:button|h2)[^>]*>([^<]*)</g)) assert.doesNotMatch(label[1], /\.$/);
});
