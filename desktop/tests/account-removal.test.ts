import test from "node:test";
import assert from "node:assert/strict";
import { accountRemovalConfirmation } from "../src/account-removal.ts";

class Dialog extends EventTarget {
  open = false;
  showModal() { this.open = true; }
  close() {
    this.open = false;
    this.dispatchEvent(new Event("close"));
  }
}
class Button extends EventTarget {
  focused = false;
  focus() { this.focused = true; }
}
function fixture() {
  const dialog = new Dialog();
  const cancel = new Button();
  const confirm = new Button();
  const heading = { textContent: "" };
  const restored: string[] = [];
  const ask = accountRemovalConfirmation({
    dialog,
    cancel,
    confirm,
    heading,
    restoreFocus: (account) => restored.push(account.id),
  });
  const account = { service: "x_read" as const, id: "burner", concurrency: 1 };
  return { dialog, cancel, confirm, heading, restored, ask, account };
}
test("Remove uses an in-app modal, defaults focus to Keep and confirms only the selected account", async () => {
  const f = fixture();
  const pending = f.ask(f.account);
  assert.equal(f.dialog.open, true);
  assert.equal(f.cancel.focused, true);
  assert.equal(f.heading.textContent, "Remove X account burner?");
  // An updated poll/second row click cannot replace the pending selection.
  assert.equal(await f.ask({ ...f.account, id: "canary" }), false);
  f.confirm.dispatchEvent(new Event("click"));
  assert.equal(await pending, true);
  assert.equal(f.dialog.open, false);
  assert.deepEqual(f.restored, ["burner"]);
});
test("Keep, Escape and modal dismissal cancel without granting removal", async () => {
  for (const reason of ["keep", "escape", "close"]) {
    const f = fixture();
    const pending = f.ask(f.account);
    if (reason === "keep") f.cancel.dispatchEvent(new Event("click"));
    if (reason === "escape") {
      const event = new Event("cancel", { cancelable: true });
      f.dialog.dispatchEvent(event);
      assert.equal(event.defaultPrevented, true);
    }
    if (reason === "close") f.dialog.close();
    assert.equal(await pending, false);
    assert.equal(f.dialog.open, false);
    assert.deepEqual(f.restored, ["burner"]);
  }
});
test("A cancelled modal can open again for another account", async () => {
  const f = fixture();
  const cancelled = f.ask(f.account);
  f.cancel.dispatchEvent(new Event("click"));
  assert.equal(await cancelled, false);
  const pending = f.ask({ service: "codex", id: "work", concurrency: 1 });
  assert.equal(f.heading.textContent, "Remove Codex account work?");
  // A browser-queued close event from the first dialog arrives after reopening.
  f.dialog.dispatchEvent(new Event("close"));
  assert.equal(f.dialog.open, true);
  f.confirm.dispatchEvent(new Event("click"));
  assert.equal(await pending, true);
  assert.deepEqual(f.restored, ["burner", "work"]);
});
