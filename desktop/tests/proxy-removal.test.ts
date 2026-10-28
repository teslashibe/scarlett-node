import test from "node:test";
import assert from "node:assert/strict";
import { proxyRemovalConfirmation } from "../src/proxy-removal.ts";

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
  let restored = 0;
  const ask = proxyRemovalConfirmation({ dialog, cancel, confirm, restoreFocus: () => { restored++; } });
  return { dialog, cancel, confirm, ask, restored: () => restored };
}
test("Remove proxy asks in an in-app modal with focus on Keep and removes only on confirm", async () => {
  const f = fixture();
  const pending = f.ask();
  assert.equal(f.dialog.open, true);
  assert.equal(f.cancel.focused, true);
  // A second click while asking cannot open another question.
  assert.equal(await f.ask(), false);
  f.confirm.dispatchEvent(new Event("click"));
  assert.equal(await pending, true);
  assert.equal(f.dialog.open, false);
  assert.equal(f.restored(), 1);
});
test("Keep, Escape and dismissal keep the proxy", async () => {
  for (const reason of ["keep", "escape", "close"]) {
    const f = fixture();
    const pending = f.ask();
    if (reason === "keep") f.cancel.dispatchEvent(new Event("click"));
    if (reason === "escape") {
      const event = new Event("cancel", { cancelable: true });
      f.dialog.dispatchEvent(event);
      assert.equal(event.defaultPrevented, true);
    }
    if (reason === "close") f.dialog.close();
    assert.equal(await pending, false, reason);
    assert.equal(f.dialog.open, false);
    assert.equal(f.restored(), 1);
  }
});
test("A kept proxy can be asked about again, and a late close does not cancel it", async () => {
  const f = fixture();
  const kept = f.ask();
  f.cancel.dispatchEvent(new Event("click"));
  assert.equal(await kept, false);
  const pending = f.ask();
  f.dialog.dispatchEvent(new Event("close"));
  assert.equal(f.dialog.open, true);
  f.confirm.dispatchEvent(new Event("click"));
  assert.equal(await pending, true);
});
