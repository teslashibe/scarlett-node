import type { Account } from "./model.ts";

type RemovalControls = {
  dialog: Pick<HTMLDialogElement, "open" | "showModal" | "close" | "addEventListener">;
  heading: Pick<HTMLElement, "textContent">;
  cancel: Pick<HTMLButtonElement, "addEventListener" | "focus">;
  confirm: Pick<HTMLButtonElement, "addEventListener">;
  restoreFocus: (account: Account) => void;
};

// A DOM dialog works in every supported webview without a native dialog plugin.
// Keep the selected account while polling updates the rows behind the modal.
export function accountRemovalConfirmation(controls: RemovalControls) {
  let pending: { account: Account; resolve: (confirmed: boolean) => void } | undefined;
  const finish = (confirmed: boolean) => {
    if (!pending) return;
    const current = pending;
    pending = undefined;
    controls.dialog.close();
    controls.restoreFocus(current.account);
    current.resolve(confirmed);
  };
  controls.cancel.addEventListener("click", () => finish(false));
  controls.confirm.addEventListener("click", () => finish(true));
  controls.dialog.addEventListener("cancel", (event) => {
    event.preventDefault();
    finish(false);
  });
  controls.dialog.addEventListener("close", () => {
    // The browser queues close events. A previous close must not cancel a
    // newly opened confirmation while its dialog is already open again.
    if (!controls.dialog.open) finish(false);
  });
  return (account: Account): Promise<boolean> => {
    // A second click cannot replace the first account or orphan its promise.
    if (pending || controls.dialog.open) return Promise.resolve(false);
    return new Promise((resolve) => {
      pending = { account, resolve };
      controls.heading.textContent = `Remove ${account.service === "x_read" ? "X" : "Codex"} account ${account.id}?`;
      try {
        controls.dialog.showModal();
        controls.cancel.focus();
      } catch {
        finish(false);
      }
    });
  };
}
