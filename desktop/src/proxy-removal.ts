type ProxyRemovalControls = {
  dialog: Pick<HTMLDialogElement, "open" | "showModal" | "close" | "addEventListener">;
  cancel: Pick<HTMLButtonElement, "addEventListener" | "focus">;
  confirm: Pick<HTMLButtonElement, "addEventListener">;
  restoreFocus: () => void;
};

// The same DOM dialog as account removal: the macOS webview shows no
// window.confirm without a dialog plugin, so a native prompt never appears.
export function proxyRemovalConfirmation(controls: ProxyRemovalControls) {
  let pending: ((confirmed: boolean) => void) | undefined;
  const finish = (confirmed: boolean) => {
    if (!pending) return;
    const resolve = pending;
    pending = undefined;
    controls.dialog.close();
    controls.restoreFocus();
    resolve(confirmed);
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
  return (): Promise<boolean> => {
    if (pending || controls.dialog.open) return Promise.resolve(false);
    return new Promise((resolve) => {
      pending = resolve;
      try {
        controls.dialog.showModal();
        controls.cancel.focus();
      } catch {
        finish(false);
      }
    });
  };
}
