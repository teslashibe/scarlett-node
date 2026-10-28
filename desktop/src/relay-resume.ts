type Control = Pick<HTMLElement, "hidden" | "addEventListener" | "focus">;

type ResumeControls = {
  banner: Pick<HTMLElement, "addEventListener">;
  resume: Control;
  confirm: Control;
  cancel: Control;
  prompt: Pick<HTMLElement, "hidden">;
  onConfirm: () => void;
};

// The confirmation is a step inside the relay banner: the macOS webview shows
// no window.confirm without a dialog plugin, and a native prompt would be the
// only one in the app. Polling re-renders the banner, so the step it is on
// is kept here, and a halt that clears while asking ends the question.
export function relayResumeConfirmation(controls: ResumeControls) {
  let halted = false;
  let asking = false;
  const sync = () => {
    controls.resume.hidden = !halted || asking;
    controls.confirm.hidden = controls.cancel.hidden = controls.prompt.hidden = !halted || !asking;
  };
  const keepPaused = () => {
    asking = false;
    sync();
    controls.resume.focus();
  };
  controls.resume.addEventListener("click", () => {
    if (!halted) return;
    asking = true;
    sync();
    // Keeping relay paused is the safe default, as Keep is for removal.
    controls.cancel.focus();
  });
  controls.cancel.addEventListener("click", keepPaused);
  controls.confirm.addEventListener("click", () => {
    if (!halted || !asking) return;
    asking = false;
    sync();
    controls.onConfirm();
  });
  controls.banner.addEventListener("keydown", (event) => {
    if (!asking || (event as KeyboardEvent).key !== "Escape") return;
    event.preventDefault();
    keepPaused();
  });
  return {
    render(isHalted: boolean) {
      halted = isHalted;
      if (!halted) asking = false;
      sync();
    },
  };
}
