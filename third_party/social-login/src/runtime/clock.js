export class SystemClock {
  now() {
    return Date.now();
  }

  setTimeout(callback, delayMs) {
    const timer = globalThis.setTimeout(callback, delayMs);
    timer.unref?.();
    return timer;
  }

  clearTimeout(timer) {
    globalThis.clearTimeout(timer);
  }
}
