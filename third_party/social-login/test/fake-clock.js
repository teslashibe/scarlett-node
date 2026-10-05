export class FakeClock {
  #now = 0;
  #next = 1;
  #timers = new Map();

  now() {
    return this.#now;
  }

  setTimeout(callback, delayMs) {
    const id = this.#next++;
    this.#timers.set(id, { at: this.#now + delayMs, callback });
    return id;
  }

  clearTimeout(id) {
    this.#timers.delete(id);
  }

  advance(ms) {
    this.#now += ms;
    for (;;) {
      const due = [...this.#timers].filter(([, timer]) => timer.at <= this.#now)
        .sort((a, b) => a[1].at - b[1].at);
      if (!due.length) return;
      const [id, timer] = due[0];
      this.#timers.delete(id);
      timer.callback();
    }
  }

  get pending() {
    return this.#timers.size;
  }
}
