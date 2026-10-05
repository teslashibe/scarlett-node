import { ServiceError } from "../http/errors.js";

export class Admission {
  #active = 0;
  #accepting = true;
  #queue = [];

  constructor({ concurrency, queueSize, queueTimeoutMs }) {
    this.concurrency = concurrency;
    this.queueSize = queueSize;
    this.queueTimeoutMs = queueTimeoutMs;
  }

  get state() {
    return { accepting: this.#accepting, active: this.#active, queued: this.#queue.length };
  }

  close() {
    this.#accepting = false;
    for (const item of this.#queue.splice(0)) {
      clearTimeout(item.timer);
      item.reject(new ServiceError("shutting_down", "service is shutting down", 503));
    }
  }

  async acquire(signal) {
    if (!this.#accepting) throw new ServiceError("shutting_down", "service is shutting down", 503);
    if (this.#active < this.concurrency) return this.#grant();
    if (this.#queue.length >= this.queueSize) {
      throw new ServiceError("overloaded", "admission queue is full", 429);
    }
    return new Promise((resolve, reject) => {
      const item = { resolve, reject, signal, timer: null, onAbort: null };
      const remove = () => {
        const index = this.#queue.indexOf(item);
        if (index >= 0) this.#queue.splice(index, 1);
        clearTimeout(item.timer);
        signal?.removeEventListener("abort", item.onAbort);
      };
      item.onAbort = () => {
        remove();
        reject(new ServiceError("request_cancelled", "request was cancelled", 499));
      };
      item.timer = setTimeout(() => {
        remove();
        reject(new ServiceError("overloaded", "admission queue timed out", 429));
      }, this.queueTimeoutMs);
      item.timer.unref?.();
      signal?.addEventListener("abort", item.onAbort, { once: true });
      this.#queue.push(item);
    });
  }

  #grant() {
    this.#active++;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.#active--;
      this.#dispatch();
    };
  }

  #dispatch() {
    while (this.#accepting && this.#active < this.concurrency && this.#queue.length) {
      const item = this.#queue.shift();
      clearTimeout(item.timer);
      item.signal?.removeEventListener("abort", item.onAbort);
      if (item.signal?.aborted) {
        item.reject(new ServiceError("request_cancelled", "request was cancelled", 499));
      } else {
        item.resolve(this.#grant());
      }
    }
  }
}
