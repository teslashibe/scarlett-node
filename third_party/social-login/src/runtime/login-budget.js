import { AsyncLocalStorage } from "node:async_hooks";
import { setTimeout as delay } from "node:timers/promises";
import { ServiceError } from "../http/errors.js";

// One request owns all nested browser launches, password submissions and solver
// tasks. HTTP requests and browser subresources are not credential attempts.
export const loginBudgetScope = new AsyncLocalStorage();
export const currentLoginBudget = () => loginBudgetScope.getStore();

export class LoginBudget {
  #controller = new AbortController();
  #timer;
  #listeners = [];
  #closers = new Set();
  #closing = [];
  #limits;
  attempts = { browser: 0, credential: 0, solver: 0, complete: true };

  constructor(input = {}, signals = [], expiresAt = Infinity) {
    if (!input || typeof input !== "object" || Array.isArray(input)) {
      throw new ServiceError("invalid_budget", "budget must be an object", 400);
    }
    const defaults = { browser: 2, credential: 3, solver: 3 };
    this.#limits = {};
    for (const [kind, fallback] of Object.entries(defaults)) {
      const value = input[`max_${kind}_attempts`] ?? fallback;
      if (!Number.isSafeInteger(value) || value < 0 || value > 10) {
        throw new ServiceError("invalid_budget", "attempt limits must be integers from 0 to 10", 400);
      }
      this.#limits[kind] = value;
    }
    const deadline = input.deadline_at === undefined ? Infinity : Date.parse(input.deadline_at);
    if (Number.isNaN(deadline)) throw new ServiceError("invalid_budget", "deadline_at must be an absolute timestamp", 400);
    this.deadline = Math.min(deadline, expiresAt, Date.now() + 240_000);
    this.#controller.signal.addEventListener("abort", () => {
      for (const close of this.#closers) this.#closing.push(Promise.resolve().then(close).catch(() => this.markIncomplete()));
    }, { once: true });
    for (const signal of signals) this.follow(signal);
    this.#timer = setTimeout(() => this.abort("deadline_exceeded"), Math.max(0, this.deadline - Date.now()));
    this.#timer.unref?.();
  }

  snapshot() {
    return { limits: { ...this.#limits }, attempts: { ...this.attempts }, deadline: this.deadline };
  }
  restore(state) {
    if (!state) return;
    // The original operation owns aggregate limits. A continuation can request
    // zero new launches/submissions; it cannot erase previous attempts.
    for (const kind of Object.keys(state.limits)) {
      this.#limits[kind] = Math.min(state.limits[kind], state.attempts[kind] + this.#limits[kind]);
    }
    this.attempts = { ...state.attempts };
    this.capDeadline(state.deadline);
  }
  get signal() { return this.#controller.signal; }
  markIncomplete() { this.attempts.complete = false; }
  follow(signal) {
    if (!signal) return;
    const abort = () => this.abort("request_cancelled");
    if (signal.aborted) abort();
    else {
      signal.addEventListener("abort", abort, { once: true });
      this.#listeners.push(() => signal.removeEventListener("abort", abort));
    }
  }
  capDeadline(deadline) {
    this.deadline = Math.min(this.deadline, deadline);
    clearTimeout(this.#timer);
    this.#timer = setTimeout(() => this.abort("deadline_exceeded"), Math.max(0, this.deadline - Date.now()));
    this.#timer.unref?.();
    this.check();
  }
  abort(code = "request_cancelled") {
    this.#controller.abort(new ServiceError(code, code === "deadline_exceeded" ? "login deadline exceeded" : "login cancelled", code === "deadline_exceeded" ? 504 : 499));
  }
  check() {
    if (Date.now() >= this.deadline) this.abort("deadline_exceeded");
    if (this.signal.aborted) throw this.signal.reason;
  }
  use(kind) {
    this.require(kind);
    this.attempts[kind]++;
  }
  require(kind) {
    this.check();
    if (this.attempts[kind] >= this.#limits[kind]) {
      throw new ServiceError("attempts_exhausted", `${kind} attempt budget exhausted`, 429);
    }
  }
  timeout(maximum) {
    this.check();
    return Math.max(1, Math.min(maximum, this.deadline - Date.now()));
  }
  async sleep(ms) {
    this.check();
    try { await delay(Math.min(ms, this.timeout(ms)), undefined, { signal: this.signal }); }
    catch { this.check(); }
    this.check();
  }
  bind(close) {
    this.#closers.add(close);
    if (this.signal.aborted) this.#closing.push(Promise.resolve().then(close).catch(() => this.markIncomplete()));
  }
  async dispose() {
    clearTimeout(this.#timer);
    for (const remove of this.#listeners) remove();
    await Promise.allSettled(this.#closing);
    this.#closers.clear();
  }
}

export const credentialSubmission = () => currentLoginBudget()?.use("credential");
export const loginSleep = async (ms) => currentLoginBudget()
  ? currentLoginBudget().sleep(ms)
  : delay(ms);
