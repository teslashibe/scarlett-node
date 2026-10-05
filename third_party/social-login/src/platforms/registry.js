import { __test as defaultRuntime, hasBrowserLoginRecipe } from "../runtime/legacy.js";

const names = ["facebook", "instagram", "linkedin", "reddit", "tiktok", "x"];

export class PlatformRegistry {
  #recipes = new Map();

  constructor(runtime = defaultRuntime) {
    for (const name of names) {
      if (hasBrowserLoginRecipe(name)) {
        this.#recipes.set(name, {
          login: (input, proxyURL, profileID, signal) =>
            runtime.runBrowserLogin(name, input, proxyURL, profileID, signal),
        });
      }
    }
  }

  names() {
    return [...this.#recipes.keys()];
  }

  get(name) {
    return this.#recipes.get(name);
  }
}
