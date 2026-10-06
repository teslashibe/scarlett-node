import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const main = readFileSync(new URL("../src/main.ts", import.meta.url), "utf8");
const acceptance = readFileSync(new URL("../scripts/check-windows-install.ps1", import.meta.url), "utf8");
const form = main.match(/<form id="x-form">([\s\S]*?)<\/form>/)?.[1];
assert.ok(form, "X import form must be present");

test("Native X account input acknowledgments follow the visible import form tab order", () => {
  const controls = [...form.matchAll(/<(input|select|button)\b([^>]*)>/g)].flatMap((match) => {
    const attributes = match[2];
    if (/\btype="hidden"/.test(attributes)) return [];
    return [{ id: attributes.match(/\bid="([^"]+)"/)?.[1] ?? "submit", disabled: /\bdisabled\b/.test(attributes) }];
  });
  const nextAfterAccount = (profilesAvailable: boolean) => {
    const enabled = controls.filter((control) => ["x-profile", "x-consent"].includes(control.id)
      ? profilesAvailable
      : !control.disabled);
    return enabled[enabled.findIndex((control) => control.id === "x-id") + 1]?.id;
  };
  assert.equal(nextAfterAccount(true), "x-profile");
  assert.equal(nextAfterAccount(false), "x-token");
  assert.match(form, /<input id="x-capacity" type="hidden" value="1">/);
  assert.match(form, /<label>Browser profile<select id="x-profile"/);
  assert.match(form, /<label>auth_token<input id="x-token"/);
  assert.match(main, /\$\("x-profile"\)\.toggleAttribute\("disabled", busy \|\| !browserProfilesAvailable\)/);
  assert.match(main, /\$\("x-consent"\)\.toggleAttribute\("disabled", busy \|\| !browserProfilesAvailable\)/);
  assert.doesNotMatch(acceptance, /'Concurrent jobs'/);
  for (const nickname of ["incomplete-firefox", "protected-chrome", "browser-paste"]) {
    assert.ok(acceptance.includes(`Set-Text 'Local X account ID' '${nickname}' 'Browser profile'`));
  }
});
