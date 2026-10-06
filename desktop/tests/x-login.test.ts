import test from "node:test";
import assert from "node:assert/strict";
import { errorMessage, xLoginMessage } from "../src/model.ts";
test("X challenge copy asks for a code without exposing protocol method names", () => {
 const text = xLoginMessage({status:"pending",method:"verification_code",destination:"f***@example.test",expires_at:"2026-10-05T23:00:00Z"});
 assert.match(text,/Enter the verification code sent to f\*\*\*@example.test/);
 assert.doesNotMatch(text,/verification_code|TOTP/);
});
test("A reconnect identity mismatch gives the operator a bounded next step", () => {
 const expected = "This login belongs to a different X account. Add it as a new account";
 assert.equal(errorMessage("identity_mismatch"), expected);
 assert.equal(xLoginMessage({status:"error",code:"identity_mismatch"}), expected);
});
test("X cooldown and recovery failures preserve the operator's saved session", () => {
 assert.match(xLoginMessage({status:"error",code:"cooldown",retry_after:90}),/90 seconds/);
 assert.match(xLoginMessage({status:"error",code:"verification_failed"}),/saved session was kept/);
 assert.match(xLoginMessage({status:"error",code:"restart_login"}),/Start a new login/);
 assert.doesNotMatch(xLoginMessage({status:"error",code:"private-provider-secret"}),/private-provider-secret/);
});
