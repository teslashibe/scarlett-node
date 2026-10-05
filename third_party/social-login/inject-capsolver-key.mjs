#!/usr/bin/env node
// Stamp CapSolver apiKey into the bundled browser extension config.
import fs from "node:fs";

const extDir = process.env.CAPSOLVER_EXTENSION_DIR || "/opt/capsolver-extension";
const key = (process.env.RECAPTCHA_SOLVER_API_KEY || process.env.CAPSOLVER_API_KEY || "").trim();
const cfgPath = `${extDir}/assets/config.js`;

if (!key) {
  console.log("capsolver extension idle (no RECAPTCHA_SOLVER_API_KEY)");
  process.exit(0);
}
if (!fs.existsSync(cfgPath)) {
  console.log(`capsolver extension idle (missing ${cfgPath})`);
  process.exit(0);
}

try {
  let src = fs.readFileSync(cfgPath, "utf8");
  if (/apiKey:\s*['"]/.test(src)) {
    src = src.replace(/apiKey:\s*['"][^'"]*['"]/, `apiKey: ${JSON.stringify(key)}`);
  } else {
    src = src.replace(/apiKey:\s*'',/, `apiKey: ${JSON.stringify(key)},`);
  }
  fs.writeFileSync(cfgPath, src);
  console.log("capsolver extension apiKey configured");
} catch (err) {
  // Never crash the sidecar over CapSolver setup — LinkedIn/X login still works
  // without the extension; API CapSolver path covers many checkpoints.
  const code = err && typeof err === "object" && "code" in err ? err.code : "";
  console.error(
    JSON.stringify({
      event: "capsolver_extension_config_failed",
      path: cfgPath,
      code: code || undefined,
      error: err instanceof Error ? err.message : String(err),
    }),
  );
  process.exit(0);
}
