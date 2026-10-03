// Build tooling only. No credential access, downloads or provider calls.
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, chmodSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
if (args.length !== 2)
  throw new Error(
    "Usage: npm run prepare:sidecars -- ABSOLUTE_NODE_BINARY ABSOLUTE_PROVER_BINARY",
  );
const triple = execFileSync("rustc", ["+1.95", "-vV"], {
  encoding: "utf8",
}).match(/^host: (.+)$/m)?.[1];
if (!triple) throw new Error("Cannot determine native target");
const out = path.join(root, "src-tauri", "binaries");
mkdirSync(out, { recursive: true });
for (const [index, name] of ["scarlett-node", "scarlett-prover"].entries()) {
  const source = args[index];
  if (!path.isAbsolute(source) || !statSync(source).isFile())
    throw new Error("Supply a reviewed native binary");
  const destination = path.join(
    out,
    `${name}-${triple}${process.platform === "win32" ? ".exe" : ""}`,
  );
  copyFileSync(source, destination);
  if (process.platform !== "win32") chmodSync(destination, 0o755);
}
console.log(`Prepared reviewed sidecars for ${triple}`);
