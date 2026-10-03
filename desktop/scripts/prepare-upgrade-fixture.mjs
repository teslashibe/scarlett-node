import { copyFileSync, lstatSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

// These version variants exercise installation, not historical schema compatibility.
export function upgradeConfig(config) {
  const version = config?.version;
  if (config?.identifier !== 'ai.scarlett.node' || typeof version !== 'string' ||
      !/^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$/.test(version)) {
    throw new Error('Upgrade fixture requires the complete stable desktop configuration');
  }
  const parts = version.split('.').map(Number);
  if (parts.some(part => part > 65535) || parts[2] === 65535 ||
      config.bundle?.windows?.allowDowngrades === false) {
    throw new Error('Version or configuration does not permit the installer round trip');
  }
  const next = structuredClone(config);
  next.version = `${parts[0]}.${parts[1]}.${parts[2] + 1}`;
  return next;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.env.GITHUB_ACTIONS !== 'true' || process.env.RUNNER_OS !== 'Windows' ||
      process.platform !== 'win32' || process.argv.length !== 3 || !process.env.RUNNER_TEMP) {
    throw new Error('Installer upgrade fixtures require the disposable native Windows runner');
  }
  const output = resolve(process.argv[2]);
  const contained = relative(resolve(process.env.RUNNER_TEMP), output);
  if (!contained || contained === '..' || contained.startsWith(`..${sep}`) || resolve(contained) === contained) {
    throw new Error('Installer fixtures must stay below the runner directory');
  }
  const configPath = resolve('src-tauri/tauri.complete.generated.json');
  const config = JSON.parse(readFileSync(configPath, 'utf8'));
  const next = upgradeConfig(config);
  const directory = resolve('src-tauri/target/debug/bundle/nsis');
  const names = readdirSync(directory).filter(name => name.endsWith('.exe'));
  if (names.length !== 1) throw new Error('Expected one initial testing installer');
  const source = join(directory, names[0]);
  const info = lstatSync(source);
  if (!info.isFile() || info.isSymbolicLink()) throw new Error('Testing installer must be a regular file');
  mkdirSync(output, { mode: 0o700 }); // Refuse reuse of another acceptance's files.
  const baseline = join(output, 'baseline.exe');
  copyFileSync(source, baseline);
  const upgradePath = join(dirname(configPath), 'tauri.upgrade-testing.generated.json');
  writeFileSync(upgradePath, JSON.stringify(next, null, 2) + '\n');
  writeFileSync(join(output, 'fixture.json'), JSON.stringify({
    syntheticOnly: true, baselineVersion: config.version, upgradeVersion: next.version,
    baselineInstaller: baseline, baselineSha256: createHash('sha256').update(readFileSync(baseline)).digest('hex'),
    sameRuntimeSource: true, signedInstaller: false,
  }, null, 2) + '\n');
  console.log(`Prepared installation-only ${config.version} → ${next.version} → ${config.version} acceptance`);
}
