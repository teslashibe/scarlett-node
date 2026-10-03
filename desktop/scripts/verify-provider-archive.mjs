// These checks cover official native packages reviewed for this release.
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
const pins = {
  '@openai/codex@0.159.2-darwin-arm64': '7SPaPFU0tdqapQ5VEgrF+wb+p9dxfWfLMXMKZMRKoWPn/tLMajlMjYBBnu8o6VtaVH2DHQ6kpnp5TMkv5bqvrg==',
  '@openai/codex@0.159.2-darwin-x64': 'VPZGYHH2yVn8S3IuxJk38vxhBADJZp68IBL8hr4quJ2R7jM16l43TLCwRemN+1J27V/cs771fbx63aGRf5F8JA==',
  '@openai/codex@0.159.2-win32-x64': '1ZJVTO40/ZaHPUUWc3uCX73jwzJRaDxAjRQEf37dC5Q3h1fp/Z7+1L8oX3bPlXgjhEY6kHW3rm0wz2sdQ5rxNw==',
  '@anthropic-ai/claude-code-darwin-arm64@2.1.286': 'QlU1+S7cNO1BKzlMJGRR/ZqdsP6c3+QAA2u9EX7dTO6HUo1/RAenn/q+mlyX60MZzTZOjPkAmTt77eYrH1IAwg==',
  '@anthropic-ai/claude-code-darwin-x64@2.1.286': 'RlnglbMpkdvIdKzPphXI+KMwXefKpMJXYGpGAfpTI6XvkDcjgj5j8WXxvoySyl2qTetWOEqjkFB/V8rtW4qp4g==',
  '@anthropic-ai/claude-code-win32-x64@2.1.286': 'Cvq6m1e2eP0p47Ze+b6rw+DjXMhLCcT9g8ZKfFDxT0NB9d9mjHcNs6Qjb1oTqbO6AsN3Ie1DIqWt50J7kboz7g==',
};
const [pkg, archive] = process.argv.slice(2);
if (process.argv.length !== 4 || !Object.hasOwn(pins, pkg)) throw new Error('Supply a reviewed provider package and downloaded archive path');
if (createHash('sha512').update(readFileSync(archive)).digest('base64') !== pins[pkg]) throw new Error('Provider archive differs from the reviewed release');
console.log(`Verified pinned native archive: ${pkg}`);
