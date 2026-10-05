// Opt-in HTTP/Chromium contract fixture. Every browser request is intercepted;
// no provider credentials, account profiles or provider traffic are used.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
const profiles = fs.mkdtempSync(path.join(os.tmpdir(), 'scarlett-x-http-contract-'));
process.env.CAP_PROFILE_BASE = profiles;
process.env.CAP_HEADLESS = 'true';
const {chromium} = await import('../third_party/social-login/node_modules/playwright/index.mjs');
const launch = chromium.launchPersistentContext.bind(chromium);
const observed = {launches: 0, passwords: 0, codes: [], navigations: 0, retainedPageContinuations: 0, validAfterStaleRejection: false};
let retainedPage, nativeWait;
chromium.launchPersistentContext = async (dir, options) => {
  observed.launches++;
  const context = await launch(dir, options);
  await context.exposeFunction('fixturePassword', () => observed.passwords++);
  await context.exposeFunction('fixtureCode', async (code, staleRejection) => {
    observed.codes.push(code);
    if (code === '123456') {
      observed.validAfterStaleRejection = staleRejection === true;
      await new Promise(resolve => setTimeout(resolve, 3000));
    }
  });
  await context.route('**/*', async route => {
    const request = route.request();
    if (request.isNavigationRequest()) observed.navigations++;
    const pathname = new URL(request.url()).pathname;
    if (pathname === '/home') {
      await context.addCookies(['auth_token', 'ct0'].map(name => ({name, value: 'synthetic-' + name, domain: '.x.com', path: '/', secure: true})));
      return route.fulfill({contentType: 'text/html', body: '<html><body>Authenticated fixture</body></html>'});
    }
    const login = `<html><body><div id="layers"><input name="username_or_email"><button onclick="document.querySelector('#layers').innerHTML='<input name=password type=password><button onclick=submitPassword()>Log in</button>'">Next</button></div><script>
      async function submitPassword(){window.fixtureState='submitting-password';await window.fixturePassword();document.querySelector('#layers').innerHTML='<p>Enter your verification code</p><input name=code autocomplete=one-time-code><button onclick=submitCode()>Verify</button>';window.fixtureState='challenge';}
      async function submitCode(){const code=document.querySelector('input[name=code]').value;await window.fixtureCode(code,document.querySelector('p').textContent==='Incorrect verification code');if(code==='123456')location.href='/home';else document.querySelector('p').textContent='Incorrect verification code';}
    </script></body></html>`;
    return route.fulfill({contentType: 'text/html', body: pathname === '/' ? '<html><body><a href="/i/flow/login">Sign in</a></body></html>' : login});
  });
  const page = context.pages()[0];
  retainedPage = page;
  const wait = page.waitForTimeout.bind(page); nativeWait = wait;
  page.waitForTimeout = async ms => {
    await wait(Math.min(ms, 10));
    await page.waitForFunction(() => window.fixtureState !== 'submitting-password', null, {timeout: 10000});
    if (observed.passwords) await page.locator('input[name="code"]').waitFor({state: 'visible', timeout: 10000});
  };
  return context;
};
const {SocialLoginService} = await import('../third_party/social-login/src/service.js');
const {createServer} = await import('../third_party/social-login/src/server.js');
const {__test: runtime} = await import('../third_party/social-login/src/runtime/legacy.js');
const service = new SocialLoginService({runtime: {...runtime, async runBrowserLogin(platform, input, ...args) {
  if (input.challengeHold) {
    if (input.challengeHold.page === retainedPage) observed.retainedPageContinuations++;
    // Submission settlement exercises the production wait and polling path.
    retainedPage.waitForTimeout = nativeWait;
  }
  return runtime.runBrowserLogin(platform, input, ...args);
}}});
const server = createServer(service, 'synthetic-contract-bearer');
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
console.log(JSON.stringify({url: `http://127.0.0.1:${server.address().port}`}));
let stopping = false;
async function stop() {
  if (stopping) return;
  stopping = true;
  await service.shutdown(3000);
  server.closeIdleConnections();
  await new Promise(resolve => server.close(resolve));
  fs.rmSync(profiles, {recursive: true, force: true});
  console.log(JSON.stringify({observed}));
}
process.stdin.resume();
process.stdin.once('end', () => void stop());
process.once('SIGTERM', () => void stop());
