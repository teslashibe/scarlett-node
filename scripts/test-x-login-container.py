#!/usr/bin/env python3
"""Packaging smoke using a synthetic secret and capability reads; no provider work."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parent.parent

def run(arguments, **kwargs):
    return subprocess.run(arguments, check=True, cwd=ROOT, text=True, **kwargs)

def main():
    identifier = uuid.uuid4().hex[:12]
    helper = 'scarlett-x-smoke-' + identifier
    volume = helper + '-profiles'
    go_image = helper + '-go'
    with tempfile.TemporaryDirectory(prefix='scarlett-x-packaging-') as temporary:
        work = Path(temporary)
        secret = work / 'secret'
        secret.write_text('synthetic-packaging-bearer-' + identifier)
        secret.chmod(0o600)
        run(['docker', 'build', '--platform', 'linux/amd64', '-f', 'packaging/x-login.Dockerfile', '-t', 'scarlett-x-login:acceptance', '.'])
        env = dict(os.environ, GOOS='linux', GOARCH='amd64', CGO_ENABLED='0')
        run(['go', 'test', '-c', '-o', str(work / 'scarlett-node'), './internal/xloginruntime'], env=env)
        shutil.copyfile(ROOT / 'packaging/node-container-entrypoint.sh', work / 'entrypoint.sh')
        (work / 'Dockerfile').write_text('FROM scarlett-x-login:acceptance\nRUN usermod -u 10001 node && groupmod -g 10001 node && mkdir -m 755 /run/scarlett-browser\nCOPY scarlett-node /usr/local/bin/scarlett-node\nCOPY entrypoint.sh /entrypoint.sh\nENTRYPOINT ["/bin/sh", "/entrypoint.sh"]\n')
        run(['docker', 'build', '--platform', 'linux/amd64', '-t', go_image, str(work)])
        try:
            run(['docker', 'run', '-d', '--name', helper, '--platform', 'linux/amd64', '--init', '--network', 'none', '--mount', f'type=bind,src={secret},dst=/run/secrets/x_login_bearer,readonly', '--mount', f'type=volume,src={volume},dst=/profiles', 'scarlett-x-login:acceptance'], capture_output=True)
            # Every request is loopback, inside a container with no network route.
            check = "const u='http://127.0.0.1:8090';for(let i=0;;i++){try{if((await fetch(u+'/v1/ready')).status===200)break}catch{}if(i===100)throw Error('readiness failed');await new Promise(r=>setTimeout(r,100))}if((await fetch(u+'/v1/capabilities')).status!==401)throw Error('bearer missing');console.log('loopback readiness and bearer protection passed')"
            run(['docker', 'exec', helper, 'node', '--input-type=module', '-e', check])
            run(['docker', 'run', '--rm', '--platform', 'linux/amd64', '--network', 'container:' + helper, '--mount', f'type=bind,src={secret},dst=/run/secrets/x_login_bearer,readonly', '-e', 'SCARLETT_TEST_X_LOGIN_EXTERNAL_URL=http://127.0.0.1:8090', go_image, '-test.run=TestExternalEndpointPrivateBearerOptIn', '-test.v'])
            browser = "import {chromium} from './third_party/social-login/node_modules/playwright/index.mjs';const b=await chromium.launch({executablePath:'/opt/google/chrome/chrome',headless:false,args:['--no-sandbox','--use-gl=angle','--use-angle=gl','--ignore-gpu-blocklist']});const p=await b.newPage();await p.goto('about:blank');await b.close();console.log('headed Google Chrome local launch and cleanup passed')"
            run(['docker', 'exec', '--user', 'node', helper, 'node', '--input-type=module', '-e', browser])
            version = run(['docker', 'exec', helper, '/opt/google/chrome/chrome', '--version'], capture_output=True).stdout.strip()
            run(['docker', 'stop', '--time', '35', helper], capture_output=True)
            state = json.loads(run(['docker', 'inspect', helper], capture_output=True).stdout)[0]['State']
            assert state['ExitCode'] == 0 and not state['OOMKilled'], 'companion did not stop cleanly'
            print(json.dumps({'containerReadiness': 'passed', 'bearerRequired': 'passed', 'goPrivateSecretAndCapabilities': 'passed', 'cleanShutdown': 'passed', 'profileVolume': volume, 'chromeVersion': version, 'providerRequests': 0}))
        finally:
            subprocess.run(['docker', 'rm', '-f', helper], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['docker', 'volume', 'rm', volume], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['docker', 'image', 'rm', go_image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

if __name__ == '__main__':
    main()
