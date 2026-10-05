#!/bin/sh
set -eu
if [ "${1:-}" != service ]; then
    # The read-only Compose secret can be host0600 or Docker0444. Only trusted
    # root startup reads it; the browser service itself runs as UID1000.
    SOCIAL_LOGIN_BEARER_TOKEN=$(cat /run/secrets/x_login_bearer)
    export SOCIAL_LOGIN_BEARER_TOKEN
    if [ ${#SOCIAL_LOGIN_BEARER_TOKEN} -lt 32 ]; then echo 'Private X login bearer missing or too short' >&2; exit 1; fi
    exec /usr/sbin/gosu node /bin/sh /app/x-login-entrypoint.sh service
fi
Xvfb :99 -screen 0 1365x768x24 -nolisten tcp &
xvfb_pid=$!
node /app/third_party/social-login/src/server.js &
service_pid=$!
stop() { trap - TERM INT; kill -TERM "$service_pid" 2>/dev/null || true; wait "$service_pid" || true; kill -TERM "$xvfb_pid" 2>/dev/null || true; wait "$xvfb_pid" || true; }
terminated=0
trap 'terminated=1; stop' TERM INT
wait "$service_pid" || result=$?
stop
if [ "$terminated" -eq 1 ]; then exit 0; fi
exit "${result:-0}"
