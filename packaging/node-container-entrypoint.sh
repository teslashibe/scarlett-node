#!/bin/sh
set -eu
# This ancestor is root-owned in the image; never repair/chown a user's tree.
if [ -f /run/secrets/x_login_bearer ]; then
    if [ -L /run/scarlett-browser ] || [ ! -d /run/scarlett-browser ]; then
        echo 'Private browser startup directory unavailable' >&2; exit 1
    fi
    private=$(mktemp -d /run/scarlett-browser/node.XXXXXX)
    # Publish the secret before granting the node access to this fresh leaf.
    install -m 600 -o 10001 -g 10001 /run/secrets/x_login_bearer "$private/bearer"
    chown 10001:10001 "$private"
    export SCARLETT_X_LOGIN_BEARER_FILE="$private/bearer"
fi
exec /usr/sbin/gosu node scarlett-node "$@"
