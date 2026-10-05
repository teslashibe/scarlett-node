#!/bin/sh
set -eu

node /app/inject-capsolver-key.mjs

if [ "${CAP_HEADLESS:-false}" = "true" ]; then
  exec "$@"
fi

export DISPLAY="${DISPLAY:-:99}"
mkdir -p /tmp/.X11-unix
chmod 1777 /tmp/.X11-unix 2>/dev/null || true
if xdpyinfo >/dev/null 2>&1; then
  echo "display ${DISPLAY} is already occupied" >&2
  exit 1
fi

display_num="${DISPLAY#:}"
lock="/tmp/.X${display_num}-lock"
sock="/tmp/.X11-unix/X${display_num}"
if [ -e "$lock" ] || [ -S "$sock" ]; then
  lockpid=$(tr -dc '0-9' < "$lock" 2>/dev/null || true)
  if [ -n "$lockpid" ] && kill -0 "$lockpid" 2>/dev/null; then
    echo "display ${DISPLAY} lock is owned by live pid $lockpid" >&2
    exit 1
  fi
  rm -f "$lock" "$sock"
  echo "{\"event\":\"stale_xvfb_lock_recovered\",\"display\":\"${DISPLAY}\"}"
fi

Xvfb "$DISPLAY" -screen 0 1280x1024x24 -nolisten tcp &
xvfb_pid=$!
i=0
until xdpyinfo >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -ge 50 ] || ! kill -0 "$xvfb_pid" 2>/dev/null; then
    echo "Xvfb failed to become ready on ${DISPLAY}" >&2
    kill "$xvfb_pid" 2>/dev/null || true
    exit 1
  fi
  sleep 0.1
done

term() {
  if [ -n "${node_pid:-}" ]; then
    kill -TERM "$node_pid" 2>/dev/null || true
    wait "$node_pid" 2>/dev/null || true
  fi
  kill -TERM "$xvfb_pid" 2>/dev/null || true
  wait "$xvfb_pid" 2>/dev/null || true
}
trap term TERM INT

"$@" &
node_pid=$!
set +e
wait "$node_pid"
status=$?
set -e
kill -TERM "$xvfb_pid" 2>/dev/null || true
wait "$xvfb_pid" 2>/dev/null || true
exit "$status"
