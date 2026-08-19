#!/bin/bash
# supervisord starts every program at roughly the same time. c-icap needs
# clamd's socket to already exist or it fails immediately with
# "Registry 'virus_scan::engines' does not exist!" and exits — this
# waits for the socket file first instead of hoping priority ordering
# in supervisord.conf is enough (it isn't, reliably).
set -e

SOCKET=/var/run/clamav/clamd.ctl
WAITED=0
MAX_WAIT=60

echo "[wait-for-clamd] Waiting for clamd socket at $SOCKET ..."
until [ -S "$SOCKET" ]; do
  sleep 1
  WAITED=$((WAITED + 1))
  if [ "$WAITED" -ge "$MAX_WAIT" ]; then
    echo "[wait-for-clamd] Gave up after ${MAX_WAIT}s — clamd never came up. Starting c-icap anyway; it will likely fail."
    break
  fi
done
echo "[wait-for-clamd] clamd socket ready after ${WAITED}s — starting c-icap."

exec /usr/bin/c-icap -N -D
