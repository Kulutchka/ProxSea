#!/bin/bash
# supervisord starts every program at roughly the same time. c-icap needs
# clamd to be fully ready — the socket present AND clamd answering PING — or
# its virus_scan engine fails to load with:
#     "Registry 'virus_scan::engines' does not exist!"
# ...and then nothing gets scanned. On slow devices (e.g. a Raspberry Pi
# loading ~300MB of signatures from an SD card) clamd can take a few minutes,
# so wait generously and actually ping clamd instead of trusting the socket
# file's existence alone (the socket can appear before clamd accepts clients).
set -e

SOCKET=/var/run/clamav/clamd.ctl
MAX_WAIT=300   # 5 minutes — ample even on a cold SD-card Pi
WAITED=0

# Returns 0 once clamd answers a PING with PONG.
clamd_ready() {
    [ -S "$SOCKET" ] || return 1
    python3 - "$SOCKET" <<'PY' 2>/dev/null
import socket, sys
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect(sys.argv[1])
    s.sendall(b"PING\n")
    ok = b"PONG" in s.recv(64)
    s.close()
    sys.exit(0 if ok else 1)
except Exception:
    sys.exit(1)
PY
}

echo "[wait-for-clamd] Waiting for clamd to be ready at $SOCKET ..."
while [ "$WAITED" -lt "$MAX_WAIT" ]; do
    if clamd_ready; then
        echo "[wait-for-clamd] clamd ready after ${WAITED}s — starting c-icap."
        exec /usr/bin/c-icap -N -D
    fi
    sleep 2
    WAITED=$((WAITED + 2))
done

echo "[wait-for-clamd] Gave up after ${MAX_WAIT}s — clamd never became ready. Starting c-icap anyway; it will likely fail."
exec /usr/bin/c-icap -N -D
