#!/bin/bash
# Watches for the dashboard's reload-trigger file (touched every time
# "Apply" is clicked) and reconfigures Squid in place when it changes —
# squid -k reconfigure re-reads config without dropping existing
# connections, unlike a full restart.
set -euo pipefail

TRIGGER_FILE="/etc/squid/managed/.reload_trigger"
LAST_SEEN=""

mkdir -p /etc/squid/managed

echo "[watch-config] Watching for changes to $TRIGGER_FILE"

while true; do
  if [ -f "$TRIGGER_FILE" ]; then
    CURRENT="$(cat "$TRIGGER_FILE" 2>/dev/null || echo "")"
    if [ -n "$CURRENT" ] && [ "$CURRENT" != "$LAST_SEEN" ]; then
      echo "[watch-config] Change detected — reconfiguring Squid."
      if squid -k reconfigure 2>&1; then
        echo "[watch-config] Squid reconfigured successfully."
      else
        echo "[watch-config] WARNING: squid -k reconfigure failed — check cache.log."
      fi

      # Also refresh c-icap so a newly-saved virus-blocked page takes effect
      # immediately instead of waiting for its template cache (TemplateReloadTime)
      # to expire. "reconfigure" re-reads config and re-reads the VIRUS_FOUND
      # template (a symlink into the managed volume).
      if [ -p /var/run/c-icap/c-icap.ctl ]; then
        if printf '%s' 'reconfigure' > /var/run/c-icap/c-icap.ctl 2>/dev/null; then
          echo "[watch-config] c-icap reconfigured (virus page refreshed)."
        else
          echo "[watch-config] WARNING: c-icap reconfigure failed."
        fi
      fi
      LAST_SEEN="$CURRENT"
    fi
  fi
  sleep 2
done
