#!/bin/bash
#
# Runs once per container start. Anything that needs to persist across
# restarts (CA cert, cert DB, virus signatures) lives on a volume and is
# only generated the first time it's missing — so re-creating the
# container doesn't silently rotate your CA or wipe signatures.
set -euo pipefail

CA_DIR="/etc/squid/ssl_cert"
CERTGEN_BIN="/usr/lib/squid/security_file_certgen"

# ---------------------------------------------------------------------------
# 1. CA cert — generate once, persist on the mounted volume from then on
# ---------------------------------------------------------------------------
mkdir -p "$CA_DIR"
if [ ! -f "$CA_DIR/squidCA.pem" ]; then
  echo "[entrypoint] No CA cert found — generating a new one (first boot)."
  cd "$CA_DIR"
  openssl req -new -newkey rsa:2048 -sha256 -days 3650 -nodes -x509 \
    -keyout squidCA.pem -out squidCA.pem \
    -subj "/CN=Squid SSL Inspection CA"
  openssl x509 -in squidCA.pem -outform DER -out squidCA.der
  echo "[entrypoint] New CA at $CA_DIR/squidCA.der — distribute this to client machines."
else
  echo "[entrypoint] Existing CA cert found on volume — reusing it (clients stay trusted across restarts)."
fi

# ---------------------------------------------------------------------------
# 2. SSL cert database
#    Squid's sslcrtd_program helper requires a pre-initialized cert DB or it
#    crashes (and takes Squid down with it) on the first SSL-bumped request.
#    Our Dockerfile points it at /var/lib/squid/ssl_db, but the Ubuntu package
#    default is /var/spool/squid/ssl_db — and on some architectures the
#    squid-openssl package ships that default *active* (uncommented), so Squid
#    resolves to /var/spool/squid/ssl_db there. Initialize BOTH paths so Squid
#    starts no matter which one the active config uses. Runs before supervisord
#    (and therefore before Squid).
# ---------------------------------------------------------------------------
for SSL_DB in /var/lib/squid/ssl_db /var/spool/squid/ssl_db; do
  PARENT_DIR="$(dirname "$SSL_DB")"
  mkdir -p "$PARENT_DIR"
  chown proxy:proxy "$PARENT_DIR"
  # Check whether the ssl_db directory actually has content, not just whether
  # it exists — an empty dir (e.g. a freshly-mounted tmpfs) would pass a bare
  # `-d` test and skip initialization, leaving sslcrtd_program to crash.
  if [ ! -d "$SSL_DB" ] || [ -z "$(ls -A "$SSL_DB" 2>/dev/null)" ]; then
    echo "[entrypoint] SSL cert DB missing or empty at $SSL_DB — initializing."
    # security_file_certgen -c insists on creating the directory itself and
    # fails with EEXIST if it already exists, so remove it first.
    rm -rf "$SSL_DB"
    "$CERTGEN_BIN" -c -s "$SSL_DB" -M 4MB
  else
    echo "[entrypoint] Existing, populated SSL cert DB found at $SSL_DB — reusing it."
  fi
  # security_file_certgen -c runs as root (entrypoint is root), so it creates
  # index.txt/certs/size owned by root. Squid later drops privileges to the
  # proxy user and spawns this helper as proxy, which then can't lock index.txt
  # — surfacing as "certificate_db lock" on every SSL-bumped request. Re-home
  # the whole DB to proxy.
  chown -R proxy:proxy "$SSL_DB"
done

# ---------------------------------------------------------------------------
# 3. Managed config (dashboard-owned) — Squid's config Includes
#    /etc/squid/managed/rules.conf, so that file must exist before Squid's
#    first parse or startup fails outright. Squid's error_directory also
#    now points into this same volume, which means ALL standard error
#    templates (not just the one the dashboard customizes) must live
#    there too, or Squid can't find templates for other error types and
#    refuses to start. Both are seeded once, on first boot only — the
#    dashboard subsequently owns rules.conf entirely, and only ever
#    overwrites the one template file it customizes, leaving the rest
#    of the seeded set alone.
# ---------------------------------------------------------------------------
mkdir -p /etc/squid/managed/lists /etc/squid/managed/errors

if [ ! -f /etc/squid/managed/rules.conf ]; then
  echo "[entrypoint] No managed rules.conf yet — creating a permissive placeholder."
  cat > /etc/squid/managed/rules.conf <<'RULES'
# No dashboard rules applied yet.
# Placeholder default policy — allow all (matches the dashboard's
# "Allow all / blacklist" default) so the proxy is usable out of the box.
http_access allow all
RULES
fi

if [ ! -d /etc/squid/managed/errors/en ] || [ -z "$(ls -A /etc/squid/managed/errors/en 2>/dev/null)" ]; then
  echo "[entrypoint] Seeding default Squid error templates into the managed volume."
  DEFAULT_ERRORS=""
  for candidate in /usr/share/squid/errors/en /usr/share/squid/errors/templates; do
    if [ -d "$candidate" ]; then
      DEFAULT_ERRORS="$candidate"
      break
    fi
  done
  if [ -n "$DEFAULT_ERRORS" ]; then
    mkdir -p /etc/squid/managed/errors/en
    cp -n "$DEFAULT_ERRORS"/* /etc/squid/managed/errors/en/ 2>/dev/null || true
    # Replace the stock block page with a friendlier default (matching the
    # dashboard's DEFAULT_ERROR_HTML) so blocked users see a clean page out
    # of the box. The %U/%i/%h/%T codes are substituted by Squid at request
    # time.
    cat > /etc/squid/managed/errors/en/ERR_ACCESS_DENIED <<'BLOCK_HTML'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ProxSea: Access blocked</title>
<style>
  *{box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f8fafc;color:#0f172a;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px}
  .card{background:#fff;border:1px solid #e2e8f0;border-radius:14px;padding:36px 40px;max-width:560px;flex:1;text-align:center;box-shadow:0 8px 30px rgba(15,23,42,.08)}
  .icon{display:flex;align-items:center;justify-content:center;margin:0 auto 16px;width:56px;height:56px;border-radius:14px;background:#fef3c7;color:#d97706}
  h1{font-size:22px;margin:0 0 8px;letter-spacing:-.01em}
  .desc{color:#475569;font-size:14px;line-height:1.6;margin:0 0 20px}
  .meta{background:#f8fafc;border:1px solid #eef2f7;border-radius:10px;padding:14px 18px;font-size:13px;color:#334155;text-align:left;word-break:break-all}
  .meta div{display:flex;gap:12px;padding:5px 0}
  .meta b{flex:0 0 84px;color:#0f172a;font-weight:600}
  .meta span{flex:1}
  .contact{margin-top:18px;font-size:13px;color:#64748b}
  .foot{margin-top:24px;padding-top:16px;border-top:1px solid #eef2f7;font-size:12px;color:#94a3b8}
</style>
</head>
<body>
  <div class="card">
    <div class="icon">
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
    </div>
    <h1><b>ProxSea: </b>Access blocked</h1>
    <p class="desc">This website has been blocked by your network's content policy.</p>
    <div class="meta">
      <div><b>Website</b><span>%U</span></div>
      <div><b>Your IP</b><span>%i</span></div>
      <div><b>Time</b><span>%T</span></div>
    </div>
    <p class="contact">If you believe this is a mistake, contact your administrator.</p>
    <div class="foot">Protected by %h</div>
  </div>
</body>
</html>
BLOCK_HTML
    echo "[entrypoint] Seeded error templates from $DEFAULT_ERRORS."
  else
    echo "[entrypoint] WARNING: couldn't find Squid's default error templates to seed — error_directory may be incomplete until the dashboard saves a custom page."
  fi
fi

# ---------------------------------------------------------------------------
# 4. c-icap virus-blocked page — c-icap's VIRUS_FOUND template is a
#    symlink into this volume (see Dockerfile), so it must exist before
#    c-icap starts or the "virus found" page renders blank. Seeded once,
#    on first boot only; the dashboard subsequently owns this file and
#    overwrites it when a custom virus page is saved. The %VVN/%huo/%VVV
#    tokens are substituted by c-icap at request time.
# ---------------------------------------------------------------------------
if [ ! -f /etc/squid/managed/virus_found.html ]; then
  echo "[entrypoint] Seeding default c-icap virus-blocked page."
  cat > /etc/squid/managed/virus_found.html <<'VIRUS_HTML'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ProxSea: Threat blocked</title>
<style>
  *{box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f8fafc;color:#0f172a;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px}
  .card{background:#fff;border:1px solid #e2e8f0;border-radius:14px;padding:36px 40px;max-width:560px;flex:1;text-align:center;box-shadow:0 8px 30px rgba(15,23,42,.08)}
  .icon{display:flex;align-items:center;justify-content:center;margin:0 auto 16px;width:56px;height:56px;border-radius:14px;background:#fee2e2;color:#dc2626}
  h1{font-size:22px;margin:0 0 8px;letter-spacing:-.01em}
  .desc{color:#475569;font-size:14px;line-height:1.6;margin:0 0 20px}
  .meta{background:#f8fafc;border:1px solid #eef2f7;border-radius:10px;padding:14px 18px;font-size:13px;color:#334155;text-align:left;word-break:break-all}
  .meta div{display:flex;gap:12px;padding:5px 0}
  .meta b{flex:0 0 84px;color:#0f172a;font-weight:600}
  .meta span{flex:1}
  .contact{margin-top:18px;font-size:13px;color:#64748b}
  .foot{margin-top:24px;padding-top:16px;border-top:1px solid #eef2f7;font-size:12px;color:#94a3b8}
</style>
</head>
<body>
  <div class="card">
    <div class="icon">
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
    </div>
    <h1><b>ProxSea: </b>Threat blocked</h1>
    <p class="desc">This file was blocked because it appears to contain a virus or malware.</p>
    <div class="meta">
      <div><b>Threat</b><span>%VVN</span></div>
      <div><b>Website</b><span>%huo</span></div>
      <div><b>Engine</b><span>%VVV</span></div>
    </div>
    <p class="contact">If you believe this is a mistake, contact your administrator.</p>
    <div class="foot">Scanned by ClamAV</div>
  </div>
</body>
</html>
VIRUS_HTML
  chmod 644 /etc/squid/managed/virus_found.html
else
  echo "[entrypoint] Existing c-icap virus-blocked page found — reusing it."
fi

# ---------------------------------------------------------------------------
# 5. Runtime directories under /run — these are tmpfs and get wiped on
#    every container start, so they must be (re)created here rather than
#    at build time. Normally the Debian init scripts (service X start)
#    create these automatically; since supervisord launches the daemons
#    directly, nobody does it for us.
# ---------------------------------------------------------------------------
mkdir -p /var/run/clamav /var/run/c-icap /var/run/squid
chown clamav:clamav /var/run/clamav
chown proxy:proxy /var/run/squid
if id c-icap >/dev/null 2>&1; then
  chown c-icap:c-icap /var/run/c-icap
fi

# /var/log/squid is a shared volume (the dashboard reads access.log +
# cache.log read-only). A freshly-created named volume is root-owned, so
# re-home it to proxy here or Squid (which drops to the proxy user) can't
# open its own log files after the volume is first mounted.
mkdir -p /var/log/squid
chown proxy:proxy /var/log/squid

# ---------------------------------------------------------------------------
# 6. ClamAV signatures — only fetch on first boot if the volume is empty;
#    afterwards the freshclam daemon (managed by supervisord) keeps them
#    updated in the background.
# ---------------------------------------------------------------------------
if [ ! -f /var/lib/clamav/daily.cvd ] && [ ! -f /var/lib/clamav/daily.cld ]; then
  echo "[entrypoint] No virus signatures found — running initial freshclam (this can take a minute)."
  freshclam || echo "[entrypoint] WARNING: initial freshclam failed — check network access to database.clamav.net"
else
  echo "[entrypoint] Existing virus signatures found on volume."
fi

# ---------------------------------------------------------------------------
# 7. Hand off to supervisord, which manages clamd / freshclam /
#    c-icap / squid as long-running sibling processes and restarts any
#    that crash — this replaces the `service X start` + manual PID
#    cleanup dance from the interactive session.
# ---------------------------------------------------------------------------
echo "[entrypoint] Starting supervisord..."
exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
