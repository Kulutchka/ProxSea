FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------------------------
# 1. Packages
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server \
        squid-openssl \
        c-icap libc-icap-mod-virus-scan \
        clamav clamav-daemon clamav-freshclam \
        supervisor \
        openssl \
        iproute2 iptables \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# 2. SSH: enable root login (password is set at runtime, never baked in)
# ---------------------------------------------------------------------------
RUN mkdir -p /var/run/sshd \
    && sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && (grep -q "^PermitRootLogin" /etc/ssh/sshd_config || echo "PermitRootLogin yes" >> /etc/ssh/sshd_config)

# ---------------------------------------------------------------------------
# 3. Squid: static config additions (same lines validated in the manual
#    debugging session — intercept ports, ssl-bump, ICAP wiring, explicit
#    proxy port with bump enabled). CA cert paths point into a volume
#    mounted at runtime, not baked into the image.
# ---------------------------------------------------------------------------
RUN sed -i "s|^http_port 3128\s*\$|http_port 3128 ssl-bump generate-host-certificates=on dynamic_cert_mem_cache_size=4MB cert=/etc/squid/ssl_cert/squidCA.pem|" /etc/squid/squid.conf \
    && sed -i '/^include \/etc\/squid\/conf.d\/\*\.conf$/i include /etc/squid/managed/rules.conf' /etc/squid/squid.conf \
    && cat >> /etc/squid/squid.conf <<'EOF'

# --- SSL-bump / transparent intercept ---
http_port 3129 intercept
https_port 3130 intercept ssl-bump cert=/etc/squid/ssl_cert/squidCA.pem generate-host-certificates=on dynamic_cert_mem_cache_size=4MB
sslcrtd_program /usr/lib/squid/security_file_certgen -s /var/lib/squid/ssl_db -M 4MB
sslcrtd_children 8 startup=1 idle=1
acl step1 at_step SslBump1
ssl_bump peek step1
ssl_bump bump all

# LAB DEFAULT — accepts any backend cert error. Tighten before real use.
sslproxy_cert_error allow all

# --- ICAP / ClamAV wiring ---
icap_enable on
icap_preview_enable on
icap_preview_size 128
icap_service avscan reqmod_precache icap://127.0.0.1:1344/avscan
adaptation_access avscan allow all
icap_service avscan2 respmod_precache icap://127.0.0.1:1344/avscan
adaptation_access avscan2 allow all

# --- Custom error templates, managed by the dashboard ---
# Populated at first boot (see entrypoint.sh) with Squid's default
# templates, then selectively overwritten (e.g. ERR_ACCESS_DENIED) by
# the dashboard when a custom error page is saved.
error_directory /etc/squid/managed/errors/en
EOF

# ---------------------------------------------------------------------------
# 4. c-icap: wire in the real virus_scan service (do NOT hand-add a
#    "Service avscan virus_scan.so" line — it collides with the
#    ServiceAlias already defined in virus_scan.conf and gets silently
#    dropped, which is the exact bug that cost the most time manually).
# ---------------------------------------------------------------------------
RUN echo "Include virus_scan.conf" >> /etc/c-icap/c-icap.conf \
    && sed -i 's/^#Include clamd_mod.conf/Include clamd_mod.conf/' /etc/c-icap/virus_scan.conf

# ---------------------------------------------------------------------------
# 4a. c-icap virus-blocked page: the virus_scan service serves VIRUS_FOUND
#    (simple mode, used by Squid's /avscan alias) from
#    /usr/share/c_icap/templates/virus_scan/en/. Replace it with a symlink
#    into the dashboard-shared managed volume so the dashboard can
#    customize the "virus found" page. The entrypoint seeds a default file
#    there on first boot; c-icap follows the symlink transparently and
#    re-reads it when its template cache expires / on reconfigure.
# ---------------------------------------------------------------------------
RUN ln -sf /etc/squid/managed/virus_found.html \
        /usr/share/c_icap/templates/virus_scan/en/VIRUS_FOUND

# ---------------------------------------------------------------------------
# 4b. ClamAV: let freshclam notify the running clamd process immediately
#    when new signatures are downloaded, instead of relying on clamd's own
#    periodic self-check (every 3600s by default) or a container restart.
# ---------------------------------------------------------------------------
RUN echo "NotifyClamd /etc/clamav/clamd.conf" >> /etc/clamav/freshclam.conf

# ---------------------------------------------------------------------------
# 5. Directories for volume mount points (created here so ownership/perms
#    are right even before a volume is attached)
# ---------------------------------------------------------------------------
RUN mkdir -p /etc/squid/ssl_cert /var/lib/squid /var/lib/clamav /etc/squid/managed/lists /etc/squid/managed/errors \
    && chown proxy:proxy /var/lib/squid

# ---------------------------------------------------------------------------
# 6. Process supervision (no systemd/PID1 init in a container, so
#    supervisord manages sshd, clamd, freshclam, c-icap, and squid as
#    sibling processes instead of relying on `service` scripts)
# ---------------------------------------------------------------------------
COPY supervisord.conf /etc/supervisor/conf.d/services.conf
COPY entrypoint.sh /entrypoint.sh
COPY wait-for-clamd.sh /usr/local/bin/wait-for-clamd.sh
COPY watch-config.sh /usr/local/bin/watch-config.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/wait-for-clamd.sh /usr/local/bin/watch-config.sh

EXPOSE 22 3128 3129 3130 1344

VOLUME ["/etc/squid/ssl_cert", "/var/lib/clamav", "/etc/squid/managed"]

ENTRYPOINT ["/entrypoint.sh"]
