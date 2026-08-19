import os
import re
import sqlite3
import time
import secrets
import threading
import logging
import urllib.request
import urllib.error
import urllib.parse
from functools import wraps
from flask import Flask, request, redirect, url_for, session, render_template, flash, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.environ.get("DASHBOARD_DB_PATH", "/data/dashboard.db")
MANAGED_DIR = os.environ.get("MANAGED_CONFIG_DIR", "/etc/squid/managed")
LISTS_DIR = os.path.join(MANAGED_DIR, "lists")
ERRORS_DIR = os.path.join(MANAGED_DIR, "errors", "en")
RULES_CONF = os.path.join(MANAGED_DIR, "rules.conf")
RELOAD_TRIGGER = os.path.join(MANAGED_DIR, ".reload_trigger")
DEFAULT_ERROR_TEMPLATE_BACKUP = os.path.join(MANAGED_DIR, "errors", "ERR_ACCESS_DENIED.default")
VIRUS_PAGE = os.path.join(MANAGED_DIR, "virus_found.html")
LOGS_DIR = os.environ.get("SQUID_LOG_DIR", "/var/log/squid")
CA_CERT_DIR = os.environ.get("CA_CERT_DIR", "/etc/squid/ssl_cert")
CA_CERT_NAME = "squidCA.der"
# One URL per line. On first run these are imported as block subscriptions so
# the proxy is useful out-of-the-box. Lines starting with # ! or ; are ignored.
BLACKLISTS_FILE = os.environ.get("BLACKLISTS_FILE", "/app/blacklists.txt")

# The address clients should use to reach the proxy (shown on the public
# Client Setup page). Override PROXY_HOST with your server's LAN IP or
# hostname so the on-page instructions are copy-paste ready.
PROXY_HOST = os.environ.get("PROXY_HOST", "").strip()
PROXY_PORT = os.environ.get("PROXY_PORT", "3128").strip()

# ---------------------------------------------------------------------------
# Subscribed lists — remote lists re-downloaded on a schedule (like Pi-hole's
# gravity). A list is a subscription when its `source_url` is non-NULL.
# ---------------------------------------------------------------------------
SUBSCRIPTION_INTERVALS = [
    (21600, "Every 6 hours"),
    (43200, "Every 12 hours"),
    (86400, "Every 24 hours"),
    (172800, "Every 2 days"),
    (604800, "Every 7 days"),
]
DEFAULT_SUBSCRIPTION_INTERVAL = 86400
# How often the scheduler wakes up to check whether any subscription is due.
SUBSCRIPTION_CHECK_INTERVAL = 60
# Prevent concurrent syncs/imports (scheduler + manual refresh + import all
# share the same SQLite write path). RLock so it can be acquired again inside
# helpers that are themselves wrapped by an outer lock.
_sync_lock = threading.RLock()
_log = logging.getLogger("subscriptions")

# Whitelist of logs the dashboard may read — the key is the URL-safe name,
# the value maps to (human label, filename) inside LOGS_DIR.
LOG_FILES = {
    "access": ("Access log", "access.log"),
    "cache": ("Cache log", "cache.log"),
}

app = Flask(__name__)
app.secret_key = os.environ.get("DASHBOARD_SECRET_KEY") or secrets.token_hex(32)


@app.context_processor
def inject_status():
    # Make the apply-status available to every template so the topbar can
    # always show whether there are pending changes waiting to be applied.
    return {
        "dirty": get_setting("dirty", "0") == "1",
        "last_applied": get_setting("last_applied", "never"),
    }


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------
def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # WAL lets the scheduler thread read while a request writes, and
    # busy_timeout makes a competing writer wait instead of raising
    # "database is locked" immediately.
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def _migrate_lists(conn):
    """Add subscription columns to pre-existing `lists` tables (SQLite's
    CREATE TABLE IF NOT EXISTS won't alter an existing table)."""
    existing = {r["name"] for r in conn.execute("PRAGMA table_info(lists)").fetchall()}
    additions = [
        ("source_url", "TEXT"),
        ("subscription_action", "TEXT"),
        ("subscription_type", "TEXT"),
        ("update_interval", "INTEGER NOT NULL DEFAULT 86400"),
        ("last_checked", "INTEGER"),
        ("last_error", "TEXT"),
    ]
    for col, ddl in additions:
        if col not in existing:
            conn.execute(f"ALTER TABLE lists ADD COLUMN {col} {ddl}")


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS lists (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            enabled INTEGER NOT NULL DEFAULT 1,
            redirect_url TEXT,
            source_url TEXT,
            subscription_action TEXT,
            subscription_type TEXT,
            update_interval INTEGER NOT NULL DEFAULT 86400,
            last_checked INTEGER,
            last_error TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            list_id INTEGER NOT NULL REFERENCES lists(id) ON DELETE CASCADE,
            entry_type TEXT NOT NULL CHECK(entry_type IN ('domain','url','network')),
            action TEXT NOT NULL CHECK(action IN ('allow','block')),
            value TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        """
    )
    _migrate_lists(conn)
    # Seed a default list so entries always have somewhere to live
    row = conn.execute("SELECT id FROM lists WHERE name = 'Default'").fetchone()
    if not row:
        conn.execute("INSERT INTO lists (name, enabled) VALUES ('Default', 1)")

    # Seed admin password from env var on very first run only
    pw_row = conn.execute("SELECT value FROM settings WHERE key = 'password_hash'").fetchone()
    if not pw_row:
        initial_password = os.environ.get("DASHBOARD_PASSWORD", "changeme")
        conn.execute(
            "INSERT INTO settings (key, value) VALUES ('password_hash', ?)",
            (generate_password_hash(initial_password),),
        )
    conn.execute(
        "INSERT OR IGNORE INTO settings (key, value) VALUES ('dirty', '0')"
    )
    conn.execute(
        "INSERT OR IGNORE INTO settings (key, value) VALUES ('last_applied', 'never')"
    )
    # Default access policy: 'allow' = blacklist mode (everything allowed
    # unless blocked), 'deny' = whitelist mode (everything blocked unless
    # explicitly allowed).
    conn.execute(
        "INSERT OR IGNORE INTO settings (key, value) VALUES ('default_policy', 'allow')"
    )
    conn.commit()
    conn.close()

    # Import any block-list URLs shipped in blacklists.txt on first run.
    preload_blacklists()


def get_setting(key, default=None):
    conn = get_db()
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else default


def set_setting(key, value):
    conn = get_db()
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
    conn.commit()
    conn.close()


def mark_dirty():
    set_setting("dirty", "1")


# ---------------------------------------------------------------------------
# Jinja filters (used by the subscription UI to show human-friendly times)
# ---------------------------------------------------------------------------
@app.template_filter("timeago")
def timeago_filter(value):
    if not value:
        return "never"
    try:
        ts = float(value)
    except (TypeError, ValueError):
        return "never"
    diff = max(0, int(time.time() - ts))
    if diff < 60:
        return "just now"
    if diff < 3600:
        return f"{diff // 60}m ago"
    if diff < 86400:
        return f"{diff // 3600}h ago"
    return f"{diff // 86400}d ago"


@app.template_filter("interval_label")
def interval_label_filter(value):
    try:
        secs = int(value)
    except (TypeError, ValueError):
        secs = 0
    for s, label in SUBSCRIPTION_INTERVALS:
        if secs == s:
            return label
    if secs % 86400 == 0:
        return f"Every {secs // 86400} days"
    if secs % 3600 == 0:
        return f"Every {secs // 3600} hours"
    return f"Every {secs} seconds"


# ---------------------------------------------------------------------------
# Client setup (public) — download the CA cert + OS trust instructions.
# These routes are intentionally NOT login-protected: end users need the
# certificate to trust the proxy's SSL-bump CA, and they don't have admin
# accounts.
# ---------------------------------------------------------------------------
@app.route("/setup")
def setup_page():
    cert_path = os.path.join(CA_CERT_DIR, CA_CERT_NAME)
    cert_ready = os.path.isfile(cert_path)
    proxy_host = PROXY_HOST or "your-server-ip"
    proxy_addr = f"{proxy_host}:{PROXY_PORT}"
    proxy_url = f"http://{proxy_addr}"
    return render_template(
        "setup.html",
        cert_ready=cert_ready,
        proxy_host=proxy_host,
        proxy_port=PROXY_PORT,
        proxy_addr=proxy_addr,
        proxy_url=proxy_url,
    )


@app.route("/setup/download")
def setup_download():
    cert_path = os.path.join(CA_CERT_DIR, CA_CERT_NAME)
    if not os.path.isfile(cert_path):
        return "CA certificate is not available yet. The proxy has not generated one.", 404
    return send_from_directory(
        CA_CERT_DIR,
        CA_CERT_NAME,
        as_attachment=True,
        download_name=CA_CERT_NAME,
    )


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form.get("password", "")
        stored_hash = get_setting("password_hash")
        if stored_hash and check_password_hash(stored_hash, password):
            session["logged_in"] = True
            return redirect(url_for("dashboard_home"))
        flash("Incorrect password.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/settings/password", methods=["POST"])
@login_required
def change_password():
    new_password = request.form.get("new_password", "").strip()
    if len(new_password) < 8:
        flash("Password must be at least 8 characters.", "error")
    else:
        set_setting("password_hash", generate_password_hash(new_password))
        flash("Password updated.", "success")
    return redirect(url_for("dashboard_home"))


@app.route("/settings/policy", methods=["POST"])
@login_required
def change_policy():
    policy = request.form.get("policy", "").strip()
    if policy not in ("allow", "deny"):
        flash("Invalid policy.", "error")
    else:
        set_setting("default_policy", policy)
        mark_dirty()
        flash("Default access policy updated. Click Apply to activate it.", "success")
    return redirect(url_for("dashboard_home"))


# ---------------------------------------------------------------------------
# Dashboard home
# ---------------------------------------------------------------------------
@app.route("/")
@login_required
def dashboard_home():
    conn = get_db()
    lists = conn.execute("SELECT * FROM lists ORDER BY name").fetchall()
    subscriptions = [l for l in lists if l["source_url"]]
    regular_lists = [l for l in lists if not l["source_url"]]
    counts = {}
    for lst in lists:
        c = conn.execute(
            "SELECT entry_type, action, COUNT(*) as n FROM entries WHERE list_id = ? GROUP BY entry_type, action",
            (lst["id"],),
        ).fetchall()
        counts[lst["id"]] = {f"{r['entry_type']}_{r['action']}": r["n"] for r in c}
    conn.close()

    # Aggregate counts across all lists for the summary stat cards.
    totals = {
        "lists": len(lists),
        "domain_block": 0,
        "url_block": 0,
        "network_block": 0,
        "allow": 0,
    }
    for c in counts.values():
        totals["domain_block"] += c.get("domain_block", 0)
        totals["url_block"] += c.get("url_block", 0)
        totals["network_block"] += c.get("network_block", 0)
        totals["allow"] += c.get("domain_allow", 0) + c.get("url_allow", 0) + c.get("network_allow", 0)

    return render_template(
        "dashboard.html",
        lists=regular_lists,
        subscriptions=subscriptions,
        counts=counts,
        totals=totals,
        default_policy=get_setting("default_policy", "allow"),
        intervals=SUBSCRIPTION_INTERVALS,
    )


# ---------------------------------------------------------------------------
# Lists
# ---------------------------------------------------------------------------
@app.route("/lists/create", methods=["POST"])
@login_required
def create_list():
    name = request.form.get("name", "").strip()
    if not name:
        flash("List name is required.", "error")
        return redirect(url_for("dashboard_home"))
    conn = get_db()
    try:
        conn.execute("INSERT INTO lists (name, enabled) VALUES (?, 1)", (name,))
        conn.commit()
        mark_dirty()
        flash(f"List '{name}' created.", "success")
    except sqlite3.IntegrityError:
        flash("A list with that name already exists.", "error")
    conn.close()
    return redirect(url_for("dashboard_home"))


@app.route("/lists/<int:list_id>/toggle", methods=["POST"])
@login_required
def toggle_list(list_id):
    conn = get_db()
    conn.execute("UPDATE lists SET enabled = 1 - enabled WHERE id = ?", (list_id,))
    conn.commit()
    conn.close()
    mark_dirty()
    return redirect(url_for("dashboard_home"))


@app.route("/lists/<int:list_id>/redirect", methods=["POST"])
@login_required
def set_list_redirect(list_id):
    redirect_url = request.form.get("redirect_url", "").strip()
    conn = get_db()
    conn.execute(
        "UPDATE lists SET redirect_url = ? WHERE id = ?",
        (redirect_url if redirect_url else None, list_id),
    )
    conn.commit()
    conn.close()
    mark_dirty()
    flash("Redirect setting saved.", "success")
    return redirect(url_for("list_detail", list_id=list_id))


@app.route("/lists/<int:list_id>/delete", methods=["POST"])
@login_required
def delete_list(list_id):
    conn = get_db()
    lst = conn.execute("SELECT name FROM lists WHERE id = ?", (list_id,)).fetchone()
    if lst and lst["name"] == "Default":
        flash("The Default list can't be deleted.", "error")
    else:
        conn.execute("DELETE FROM lists WHERE id = ?", (list_id,))
        conn.commit()
        mark_dirty()
        flash("List deleted.", "success")
    conn.close()
    return redirect(url_for("dashboard_home"))


@app.route("/lists/<int:list_id>")
@login_required
def list_detail(list_id):
    conn = get_db()
    lst = conn.execute("SELECT * FROM lists WHERE id = ?", (list_id,)).fetchone()
    if not lst:
        flash("List not found.", "error")
        conn.close()
        return redirect(url_for("dashboard_home"))
    entries = conn.execute(
        "SELECT * FROM entries WHERE list_id = ? ORDER BY entry_type, action, value", (list_id,)
    ).fetchall()
    conn.close()
    return render_template(
        "list_detail.html",
        lst=lst,
        entries=entries,
        is_subscription=bool(lst["source_url"]),
        intervals=SUBSCRIPTION_INTERVALS,
    )


# ---------------------------------------------------------------------------
# Entries (domains / URLs / networks)
# ---------------------------------------------------------------------------
DOMAIN_RE = re.compile(r"^\.?[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$")
CIDR_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$")


def validate_entry(entry_type, value):
    value = value.strip()
    if not value:
        return None, "Empty value."
    if entry_type == "domain":
        if not DOMAIN_RE.match(value):
            return None, f"'{value}' doesn't look like a valid domain."
    elif entry_type == "network":
        if not CIDR_RE.match(value):
            return None, f"'{value}' doesn't look like a valid IP or CIDR (e.g. 192.168.1.0/24)."
    elif entry_type == "url":
        try:
            re.compile(value)
        except re.error as e:
            return None, f"'{value}' isn't a valid regex: {e}"
    else:
        return None, "Unknown entry type."
    return value, None


@app.route("/entries/create", methods=["POST"])
@login_required
def create_entries():
    list_id = request.form.get("list_id", type=int)
    entry_type = request.form.get("entry_type")
    action = request.form.get("action")
    raw_values = request.form.get("values", "")

    if entry_type not in ("domain", "url", "network") or action not in ("allow", "block"):
        flash("Invalid entry type or action.", "error")
        return redirect(url_for("list_detail", list_id=list_id))

    lines = [v.strip() for v in raw_values.splitlines() if v.strip()]
    if not lines:
        flash("No values provided.", "error")
        return redirect(url_for("list_detail", list_id=list_id))

    conn = get_db()
    added, errors = 0, []
    for raw in lines:
        value, err = validate_entry(entry_type, raw)
        if err:
            errors.append(err)
            continue
        conn.execute(
            "INSERT INTO entries (list_id, entry_type, action, value) VALUES (?, ?, ?, ?)",
            (list_id, entry_type, action, value),
        )
        added += 1
    conn.commit()
    conn.close()

    if added:
        mark_dirty()
        flash(f"Added {added} {entry_type} entr{'y' if added == 1 else 'ies'}.", "success")
    for e in errors[:5]:
        flash(e, "error")
    if len(errors) > 5:
        flash(f"...and {len(errors) - 5} more errors.", "error")

    return redirect(url_for("list_detail", list_id=list_id))


@app.route("/entries/<int:entry_id>/delete", methods=["POST"])
@login_required
def delete_entry(entry_id):
    conn = get_db()
    row = conn.execute("SELECT list_id FROM entries WHERE id = ?", (entry_id,)).fetchone()
    conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
    conn.commit()
    conn.close()
    mark_dirty()
    return redirect(url_for("list_detail", list_id=row["list_id"] if row else 1))


# ---------------------------------------------------------------------------
# List import from URL (whitelists / blacklists)
# ---------------------------------------------------------------------------
MAX_IMPORT_BYTES = 10 * 1024 * 1024  # 10 MB safety cap on remote lists

GENERIC_NAMES = {
    "domains", "domain", "hosts", "host", "blacklist", "whitelist",
    "list", "urls", "url", "ips", "ip",
}


def fetch_list_url(url):
    """Download a remote list and return (text, error). Only http/https."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return None, "Only http:// and https:// URLs are supported."
    if not parsed.netloc:
        return None, "That doesn't look like a valid URL."
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "proxsea/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read(MAX_IMPORT_BYTES + 1)
        if len(data) > MAX_IMPORT_BYTES:
            return None, "File is too large (over 10 MB)."
        charset = "utf-8"
        text = data.decode(charset, errors="replace")
    except urllib.error.URLError as e:
        return None, f"Could not fetch URL: {getattr(e, 'reason', e)}"
    except Exception as e:  # noqa: BLE001 - surface a clean message to the admin
        return None, f"Could not fetch URL: {e}"
    return text, None


def derive_list_name(url):
    """Build a sensible list name from a URL when the user leaves it blank."""
    parsed = urllib.parse.urlparse(url)
    parts = [urllib.parse.unquote(p) for p in parsed.path.split("/") if p]
    last = parts[-1] if parts else ""
    base = re.sub(
        r"\.(txt|list|conf|dat|domains|hosts|blacklist|whitelist)$",
        "", last, flags=re.IGNORECASE,
    ).strip()
    if not base:
        base = parsed.netloc
    # If the filename is generic ("domains"), prepend its category folder.
    if base.lower() in GENERIC_NAMES and len(parts) >= 2:
        base = f"{parts[-2]}-{base}"
    base = re.sub(r"[-_]+", " ", base)
    base = " ".join(base.split()).title()
    return base or "Imported list"


def parse_import_line(raw, entry_type):
    """Turn one raw line from an imported list into (entry_type, value,
    action), or None if it can't be used. `entry_type` is 'auto', 'domain',
    'network' or 'url'. `action` is 'allow' when the line was an Adblock
    exception (@@...) and None otherwise (meaning "use the list default").

    Accepted input styles:
      - hosts file:      "0.0.0.0 example.com"
      - Adblock domain:  "||example.com^"  /  "||example.com^$important"
      - Adblock exact:   "|https://example.com/path"
      - plain:           "example.com"  /  ".example.com"  /  "*.example.com"
    """
    line = raw.strip()
    if not line:
        return None
    # Full-line comments (hosts use '#'; Adblock uses '!' and '#')
    if line.startswith(("#", "!", ";")):
        return None

    # URL/regex lists are kept verbatim — no normalization.
    if entry_type == "url":
        try:
            re.compile(line)
        except re.error:
            return None
        return ("url", line, None)

    # Inline comments (hosts-style trailing "# comment")
    line = re.split(r"\s+[#;]", line, maxsplit=1)[0].strip()
    if not line:
        return None

    # Adblock exception rules ("@@...") map to allow entries.
    line_action = None
    if line.startswith("@@"):
        line_action = "allow"
        line = line[2:].lstrip()

    # Adblock anchors: '||' = domain + subdomains, '|' = exact-URL start.
    if line.startswith("||"):
        line = line[2:]
    elif line.startswith("|"):
        line = line[1:]

    # Adblock separator ('^') and filter options ('$...').
    line = re.split(r"[$^]", line, maxsplit=1)[0].strip()
    if not line:
        return None

    # Scheme, path, and wildcard prefix.
    line = re.sub(r"^https?://", "", line, flags=re.IGNORECASE)
    # Strip a URL path, but keep CIDR notation intact (e.g. 192.168.1.0/24).
    if not CIDR_RE.match(line):
        line = line.split("/")[0]
    if line.startswith("*."):
        line = line[2:]
    line = line.rstrip(".")

    if entry_type == "auto":
        # hosts-file form: "0.0.0.0 example.com" -> example.com. The second
        # token must contain a letter, so "0.0.0.0 0.0.0.0" (a hosts-file
        # placeholder) isn't mistaken for a hostname.
        parts = line.split()
        if (
            len(parts) == 2
            and CIDR_RE.match(parts[0])
            and DOMAIN_RE.match(parts[1])
            and re.search(r"[a-zA-Z]", parts[1])
        ):
            line = parts[1]
        if CIDR_RE.match(line):
            return ("network", line, line_action)
        if DOMAIN_RE.match(line):
            return ("domain", line, line_action)
        return None

    if entry_type == "network":
        if CIDR_RE.match(line):
            return ("network", line, line_action)
        return None

    # entry_type == "domain"
    if DOMAIN_RE.match(line):
        return ("domain", line, line_action)
    return None


def import_entries_from_text(list_id, text, entry_type, action):
    """Parse text lines and insert them into list_id. Returns
    (added, skipped, errors). Duplicates (within the file and against
    existing entries) are skipped. Adblock `@@` exception lines become
    'allow' entries; everything else uses the list's `action`.

    Performs a single batched write so large lists (e.g. 100k-line hosts
    files) complete in well under a second instead of timing out."""
    # Parse first (in memory, no DB) into a map keyed by (type, value).
    # A later 'allow' (from an @@ exception) overrides a 'block' for the
    # same value, matching Adblock's "exceptions win" semantics.
    parsed_map = {}
    skipped = 0
    errors = []
    for raw in text.splitlines():
        p = parse_import_line(raw, entry_type)
        if p is None:
            skipped += 1
            continue
        etype, value, line_action = p
        value, err = validate_entry(etype, value)
        if err:
            errors.append(err)
            skipped += 1
            continue
        act = line_action or action
        prev = parsed_map.get((etype, value))
        if prev is None or (prev != "allow" and act == "allow"):
            parsed_map[(etype, value)] = act

    with _sync_lock:
        conn = get_db()
        existing = {
            (r["entry_type"], r["value"])
            for r in conn.execute(
                "SELECT entry_type, value FROM entries WHERE list_id = ?", (list_id,)
            )
        }
        rows = []
        for (etype, value), act in parsed_map.items():
            if (etype, value) in existing:
                skipped += 1
                continue
            rows.append((list_id, etype, act, value))
        if rows:
            conn.executemany(
                "INSERT INTO entries (list_id, entry_type, action, value) "
                "VALUES (?, ?, ?, ?)",
                rows,
            )
        added = len(rows)
        conn.commit()
        conn.close()
    return added, skipped, errors


@app.route("/lists/import", methods=["POST"])
@login_required
def import_list():
    url = request.form.get("url", "").strip()
    name = request.form.get("name", "").strip()
    action = request.form.get("action", "block")
    if action not in ("block", "allow"):
        action = "block"

    if not url:
        flash("A URL is required.", "error")
        return redirect(url_for("dashboard_home"))

    text, err = fetch_list_url(url)
    if err:
        flash(err, "error")
        return redirect(url_for("dashboard_home"))

    if not name:
        name = derive_list_name(url)

    conn = get_db()
    try:
        cur = conn.execute("INSERT INTO lists (name, enabled) VALUES (?, 1)", (name,))
        conn.commit()
        list_id = cur.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        flash(f"A list named '{name}' already exists — import into it directly or choose another name.", "error")
        return redirect(url_for("dashboard_home"))
    conn.close()

    added, skipped, errors = import_entries_from_text(list_id, text, "auto", action)
    mark_dirty()
    verb = "blocked" if action == "block" else "allowed"
    flash(f"Imported {added} entries into '{name}' ({verb}); {skipped} lines skipped.", "success")
    for e in errors[:5]:
        flash(e, "error")
    if len(errors) > 5:
        flash(f"...and {len(errors) - 5} more invalid entries skipped.", "error")
    return redirect(url_for("list_detail", list_id=list_id))


@app.route("/lists/<int:list_id>/import", methods=["POST"])
@login_required
def import_into_list(list_id):
    conn = get_db()
    lst = conn.execute("SELECT * FROM lists WHERE id = ?", (list_id,)).fetchone()
    conn.close()
    if not lst:
        flash("List not found.", "error")
        return redirect(url_for("dashboard_home"))

    url = request.form.get("url", "").strip()
    action = request.form.get("action", "block")
    entry_type = request.form.get("entry_type", "auto")
    if action not in ("block", "allow"):
        action = "block"
    if entry_type not in ("auto", "domain", "network", "url"):
        entry_type = "auto"

    if not url:
        flash("A URL is required.", "error")
        return redirect(url_for("list_detail", list_id=list_id))

    text, err = fetch_list_url(url)
    if err:
        flash(err, "error")
        return redirect(url_for("list_detail", list_id=list_id))

    added, skipped, errors = import_entries_from_text(list_id, text, entry_type, action)
    mark_dirty()
    flash(f"Imported {added} entries into '{lst['name']}'; {skipped} lines skipped.", "success")
    for e in errors[:5]:
        flash(e, "error")
    if len(errors) > 5:
        flash(f"...and {len(errors) - 5} more invalid entries skipped.", "error")
    return redirect(url_for("list_detail", list_id=list_id))


# ---------------------------------------------------------------------------
# Subscribed lists — remote lists re-downloaded on a schedule (Pi-hole style)
# ---------------------------------------------------------------------------
def _set_sync_result(list_id, error=None):
    conn = get_db()
    conn.execute(
        "UPDATE lists SET last_checked = ?, last_error = ? WHERE id = ?",
        (int(time.time()), error, list_id),
    )
    conn.commit()
    conn.close()


def sync_subscription(list_id):
    """Re-download a subscribed list and replace its entries with the remote
    content. Returns True if the entries changed. On fetch/parse failure the
    list is left untouched and `last_error` is recorded."""
    conn = get_db()
    lst = conn.execute("SELECT * FROM lists WHERE id = ?", (list_id,)).fetchone()
    if not lst or not lst["source_url"]:
        conn.close()
        return False
    url = lst["source_url"]
    action = lst["subscription_action"] or "block"
    etype = lst["subscription_type"] or "auto"
    conn.close()

    text, err = fetch_list_url(url)
    if err:
        _set_sync_result(list_id, error=err)
        return False

    parsed_map = {}
    for raw in text.splitlines():
        p = parse_import_line(raw, etype)
        if p is None:
            continue
        tp, val, line_action = p
        v, verr = validate_entry(tp, val)
        if verr:
            continue
        act = line_action or action
        prev = parsed_map.get((tp, v))
        if prev is None or (prev != "allow" and act == "allow"):
            parsed_map[(tp, v)] = act

    with _sync_lock:
        conn = get_db()
        current = {
            (r["entry_type"], r["value"], r["action"])
            for r in conn.execute(
                "SELECT entry_type, value, action FROM entries WHERE list_id = ?",
                (list_id,),
            )
        }
        new_state = {(tp, v, act) for (tp, v), act in parsed_map.items()}
        if new_state == current:
            conn.close()
            _set_sync_result(list_id)
            return False

        conn.execute("DELETE FROM entries WHERE list_id = ?", (list_id,))
        conn.executemany(
            "INSERT INTO entries (list_id, entry_type, action, value) VALUES (?, ?, ?, ?)",
            [(list_id, tp, act, v) for (tp, v), act in parsed_map.items()],
        )
        conn.commit()
        conn.close()
        _set_sync_result(list_id)
        return True


def preload_blacklists():
    """Import block-list URLs shipped in blacklists.txt as subscriptions on the
    very first run. Idempotent: guarded by a settings flag and skips URLs that
    already exist as a subscription, so a later upgrade doesn't clobber the
    admin's data. On a fetch failure the subscription is still created (empty)
    and `last_error` is set, leaving the scheduler to retry on its next sweep."""
    if get_setting("blacklists_preloaded") == "1":
        return 0
    if not os.path.isfile(BLACKLISTS_FILE):
        set_setting("blacklists_preloaded", "1")
        return 0

    try:
        with open(BLACKLISTS_FILE, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        set_setting("blacklists_preloaded", "1")
        return 0

    preloaded = 0
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith(("#", "!", ";")):
            continue
        url = line.split()[0]  # tolerate a trailing inline comment
        if urllib.parse.urlparse(url).scheme not in ("http", "https"):
            continue

        conn = get_db()
        exists = conn.execute(
            "SELECT id FROM lists WHERE source_url = ?", (url,)
        ).fetchone()
        conn.close()
        if exists:
            continue

        name = derive_list_name(url)
        conn = get_db()
        try:
            cur = conn.execute(
                "INSERT INTO lists (name, enabled, source_url, subscription_action, "
                "subscription_type, update_interval) VALUES (?, 1, ?, 'block', 'auto', ?)",
                (name, url, DEFAULT_SUBSCRIPTION_INTERVAL),
            )
            conn.commit()
            list_id = cur.lastrowid
        except sqlite3.IntegrityError:
            conn.close()
            continue
        conn.close()

        text, err = fetch_list_url(url)
        if err:
            _set_sync_result(list_id, error=err)
            preloaded += 1
            continue
        import_entries_from_text(list_id, text, "auto", "block")
        _set_sync_result(list_id)
        preloaded += 1

    set_setting("blacklists_preloaded", "1")
    if preloaded:
        mark_dirty()
    return preloaded


def sync_due_subscriptions():
    """Refresh any enabled subscription whose interval has elapsed. Auto-applies
    only when nothing else is pending, so a background refresh never clobbers
    the admin's un-applied manual edits."""
    conn = get_db()
    subs = conn.execute(
        "SELECT id, update_interval, last_checked FROM lists "
        "WHERE source_url IS NOT NULL AND enabled = 1"
    ).fetchall()
    conn.close()

    now = time.time()
    changed = []
    for s in subs:
        interval = s["update_interval"] or DEFAULT_SUBSCRIPTION_INTERVAL
        if s["last_checked"] and (now - s["last_checked"]) < interval:
            continue
        with _sync_lock:
            if sync_subscription(s["id"]):
                changed.append(s["id"])

    if changed and get_setting("dirty", "0") != "1":
        _log.info("Subscription refresh changed %d list(s); applying now.", len(changed))
        write_and_apply()


def _subscription_loop():
    # Let the app finish booting (and init_db run) before the first sweep.
    time.sleep(SUBSCRIPTION_CHECK_INTERVAL)
    while True:
        try:
            sync_due_subscriptions()
        except Exception:  # noqa: BLE001 - never let the scheduler die
            _log.exception("Unhandled error in subscription scheduler")
        time.sleep(SUBSCRIPTION_CHECK_INTERVAL)


_scheduler_started = False
_scheduler_start_lock = threading.Lock()


def start_scheduler():
    global _scheduler_started
    with _scheduler_start_lock:
        if _scheduler_started:
            return
        _scheduler_started = True
    threading.Thread(
        target=_subscription_loop, name="subscription-scheduler", daemon=True
    ).start()


@app.route("/subscriptions/create", methods=["POST"])
@login_required
def create_subscription():
    url = request.form.get("url", "").strip()
    name = request.form.get("name", "").strip()
    action = request.form.get("action", "block")
    etype = request.form.get("entry_type", "auto")
    interval = request.form.get("interval", type=int) or DEFAULT_SUBSCRIPTION_INTERVAL
    if action not in ("block", "allow"):
        action = "block"
    if etype not in ("auto", "domain", "network", "url"):
        etype = "auto"
    if interval not in [i for i, _ in SUBSCRIPTION_INTERVALS]:
        interval = DEFAULT_SUBSCRIPTION_INTERVAL

    if not url:
        flash("A URL is required.", "error")
        return redirect(url_for("dashboard_home"))
    if not name:
        name = derive_list_name(url)

    # Fetch once now so the admin gets immediate feedback + entries.
    text, err = fetch_list_url(url)
    if err:
        flash(err, "error")
        return redirect(url_for("dashboard_home"))

    conn = get_db()
    try:
        cur = conn.execute(
            "INSERT INTO lists (name, enabled, source_url, subscription_action, "
            "subscription_type, update_interval) VALUES (?, 1, ?, ?, ?, ?)",
            (name, url, action, etype, interval),
        )
        conn.commit()
        list_id = cur.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        flash(f"A list named '{name}' already exists.", "error")
        return redirect(url_for("dashboard_home"))
    conn.close()

    added, skipped, errors = import_entries_from_text(list_id, text, etype, action)
    _set_sync_result(list_id)
    mark_dirty()
    verb = "blocked" if action == "block" else "allowed"
    flash(
        f"Subscribed to '{name}' — {added} entries {verb}, {skipped} lines skipped. "
        "Click Apply to activate.",
        "success",
    )
    for e in errors[:5]:
        flash(e, "error")
    if len(errors) > 5:
        flash(f"...and {len(errors) - 5} more invalid entries skipped.", "error")
    return redirect(url_for("list_detail", list_id=list_id))


@app.route("/subscriptions/<int:list_id>/refresh", methods=["POST"])
@login_required
def refresh_subscription(list_id):
    conn = get_db()
    lst = conn.execute("SELECT name FROM lists WHERE id = ?", (list_id,)).fetchone()
    conn.close()
    if not lst:
        flash("List not found.", "error")
        return redirect(url_for("dashboard_home"))

    with _sync_lock:
        changed = sync_subscription(list_id)

    if changed:
        write_and_apply()
        flash(f"Refreshed '{lst['name']}' and applied the changes.", "success")
    else:
        conn = get_db()
        row = conn.execute("SELECT last_error FROM lists WHERE id = ?", (list_id,)).fetchone()
        conn.close()
        if row and row["last_error"]:
            flash(f"Refresh failed for '{lst['name']}': {row['last_error']}", "error")
        else:
            flash(f"'{lst['name']}' is up to date — no changes.", "success")
    return redirect(url_for("list_detail", list_id=list_id))


@app.route("/subscriptions/<int:list_id>/interval", methods=["POST"])
@login_required
def set_subscription_interval(list_id):
    interval = request.form.get("interval", type=int)
    if interval not in [i for i, _ in SUBSCRIPTION_INTERVALS]:
        flash("Invalid interval.", "error")
        return redirect(url_for("list_detail", list_id=list_id))
    conn = get_db()
    conn.execute("UPDATE lists SET update_interval = ? WHERE id = ?", (interval, list_id))
    conn.commit()
    conn.close()
    flash("Update interval saved.", "success")
    return redirect(url_for("list_detail", list_id=list_id))


# ---------------------------------------------------------------------------
# Custom error page
# ---------------------------------------------------------------------------
# Default "access denied" page served by Squid. The %U / %i / %h / %T
# codes are substituted by Squid at request time (requested URL, client IP,
# proxy hostname, UTC time). See the Block Page editor for the full list.
DEFAULT_ERROR_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access blocked</title>
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
    <h1>Access blocked</h1>
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
"""

# Default "virus found" page served by c-icap. The %VVN / %huo / %VVV
# tokens are substituted by c-icap at request time (virus name, requested
# URL, antivirus engine) — they must be left as-is in the editable HTML.
DEFAULT_VIRUS_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Threat blocked</title>
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
    <h1>Threat blocked</h1>
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
"""


@app.route("/error-page")
@login_required
def error_page_editor():
    conn = get_db()
    row = conn.execute("SELECT value FROM settings WHERE key = 'custom_error_html'").fetchone()
    conn.close()
    current_html = row["value"] if row else DEFAULT_ERROR_HTML
    return render_template("error_page.html", current_html=current_html)


@app.route("/error-page/save", methods=["POST"])
@login_required
def save_error_page():
    html = request.form.get("html", "").strip()
    if not html:
        html = DEFAULT_ERROR_HTML
    set_setting("custom_error_html", html)
    mark_dirty()
    flash("Custom error page saved. Click Apply to activate it.", "success")
    return redirect(url_for("error_page_editor"))


@app.route("/virus-page")
@login_required
def virus_page_editor():
    conn = get_db()
    row = conn.execute("SELECT value FROM settings WHERE key = 'custom_virus_html'").fetchone()
    conn.close()
    current_html = row["value"] if row else DEFAULT_VIRUS_HTML
    return render_template("virus_page.html", current_html=current_html)


@app.route("/virus-page/save", methods=["POST"])
@login_required
def save_virus_page():
    html = request.form.get("html", "").strip()
    if not html:
        html = DEFAULT_VIRUS_HTML
    set_setting("custom_virus_html", html)
    mark_dirty()
    flash("Virus page saved. Click Apply to activate it.", "success")
    return redirect(url_for("virus_page_editor"))


# ---------------------------------------------------------------------------
# Config generation + apply
# ---------------------------------------------------------------------------
def sanitize_acl_name(text):
    return re.sub(r"[^a-zA-Z0-9_]", "_", text)


def generate_config():
    """Builds rules.conf + list value files from current DB state.
    Returns the generated rules.conf text (used for both writing to disk
    and for the review preview shown before Apply)."""
    conn = get_db()
    lists = conn.execute("SELECT * FROM lists ORDER BY id").fetchall()

    os.makedirs(LISTS_DIR, exist_ok=True)
    # clear stale list files from a previous generation
    for f in os.listdir(LISTS_DIR):
        os.remove(os.path.join(LISTS_DIR, f))

    acl_lines = []
    allow_access_lines = []
    deny_access_lines = []
    deny_info_lines = []

    type_to_acltype = {"domain": "dstdomain", "url": "url_regex -i", "network": "src"}

    for lst in lists:
        if not lst["enabled"]:
            continue
        list_tag = f"l{lst['id']}_{sanitize_acl_name(lst['name'])}"
        entries = conn.execute(
            "SELECT entry_type, action, value FROM entries WHERE list_id = ?", (lst["id"],)
        ).fetchall()

        # group values by (type, action)
        groups = {}
        for e in entries:
            groups.setdefault((e["entry_type"], e["action"]), []).append(e["value"])

        for (etype, action), values in groups.items():
            if not values:
                continue
            fname = f"{list_tag}_{etype}_{action}.txt"
            fpath = os.path.join(LISTS_DIR, fname)
            with open(fpath, "w") as fh:
                fh.write("\n".join(values) + "\n")

            acl_name = f"acl_{list_tag}_{etype}_{action}"
            acl_type = type_to_acltype[etype]
            acl_lines.append(f'acl {acl_name} {acl_type} "{fpath}"')

            if action == "allow":
                allow_access_lines.append(f"http_access allow {acl_name}")
            else:
                deny_access_lines.append(f"http_access deny {acl_name}")
                if lst["redirect_url"]:
                    deny_info_lines.append(f"deny_info {lst['redirect_url']} {acl_name}")
                else:
                    deny_info_lines.append(f"deny_info ERR_ACCESS_DENIED {acl_name}")

    conn.close()

    # Final catch-all: the admin picks the default behavior for anything that
    # didn't match an explicit allow/block rule above. This line shadows the
    # http_access rules that follow the include in squid.conf, so it's the
    # single source of truth for the default policy.
    default_policy = get_setting("default_policy", "allow")
    if default_policy == "deny":
        default_comment = "# --- Default policy: DENY all (whitelist mode) ---"
        default_rule = "http_access deny all"
    else:
        default_comment = "# --- Default policy: ALLOW all (blacklist mode) ---"
        default_rule = "http_access allow all"

    parts = [
        "# ============================================================",
        "# AUTO-GENERATED by the management dashboard. Do not edit by hand",
        "# -- changes here are overwritten every time Apply is clicked.",
        "# ============================================================",
        "",
        "# --- ACL definitions ---",
        *acl_lines,
        "",
        "# --- Custom block -> redirect/error page mappings ---",
        *deny_info_lines,
        "",
        "# --- Explicit allow rules (evaluated first: carve-outs win) ---",
        *allow_access_lines,
        "",
        "# --- Block rules ---",
        *deny_access_lines,
        "",
        default_comment,
        default_rule,
        "",
    ]
    return "\n".join(parts)


@app.route("/apply")
@login_required
def apply_preview():
    preview = generate_config()
    dirty = get_setting("dirty", "0") == "1"
    return render_template("apply.html", preview=preview, dirty=dirty)


def write_and_apply():
    """Write the generated config + custom pages to the shared volume and
    signal the ssl-proxy container to reload Squid. Used both by the manual
    Apply button and by the subscription scheduler."""
    config_text = generate_config()
    os.makedirs(os.path.dirname(RULES_CONF), exist_ok=True)
    with open(RULES_CONF, "w") as fh:
        fh.write(config_text)

    # Block page: always write Squid's ERR_ACCESS_DENIED template so the
    # served page matches the editor (falling back to the built-in default
    # when nothing custom has been saved yet).
    custom_html = get_setting("custom_error_html") or DEFAULT_ERROR_HTML
    os.makedirs(ERRORS_DIR, exist_ok=True)
    with open(os.path.join(ERRORS_DIR, "ERR_ACCESS_DENIED"), "w") as fh:
        fh.write(custom_html)

    # Virus-blocked page: write it to the shared managed volume where c-icap's
    # VIRUS_FOUND template is symlinked, always (falling back to the built-in
    # default). The config-watcher triggers a c-icap reconfigure so the new
    # page is picked up immediately.
    custom_virus_html = get_setting("custom_virus_html") or DEFAULT_VIRUS_HTML
    os.makedirs(MANAGED_DIR, exist_ok=True)
    with open(VIRUS_PAGE, "w") as fh:
        fh.write(custom_virus_html)

    # Signal the watcher inside the ssl-proxy container to reconfigure Squid
    os.makedirs(os.path.dirname(RELOAD_TRIGGER), exist_ok=True)
    with open(RELOAD_TRIGGER, "w") as fh:
        fh.write(str(time.time()))

    set_setting("dirty", "0")
    set_setting("last_applied", time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()))


@app.route("/apply/confirm", methods=["POST"])
@login_required
def apply_confirm():
    write_and_apply()
    flash("Changes applied — Squid is reloading now.", "success")
    return redirect(url_for("dashboard_home"))


# ---------------------------------------------------------------------------
# Log monitoring (Squid access.log / cache.log, read from a shared volume)
# ---------------------------------------------------------------------------
def tail_file(path, max_lines=500, max_bytes=512 * 1024):
    """Return the last up-to max_lines lines of a file without reading the
    whole thing into memory (these logs can grow large)."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return []
    if size == 0:
        return []
    read_len = min(size, max_bytes)
    with open(path, "rb") as fh:
        fh.seek(size - read_len)
        data = fh.read()
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()
    # If we started mid-file, the first line is likely partial — drop it so
    # we don't show a torn line at the top.
    if read_len < size and lines:
        lines = lines[1:]
    return lines[-max_lines:]


@app.route("/logs")
@login_required
def logs_view():
    return render_template("logs.html", log_files=LOG_FILES)


@app.route("/logs/data/<name>")
@login_required
def logs_data(name):
    info = LOG_FILES.get(name)
    if not info:
        return jsonify({"error": "unknown log"}), 404
    path = os.path.join(LOGS_DIR, info[1])
    lines = tail_file(path)
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0
    return jsonify({"name": name, "label": info[0], "lines": lines, "size": size})


start_scheduler()


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
