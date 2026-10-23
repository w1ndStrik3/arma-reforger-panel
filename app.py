"""
Arma Reforger Server Management Panel
https://github.com/mateuszgolebiewski-code/arma-reforger-panel

Local fork — modifications:
  - Bcrypt-hashed admin password + constant-time verification + rate limiting
  - CSRF protection on state-changing routes
  - Persistent SECRET_KEY (sessions survive panel restart)
  - Named mod lists (one selected list is written into config.json at every launch)
  - Auto-discovery of scenarios from installed mods (`.pak` strings scan, mtime-cached)
"""

from flask import Flask, request, jsonify, session, redirect, Response, send_from_directory
import bcrypt
import psutil
import hmac
import re
import secrets
import subprocess
import sys
import os
import json
import threading
import time
import glob

IS_WINDOWS = os.name == "nt"

# ─── CONFIG ───────────────────────────────────────────────────────────────────

def load_env(path="config.env"):
    env = {}
    if not os.path.exists(path):
        return env
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, val = line.partition("=")
                env[key.strip()] = val.strip().strip('"').strip("'")
    return env

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_cfg = load_env(os.path.join(_BASE_DIR, "config.env"))

# Backwards-compatible password handling: prefer the bcrypt hash; if only the
# plaintext PANEL_PASSWORD is set (old configs), hash it in-memory at startup.
PANEL_PASSWORD_HASH = _cfg.get("PANEL_PASSWORD_HASH", "").strip()
_LEGACY_PLAINTEXT   = _cfg.get("PANEL_PASSWORD", "").strip()
if not PANEL_PASSWORD_HASH and _LEGACY_PLAINTEXT:
    PANEL_PASSWORD_HASH = bcrypt.hashpw(_LEGACY_PLAINTEXT.encode(), bcrypt.gensalt()).decode()
    print("[panel] WARNING: config.env uses legacy plaintext PANEL_PASSWORD. "
          "Re-run install.sh --update or replace it with PANEL_PASSWORD_HASH=...", flush=True)
if not PANEL_PASSWORD_HASH:
    PANEL_PASSWORD_HASH = bcrypt.hashpw(b"changeme", bcrypt.gensalt()).decode()
    print("[panel] WARNING: no panel password set. Defaulting to 'changeme'.", flush=True)

# On Windows the server keeps logs, addons and profile under
# Documents\My Games\ArmaReforger of the user it runs as.
_WIN_GAME_HOME = os.path.join(os.path.expanduser("~"), "Documents", "My Games", "ArmaReforger")

PANEL_PORT     = int(_cfg.get("PANEL_PORT", 8888))
# 127.0.0.1 = reachable only through a reverse proxy on the same machine.
PANEL_HOST     = _cfg.get("PANEL_HOST", "0.0.0.0")
# Set when the panel is served over HTTPS, so the browser never sends the
# session cookie over plain HTTP.
SECURE_COOKIES = _cfg.get("SECURE_COOKIES", "").strip().lower() in ("1", "true", "yes")
if IS_WINDOWS:
    SERVER_DIR    = _cfg.get("SERVER_DIR",    r"C:\arma\server")
    SERVER_CONFIG = _cfg.get("SERVER_CONFIG", os.path.join(SERVER_DIR, "config.json"))
    LOG_DIR       = _cfg.get("LOG_DIR",       os.path.join(_WIN_GAME_HOME, "logs"))
    WORKSHOP_DIR  = _cfg.get("WORKSHOP_DIR",  os.path.join(_WIN_GAME_HOME, "addons"))
else:
    SERVER_DIR    = _cfg.get("SERVER_DIR",    "/home/arma/server")
    SERVER_CONFIG = _cfg.get("SERVER_CONFIG", "/home/arma/server/config.json")
    LOG_DIR       = _cfg.get("LOG_DIR",       "/home/arma/.config/ArmaReforger/logs")
    WORKSHOP_DIR  = _cfg.get("WORKSHOP_DIR",  os.path.expanduser("~/.local/share/Arma Reforger/addons"))
# Where Reforger writes session saves. The real layout produced by the server
# under install.sh defaults is `{LOG_DIR_parent}/profile/.save/`, e.g.
# `/home/arma/.config/ArmaReforger/profile/.save/{game,playersave,settings}/`.
# Override with PROFILE_DIR in config.env if your install differs.
PROFILE_DIR    = _cfg.get(
    "PROFILE_DIR",
    os.path.join(os.path.dirname(LOG_DIR.rstrip("/\\")) or "/home/arma/.config/ArmaReforger", "profile"),
)
SERVER_BINARY  = os.path.join(SERVER_DIR, "ArmaReforgerServer.exe" if IS_WINDOWS else "ArmaReforgerServer")
MAX_FPS        = _cfg.get("MAX_FPS", "").strip()
# Seconds to wait for the server to save and exit on stop / soft restart.
SHUTDOWN_TIMEOUT = int(_cfg.get("SHUTDOWN_TIMEOUT", 180))
# Small helper that delivers Ctrl+C to the server's console on Windows.
_CTRL_C_HELPER = os.path.join(_BASE_DIR, "win_ctrl_c.py")

def build_server_args():
    """Build the launch arguments. `-loadSessionSave` is always passed: with no
    save files it's a no-op, and including it keeps panel-launched and
    systemd-launched starts behaving the same way. The 'enabled' toggle in the
    UI controls only the `persistence` block in config.json (autosave)."""
    args = ["-config", SERVER_CONFIG, "-loadSessionSave"]
    if MAX_FPS:
        args.append(f"-maxFPS={MAX_FPS}")
    return args

# Persistent secret key so sessions survive panel restarts.
_SECRET_FILE = os.path.join(_BASE_DIR, ".panel-secret")
def _load_or_create_secret():
    try:
        if os.path.exists(_SECRET_FILE):
            with open(_SECRET_FILE, "rb") as f:
                data = f.read().strip()
                if len(data) >= 32:
                    return data
    except OSError:
        pass
    data = secrets.token_bytes(48)
    try:
        with open(_SECRET_FILE, "wb") as f:
            f.write(data)
        os.chmod(_SECRET_FILE, 0o600)
    except OSError as e:
        print(f"[panel] WARNING: could not persist session secret ({e}); using ephemeral one.", flush=True)
    return data

app = Flask(__name__, static_folder='static')
app.secret_key = _load_or_create_secret()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=SECURE_COOKIES,
    PERMANENT_SESSION_LIFETIME=60 * 60 * 12,
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,  # 2 MB cap on uploads
)


# ─── SECURITY HELPERS ─────────────────────────────────────────────────────────

def _client_ip():
    # X-Forwarded-For is only believable when a reverse proxy on this machine
    # (Caddy, nginx, tailscale serve/funnel) added it; from anyone else it's
    # whatever the client chose to send. Proxies append the address they saw,
    # so the last entry is the real one; earlier entries can be forged.
    remote = request.remote_addr or ""
    if remote in ("127.0.0.1", "::1"):
        forwarded = request.headers.get("X-Forwarded-For", "").split(",")[-1].strip()
        if forwarded:
            return forwarded
    return remote or "unknown"


_LOGIN_BUCKETS: dict[str, list[float]] = {}
_LOGIN_WINDOW_SEC = 60.0
_LOGIN_MAX_ATTEMPTS = 5

def _login_rate_ok(ip: str) -> bool:
    now = time.time()
    bucket = [t for t in _LOGIN_BUCKETS.get(ip, []) if now - t < _LOGIN_WINDOW_SEC]
    if len(bucket) >= _LOGIN_MAX_ATTEMPTS:
        _LOGIN_BUCKETS[ip] = bucket
        return False
    bucket.append(now)
    _LOGIN_BUCKETS[ip] = bucket
    return True


def _verify_password(plain: str) -> bool:
    if not plain:
        return False
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), PANEL_PASSWORD_HASH.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def _ensure_csrf() -> str:
    tok = session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf"] = tok
    return tok


def _csrf_required() -> Response | None:
    """Check CSRF token from header or body. Returns an error Response or None."""
    expected = session.get("csrf")
    supplied = (
        request.headers.get("X-CSRF-Token", "")
        or (request.get_json(silent=True) or {}).get("_csrf", "")
        or request.form.get("_csrf", "")
    )
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        return jsonify({"ok": False, "error": "CSRF token invalid"}), 403
    return None


@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp

# ─── MISSIONS ─────────────────────────────────────────────────────────────────
#
# Hardcoded Bohemia/vanilla scenarios used as a fallback when the dedicated
# server install can't be scanned (e.g. SERVER_DIR misconfigured). When the
# server install IS scannable, dynamic discovery from its addons folder
# supersedes this list.

AVAILABLE_MISSIONS = [
    # Everon
    {"id": "{ECC61978EDCC2B5A}Missions/23_Campaign.conf",              "name": "Conflict — Everon"},
    {"id": "{C700DB41F0C546E1}Missions/23_Campaign_NorthCentral.conf", "name": "Conflict — Northern Everon"},
    {"id": "{28802845ADA64D52}Missions/23_Campaign_SWCoast.conf",      "name": "Conflict — Southern Everon"},
    {"id": "{94992A3D7CE4FF8A}Missions/23_Campaign_Western.conf",      "name": "Conflict — Western Everon"},
    {"id": "{FDE33AFE2ED7875B}Missions/23_Campaign_Montignac.conf",    "name": "Conflict — Montignac"},
    {"id": "{0220741028718E7F}Missions/23_Campaign_HQC_Everon.conf",   "name": "Conflict: HQ Commander — Everon"},
    {"id": "{59AD59368755F41A}Missions/21_GM_Eden.conf",               "name": "Game Master — Everon"},
    {"id": "{DFAC5FABD11F2390}Missions/26_CombatOpsEveron.conf",       "name": "Combat Ops — Everon"},
    # Capture & Hold
    {"id": "{3F2E005F43DBD2F8}Missions/CAH_Briars_Coast.conf",         "name": "Capture & Hold — Briars Coast"},
    {"id": "{F1A1BEA67132113E}Missions/CAH_Castle.conf",               "name": "Capture & Hold — Montfort Castle"},
    {"id": "{589945FB9FA7B97D}Missions/CAH_Concrete_Plant.conf",       "name": "Capture & Hold — Concrete Plant"},
    {"id": "{9405201CBD22A30C}Missions/CAH_Factory.conf",              "name": "Capture & Hold — Almara Factory"},
    {"id": "{1CD06B409C6FAE56}Missions/CAH_Forest.conf",               "name": "Capture & Hold — Simon's Wood"},
    {"id": "{7C491B1FCC0FF0E1}Missions/CAH_LeMoule.conf",              "name": "Capture & Hold — Le Moule"},
    {"id": "{6EA2E454519E5869}Missions/CAH_Military_Base.conf",        "name": "Capture & Hold — Camp Blake"},
    # Showcase / SP
    {"id": "{C47A1A6245A13B26}Missions/SP01_ReginaV2.conf",            "name": "Elimination"},
    {"id": "{0648CDB32D6B02B3}Missions/SP02_AirSupport.conf",          "name": "Air Support"},
    # Arland
    {"id": "{C41618FD18E9D714}Missions/23_Campaign_Arland.conf",       "name": "Conflict — Arland"},
    {"id": "{68D1240A11492545}Missions/23_Campaign_HQC_Arland.conf",   "name": "Conflict: HQ Commander — Arland"},
    {"id": "{2BBBE828037C6F4B}Missions/22_GM_Arland.conf",             "name": "Game Master — Arland"},
    {"id": "{DAA03C6E6099D50F}Missions/24_CombatOps.conf",             "name": "Combat Ops — Arland"},
    # Kolguyev
    {"id": "{F45C6C15D31252E6}Missions/27_GM_Cain.conf",               "name": "Game Master — Kolguyev"},
    {"id": "{BB5345C22DD2B655}Missions/23_Campaign_HQC_Cain.conf",     "name": "Conflict: HQ Commander — Kolguyev"},
    {"id": "{CB347F2F10065C9C}Missions/CombatOpsCain.conf",            "name": "Combat Ops — Kolguyev"},
    {"id": "{2B4183DF23E88249}Missions/CAH_Morton.conf",               "name": "Capture & Hold — Morton"},
    # Operation Omega
    {"id": "{10B8582BAD9F7040}Missions/Scenario01_Intro.conf",         "name": "Operation Omega 01: Over The Hills And Far Away"},
    {"id": "{1D76AF6DC4DF0577}Missions/Scenario02_Steal.conf",         "name": "Operation Omega 02: Radio Check"},
    {"id": "{D1647575BCEA5A05}Missions/Scenario03_Villa.conf",         "name": "Operation Omega 03: Light In The Dark"},
    {"id": "{6D224A109B973DD8}Missions/Scenario04_Sabotage.conf",      "name": "Operation Omega 04: Red Silence"},
    {"id": "{FA2AB0181129CB16}Missions/Scenario05_Hill.conf",          "name": "Operation Omega 05: Cliffhanger"},
]
# Add a "source" tag so the UI can group by origin.
for _m in AVAILABLE_MISSIONS:
    _m.setdefault("source", "vanilla")


# Friendly display names for scenarios discovered via .rdb (which only gives
# us the filename, not the publisher's display name). Used as an override when
# the .rdb scan finds a known scenario ID. Anything not listed here falls back
# to the cleaned-up filename derived from the path.
_SCENARIO_NAME_OVERRIDES = {
    # RHS — Status Quo
    "{AAD43C10045857C1}Missions/RHS_Conflict.conf":              ("Conflict — Everon (RHS)",                 64),
    "{B694A77592CB69E0}Missions/RHS_ConflictWithoutAIs.conf":    ("Conflict — Everon, no AI (RHS)",          64),
    "{9909DB7ECEA05535}Missions/RHS_Conflict_East.conf":         ("Conflict — Everon East (RHS)",            40),
    "{2F5DD5ACC14120A9}Missions/RHS_Conflict_NorthCentral.conf": ("Conflict — Everon North Central (RHS)",   64),
    "{57B154A20B8B283E}Missions/RHS_Conflict_SWCoast.conf":      ("Conflict — Everon SW Coast (RHS)",        64),
    "{367A7800D147878A}Missions/RHS_Conflict_West.conf":         ("Conflict — Everon West (RHS)",            40),
    "{7577640CD42A00BD}Missions/RHS_Conflict_Arland.conf":       ("Conflict — Arland (RHS)",                 64),
    "{C5EAD55037EB4751}Missions/RHS_CombatOps_MSV.conf":         ("Combat Ops — Arland, MSV vs FIA (RHS)",   16),
    "{D10B11A71A36FCF5}Missions/RHS_CombatOps_USMC_vs_MSV.conf": ("Combat Ops — Arland, USMC vs MSV (RHS)",  16),
    "{68A6FBF43B801FF6}Missions/RHS_ShowcaseBasic.conf":         ("Showcase Mission (RHS)",                   6),
    "{217436B52D34E4BD}Missions/RHS_Showcase_GM.conf":           ("Showcase Mission, Game Master (RHS)",     36),
}


# ─── SCENARIO AUTO-DISCOVERY (workshop meta) ─────────────────────────────────
#
# Reforger workshop mods unpack to <WORKSHOP_DIR>/<Name>_<HEXID>/. Each addon
# ships a `meta` file (UTF-8-with-BOM JSON) that contains the workshop
# metadata, including a `versions[].scenarios[]` array. Each scenario entry
# is a dict with at least `name` and `gameId` (the full {HEX16}Missions/...
# .conf identifier we need). This is far more reliable than scanning the
# binary .pak file — and the `meta` file is tiny, so the scan is instant.
#
# We cache results per addon dir by `meta` mtime to avoid re-reading the same
# file if nothing changed.

_SCENARIO_GAME_ID_RE = re.compile(r'^\{[0-9A-Fa-f]{16}\}.+\.conf$')
_SCAN_CACHE_FILE = os.path.join(_BASE_DIR, ".scenario-cache.json")


def _scan_cache_load():
    try:
        with open(_SCAN_CACHE_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("mods", {}), data.get("mtimes", {})
    except (OSError, json.JSONDecodeError):
        return {}, {}


def _scan_cache_save(mods, mtimes):
    try:
        with open(_SCAN_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump({"mods": mods, "mtimes": mtimes, "saved_at": time.time()}, f)
    except OSError as e:
        print(f"[panel] WARNING: could not write scenario cache: {e}", flush=True)


_SCAN_LOCK = threading.Lock()
_LAST_SCAN_RESULT: dict = {"scenarios": [], "diag": None, "ts": 0.0}


def _candidate_addon_roots():
    """Locations to scan for addons. Each entry is (path, is_vanilla).
    `is_vanilla=True` means anything found there is Bohemia-shipped game
    content (the dedicated server's bundled addons), not a workshop mod."""
    home = os.path.dirname(SERVER_DIR.rstrip("/")) if SERVER_DIR else os.path.expanduser("~")
    if not home or home == "/":
        home = os.path.expanduser("~arma") if os.path.isdir("/home/arma") else os.path.expanduser("~")

    roots = []
    # Workshop mod dirs (downloaded via SteamCMD / the game)
    if WORKSHOP_DIR:
        roots.append((WORKSHOP_DIR, False))
    if IS_WINDOWS:
        roots.append((os.path.join(_WIN_GAME_HOME, "addons"), False))
    roots.extend([
        (os.path.join(home, ".local/share/Arma Reforger/profile/addons"), False),
        (os.path.join(home, ".local/share/Arma Reforger/addons"),         False),
        (os.path.join(home, ".config/Arma Reforger/addons"),              False),
        (os.path.join(home, ".config/ArmaReforger/addons"),               False),
    ])
    # Bohemia-shipped game content (Conflict, GM, CAH, Operation Omega, etc.)
    if SERVER_DIR:
        roots.extend([
            (os.path.join(SERVER_DIR, "Addons"), True),
            (os.path.join(SERVER_DIR, "addons"), True),
            (SERVER_DIR,                          True),  # falls back to walking server install
        ])
    seen, out = set(), []
    for path, vanilla in roots:
        if path and path not in seen and os.path.isdir(path):
            seen.add(path)
            out.append((path, vanilla))
    return out


def _find_addons(root, max_depth=4):
    """Walk `root` up to `max_depth` levels and yield (addon_dir, meta_or_None,
    rdb_or_None) for every directory that looks like a Reforger addon (i.e.
    contains a `meta` JSON, a `resourceDatabase.rdb`, or an `addon.gproj`)."""
    if not root or not os.path.isdir(root):
        return
    root = os.path.abspath(root)
    base_depth = root.rstrip("/").count("/")
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        depth = dirpath.rstrip("/").count("/") - base_depth
        if depth >= max_depth:
            dirnames[:] = []
        meta_file = os.path.join(dirpath, "meta") if "meta" in filenames else None
        rdb_file = os.path.join(dirpath, "resourceDatabase.rdb") if "resourceDatabase.rdb" in filenames else None
        gproj = "addon.gproj" in filenames
        if meta_file or rdb_file or gproj:
            # Don't descend into addon dirs further (their inner files aren't more addons)
            dirnames[:] = []
            if meta_file or rdb_file:
                yield dirpath, meta_file, rdb_file


def _addon_name_from_gproj(addon_dir):
    """Pull a friendly display name from addon.gproj (TITLE or ID field)."""
    gproj = os.path.join(addon_dir, "addon.gproj")
    if not os.path.isfile(gproj):
        return None
    try:
        with open(gproj, encoding="utf-8", errors="replace") as f:
            text = f.read(2048)
    except OSError:
        return None
    m = re.search(r'TITLE\s+"([^"]+)"', text) or re.search(r'ID\s+"([^"]+)"', text)
    return m.group(1).strip() if m else None


_RDB_PATH_RE = re.compile(rb'Missions/[A-Za-z0-9_./\-]+\.conf')

def _scenarios_from_rdb(rdb_path, source_label):
    """Fallback: parse `resourceDatabase.rdb` for scenario records.

    The dedicated-server workshop downloader strips `meta.versions[].scenarios`
    on Linux (just an empty list), so we can't rely on the JSON for those.
    The .rdb file ships next to data.pak in every addon and contains the
    asset directory in a simple length-prefixed binary format. Each scenario
    asset record looks like:
        <4-byte LE length>  <path bytes>  <\\0>  <6-byte padding>  <8-byte LE GUID>  …
    where the LE length equals len(path) + 1 (counting the null terminator).
    The 8-byte GUID is little-endian, so we reverse it for the {HEX16} display.

    We rely on the path-prefix `Missions/` to filter for scenarios, then
    validate each candidate by checking the length prefix matches; this
    rejects stray substring hits in unrelated records.
    """
    try:
        with open(rdb_path, "rb") as f:
            data = f.read()
    except OSError:
        return []

    out = []
    seen = set()
    for m in _RDB_PATH_RE.finditer(data):
        ps, pe = m.start(), m.end()
        if ps < 4:
            continue
        path_len_field = int.from_bytes(data[ps - 4:ps], "little")
        if path_len_field != (pe - ps) + 1:
            continue  # not a length-prefixed record — likely a substring inside something else
        if pe >= len(data) or data[pe] != 0:
            continue
        guid_start = pe + 7  # 1 null byte + 6-byte padding
        if guid_start + 8 > len(data):
            continue
        guid_bytes = data[guid_start:guid_start + 8]
        # Reject obviously-bogus GUIDs (all-zero / all-0xFF fillers).
        if guid_bytes == b"\x00" * 8 or guid_bytes == b"\xff" * 8:
            continue
        guid_hex = guid_bytes[::-1].hex().upper()  # little-endian → big-endian display
        path_str = m.group(0).decode("ascii", errors="replace")
        sid = "{" + guid_hex + "}" + path_str
        if sid in seen:
            continue
        seen.add(sid)
        out.append({
            "id": sid,
            "name": path_str.split("/")[-1].replace(".conf", ""),
            "description": "",
            "player_count": None,
            "source": source_label or "mod",
        })
    return out


def _scenarios_from_meta(meta_path):
    """Parse a workshop `meta` file and return a list of scenario dicts:
       [{id, name, description, player_count, source}, ...]
       The `meta` file is UTF-8 with BOM and contains the workshop publisher
       metadata. Scenarios appear under meta.versions[].scenarios[].
    """
    try:
        with open(meta_path, encoding="utf-8-sig") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return [], None

    m = (data.get("meta") or {})
    mod_name = (m.get("name") or "").strip()

    # Pull scenarios from the latest version (versions[0]) — that's what's installed.
    versions = m.get("versions") or []
    raw_scenarios = []
    if versions and isinstance(versions, list):
        raw_scenarios = versions[0].get("scenarios") or []
    if not raw_scenarios:
        # Some older meta layouts have a top-level scenarios array.
        raw_scenarios = m.get("scenarios") or []
    if not isinstance(raw_scenarios, list):
        return [], mod_name

    out = []
    for s in raw_scenarios:
        if not isinstance(s, dict):
            continue
        sid = (s.get("gameId") or "").strip()
        if not sid or not _SCENARIO_GAME_ID_RE.match(sid):
            continue
        out.append({
            "id":           sid,
            "name":         (s.get("name") or sid.split("/")[-1].replace(".conf", "")).strip(),
            "description":  (s.get("description") or "").strip()[:300],
            "player_count": s.get("playerCount") if isinstance(s.get("playerCount"), int) else None,
            "source":       mod_name or "mod",
        })
    return out, mod_name


def _apply_name_override(scenario):
    """If we have a curated friendly name for this scenario ID, use it."""
    override = _SCENARIO_NAME_OVERRIDES.get(scenario["id"])
    if override:
        scenario["name"] = override[0]
        if override[1] and not scenario.get("player_count"):
            scenario["player_count"] = override[1]
    return scenario


def _discover_locked(force_rescan):
    """Actual scan work. Caller must hold _SCAN_LOCK."""
    diag = {"candidates_tried": [], "addons_scanned": 0,
            "mods_with_scenarios": 0, "scenarios_total": 0, "errors": []}

    cache_mods, cache_mtimes = ({}, {}) if force_rescan else _scan_cache_load()
    fresh_mods, fresh_mtimes = {}, {}

    seen_addon_dirs = set()
    addons_scanned = 0

    for root, is_vanilla in _candidate_addon_roots():
        diag["candidates_tried"].append({"path": root, "vanilla": is_vanilla})
        for addon_dir, meta_path, rdb_path in _find_addons(root):
            real_dir = os.path.realpath(addon_dir)
            if real_dir in seen_addon_dirs:
                continue
            seen_addon_dirs.add(real_dir)
            addons_scanned += 1

            # Cache key tracks both files so we re-scan if either changes.
            cache_key = real_dir
            try:
                meta_mtime = os.path.getmtime(meta_path) if meta_path else 0
                rdb_mtime  = os.path.getmtime(rdb_path) if rdb_path else 0
                mtime = max(meta_mtime, rdb_mtime)
            except OSError as e:
                diag["errors"].append(f"{cache_key}: stat failed ({e})")
                continue

            if cache_mtimes.get(cache_key) == mtime and cache_key in cache_mods:
                fresh_mods[cache_key] = cache_mods[cache_key]
                fresh_mtimes[cache_key] = mtime
                continue

            scenarios = []
            mod_name = None
            # 1. Try the workshop meta JSON first (gives us the publisher's
            #    display names + player counts when populated).
            if meta_path:
                scenarios, mod_name = _scenarios_from_meta(meta_path)
            # 2. Fall back to the .rdb scan when the meta has no scenarios
            #    (Linux dedi strips them) or when there's no meta at all
            #    (Bohemia's bundled vanilla addons).
            if not scenarios and rdb_path:
                if not mod_name:
                    mod_name = _addon_name_from_gproj(addon_dir) or os.path.basename(addon_dir)
                source = "vanilla" if is_vanilla else mod_name
                scenarios = _scenarios_from_rdb(rdb_path, source)
            # 3. Force-tag everything found in the server install dir as vanilla.
            if is_vanilla:
                for s in scenarios:
                    s["source"] = "vanilla"
            # 4. Single-scenario mods are usually named after their scenario.
            #    The .rdb fallback only knows the filename (e.g.
            #    "MontfordFortress"), but the workshop name is the friendly
            #    one ("Fortress"). When a mod publishes exactly one scenario
            #    and we have an addon display name, prefer that — unless an
            #    explicit override is already in place.
            if len(scenarios) == 1 and not is_vanilla and mod_name:
                if scenarios[0]["id"] not in _SCENARIO_NAME_OVERRIDES:
                    scenarios[0]["name"] = mod_name
            # 5. Apply our curated friendly-name overrides (mainly RHS).
            for s in scenarios:
                _apply_name_override(s)

            if scenarios:
                fresh_mods[cache_key] = scenarios
            fresh_mtimes[cache_key] = mtime

    _scan_cache_save(fresh_mods, fresh_mtimes)

    flat = []
    for sids in fresh_mods.values():
        flat.extend(sids)
    diag["addons_scanned"] = addons_scanned
    diag["mods_with_scenarios"] = len(fresh_mods)
    diag["scenarios_total"] = len(flat)
    # Back-compat fields the old UI knew about
    diag["workshop_dir"] = "; ".join(p for p, _ in _candidate_addon_roots()) or None
    diag["metas_found"]  = addons_scanned
    return flat, diag


def discover_mod_scenarios(force_rescan=False):
    """Return (scenarios, diag).
       Lock-protected so concurrent /api/status polls or rescan clicks can't
       launch overlapping scans.  Non-rescan callers get the cached result
       without doing any disk I/O if a scan is already in progress."""
    if not force_rescan:
        # Cheap path: just read the on-disk cache.
        cache_mods, _mtimes = _scan_cache_load()
        if cache_mods:
            flat = []
            for sids in cache_mods.values():
                flat.extend(sids)
            diag = {"workshop_dir": None, "paks_found": len(cache_mods),
                    "scenarios_total": len(flat), "from_cache": True}
            return flat, diag

    if not _SCAN_LOCK.acquire(blocking=force_rescan):
        # Scan in progress and we don't want to block — return whatever we have.
        return _LAST_SCAN_RESULT["scenarios"], (_LAST_SCAN_RESULT["diag"] or {"busy": True})
    try:
        scenarios, diag = _discover_locked(force_rescan)
        _LAST_SCAN_RESULT["scenarios"] = scenarios
        _LAST_SCAN_RESULT["diag"] = diag
        _LAST_SCAN_RESULT["ts"] = time.time()
        return scenarios, diag
    finally:
        _SCAN_LOCK.release()


def cached_scenarios():
    """Cheap read for /api/status — never triggers a fresh scan."""
    cache_mods, _mtimes = _scan_cache_load()
    flat = []
    for sids in cache_mods.values():
        flat.extend(sids)
    return flat


def all_scenarios(force_rescan=False):
    """Vanilla list + auto-discovered, deduped by id (vanilla wins for naming).
       Returns (list, diag)."""
    by_id = {}
    for s in AVAILABLE_MISSIONS:
        by_id[s["id"]] = dict(s)
    discovered, diag = discover_mod_scenarios(force_rescan=force_rescan)
    for s in discovered:
        by_id.setdefault(s["id"], dict(s))
    out = list(by_id.values())
    out.sort(key=lambda s: (s["source"] != "vanilla", s["source"], s["name"]))
    return out, diag


def all_scenarios_cached():
    """Like all_scenarios() but never scans — used by /api/status hot path."""
    by_id = {}
    for s in AVAILABLE_MISSIONS:
        by_id[s["id"]] = dict(s)
    for s in cached_scenarios():
        by_id.setdefault(s["id"], dict(s))
    out = list(by_id.values())
    out.sort(key=lambda s: (s["source"] != "vanilla", s["source"], s["name"]))
    return out


# ─── HELPERS ──────────────────────────────────────────────────────────────────

# The server's psutil.Process is kept between calls: cpu_percent() measures
# usage since the previous call on the same object.
_server_proc = None

def _is_server_process(p):
    # Linux truncates process names to 15 chars, so also look at argv[0].
    if (p.info.get("name") or "").startswith("ArmaReforgerSer"):
        return True
    cmd = p.info.get("cmdline") or []
    return bool(cmd) and os.path.basename(cmd[0]).startswith("ArmaReforgerServer")

def get_server_process():
    global _server_proc
    p = _server_proc
    if p is not None:
        try:
            if p.is_running() and p.status() != psutil.STATUS_ZOMBIE:
                return p
        except psutil.Error:
            pass
        _server_proc = None
    for p in psutil.process_iter(["name", "cmdline"]):
        try:
            if _is_server_process(p) and p.status() != psutil.STATUS_ZOMBIE:
                _server_proc = p
                return p
        except psutil.Error:
            continue
    return None

def get_server_pid():
    p = get_server_process()
    return p.pid if p else None

def get_process_uptime(proc):
    try:
        return max(0, int(time.time() - proc.create_time()))
    except psutil.Error:
        return 0

def format_uptime(seconds):
    if seconds < 60:    return f"{seconds}s"
    if seconds < 3600:  return f"{seconds // 60}m {seconds % 60}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60}m"

def get_cpu_ram(proc):
    try:
        cpu = round(proc.cpu_percent(None) / (psutil.cpu_count() or 1), 1)
        ram = round(proc.memory_info().rss / 1024 / 1024, 1)
        return cpu, ram
    except psutil.Error:
        return 0.0, 0.0

def get_system_ram():
    try:
        mem = psutil.virtual_memory()
        total = round(mem.total / 1024 / 1024, 1)
        used  = round((mem.total - mem.available) / 1024 / 1024, 1)
        return used, total
    except Exception:
        return 0, 0

def tail_lines(path, n):
    """Last `n` lines of a file, read backwards in blocks so big logs stay cheap."""
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        pos = f.tell()
        data = b""
        while pos > 0 and data.count(b"\n") <= n:
            step = min(8192, pos)
            pos -= step
            f.seek(pos)
            data = f.read(step) + data
    return data.decode("utf-8", errors="replace").splitlines()[-n:]

def launch_server():
    apply_selected_modlist()
    if IS_WINDOWS:
        # Give the server its own console, as if started by hand, so the panel
        # can later send it Ctrl+C for a clean save-and-exit.
        subprocess.Popen([SERVER_BINARY] + build_server_args(), cwd=SERVER_DIR,
                         creationflags=subprocess.CREATE_NEW_CONSOLE)
    else:
        subprocess.Popen([SERVER_BINARY] + build_server_args(), cwd=SERVER_DIR,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)

def request_shutdown(proc):
    """Ask the server to save the game state and exit. On Windows this is the
    same as pressing Ctrl+C in its console; on Linux it sends SIGTERM."""
    if not IS_WINDOWS:
        proc.terminate()
        return
    # Attaching to another process's console means leaving our own first, so
    # it's done in a short-lived helper rather than in the panel itself.
    r = subprocess.run([sys.executable, _CTRL_C_HELPER, str(proc.pid)],
                       capture_output=True, text=True, timeout=15,
                       creationflags=subprocess.DETACHED_PROCESS)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or f"Ctrl+C helper exited with code {r.returncode}")

def get_latest_log():
    try:
        dirs = sorted(glob.glob(f"{LOG_DIR}/logs_*"), reverse=True)
        if not dirs:
            return None
        path = os.path.join(dirs[0], "console.log")
        return path if os.path.exists(path) else None
    except Exception:
        return None

def read_config():
    try:
        with open(SERVER_CONFIG, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def write_config(cfg):
    with open(SERVER_CONFIG, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent="\t")

# ─── PERSISTENCE ─────────────────────────────────────────────────────────────
#
# Reforger session save/load. The toggle is the presence of a top-level
# `persistence` block in config.json (autosave); `-loadSessionSave` is always
# passed at launch so any existing save loads on start. Save files live under
# PROFILE_DIR/.save/ on Linux dedicated installs (Conflict / Combat Ops layout).
# Subdirs underneath: game/ (world/session), playersave/ (per-player), settings/.

_SAVE_SUBDIRS = (".save", "save", "saves")

def _get_persistence_block(cfg):
    """Read the persistence block at its real schema location:
    `game.gameProperties.persistence`. Returns the block dict or None."""
    gp = (cfg.get("game") or {}).get("gameProperties") or {}
    block = gp.get("persistence")
    return block if isinstance(block, dict) else None

def _set_persistence_block(cfg, block):
    """Write `block` (a dict) at game.gameProperties.persistence, or remove it
    if `block` is None. Also pops any legacy top-level `persistence` key — the
    1.6 server schema rejects it, so its presence is always a bug."""
    cfg.pop("persistence", None)
    gp = cfg.setdefault("game", {}).setdefault("gameProperties", {})
    if block is None:
        gp.pop("persistence", None)
    else:
        gp["persistence"] = block

def _persistence_enabled(cfg=None):
    if cfg is None:
        cfg = read_config()
    return _get_persistence_block(cfg) is not None

# Subdirs the flush button targets. `settings/` is intentionally preserved
# because it holds non-session config the server expects to regenerate from.
_FLUSHABLE_SUBDIRS = ("game", "playersave")

def _save_root():
    for sub in _SAVE_SUBDIRS:
        p = os.path.join(PROFILE_DIR, sub)
        if os.path.isdir(p):
            return p
    return os.path.join(PROFILE_DIR, ".save")  # canonical Linux dedicated path

def _scan_dir(path):
    """Return {count, bytes, newest} for files under `path`, or zeros if absent."""
    if not os.path.isdir(path):
        return {"count": 0, "bytes": 0, "newest": None}
    count = 0
    total = 0
    newest = 0.0
    for dirpath, _dirs, files in os.walk(path):
        for fn in files:
            try:
                st = os.stat(os.path.join(dirpath, fn))
            except OSError:
                continue
            count += 1
            total += st.st_size
            if st.st_mtime > newest:
                newest = st.st_mtime
    return {"count": count, "bytes": total, "newest": newest or None}

def _scan_saves():
    root = _save_root()
    if not os.path.isdir(root):
        return {"path": root, "exists": False, "total": {"count": 0, "bytes": 0, "newest": None}, "buckets": {}}
    buckets = {name: _scan_dir(os.path.join(root, name)) for name in ("game", "playersave", "settings")}
    total_count = sum(b["count"] for b in buckets.values())
    total_bytes = sum(b["bytes"] for b in buckets.values())
    newest_vals = [b["newest"] for b in buckets.values() if b["newest"]]
    return {
        "path":    root,
        "exists":  True,
        "buckets": buckets,
        "total":   {
            "count":  total_count,
            "bytes":  total_bytes,
            "newest": max(newest_vals) if newest_vals else None,
        },
    }

def _flush_saves():
    """Remove the contents of `.save/game/` and `.save/playersave/` (world
    session + per-player data). `.save/settings/` is left alone — it holds
    non-session config the server regenerates from. Returns the count of files
    deleted."""
    import shutil
    root = _save_root()
    if not os.path.isdir(root):
        return 0
    removed = 0
    for sub in _FLUSHABLE_SUBDIRS:
        bucket = os.path.join(root, sub)
        if not os.path.isdir(bucket):
            continue
        for name in os.listdir(bucket):
            full = os.path.join(bucket, name)
            try:
                if os.path.isdir(full) and not os.path.islink(full):
                    for _dp, _dn, files in os.walk(full):
                        removed += len(files)
                    shutil.rmtree(full)
                else:
                    os.remove(full)
                    removed += 1
            except OSError:
                pass
    return removed


def get_map_name(cfg=None):
    """The scenario's resource name, e.g. {0648CDB32D6B02B3}Missions/SP02_AirSupport.conf."""
    if cfg is None:
        cfg = read_config()
    return cfg.get("game", {}).get("scenarioId", "") or "Unknown"

# ─── ROUTES ───────────────────────────────────────────────────────────────────

@app.route("/manifest.json")
def manifest():
    return send_from_directory('static', 'manifest.json', mimetype='application/manifest+json')

@app.route("/service-worker.js")
def service_worker():
    return send_from_directory('static', 'service-worker.js', mimetype='application/javascript')

@app.route("/")
def index():
    if not session.get("logged_in"):
        return redirect("/login")
    _ensure_csrf()
    with open(os.path.join(_BASE_DIR, "index.html"), encoding="utf-8") as f:
        return f.read()

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = _client_ip()
        if not _login_rate_ok(ip):
            return jsonify({"ok": False, "error": "Too many attempts. Wait a minute."}), 429
        data = request.get_json(silent=True) or {}
        # bcrypt is intentionally slow — even on a successful login it adds ~100ms,
        # which is also a natural defense against brute force.
        if _verify_password(data.get("password", "")):
            session.clear()
            session.permanent = True
            session["logged_in"] = True
            session["login_at"] = int(time.time())
            _ensure_csrf()
            return jsonify({"ok": True, "csrf": session["csrf"]})
        return jsonify({"ok": False, "error": "Invalid password"}), 401
    with open(os.path.join(_BASE_DIR, "login.html"), encoding="utf-8") as f:
        return f.read()

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})

@app.route("/api/csrf")
def api_csrf():
    """Front-end fetches a CSRF token after login and on tab refresh."""
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"csrf": _ensure_csrf()})

@app.route("/api/status")
def api_status():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    proc = get_server_process()
    pid = proc.pid if proc else None
    cfg = read_config()
    cpu, ram = get_cpu_ram(proc) if proc else (0.0, 0.0)
    uptime = get_process_uptime(proc) if proc else 0
    ram_used, ram_total = get_system_ram()
    missions = all_scenarios_cached()
    return jsonify({
        "running":        pid is not None,
        "pid":            pid,
        "lifecycle":      dict(_LIFECYCLE),
        "map":            get_map_name(cfg),
        "players":        0,
        "uptime":         format_uptime(uptime) if proc else "—",
        "uptime_sec":     uptime,
        "server_name":    cfg.get("game", {}).get("name", "—"),
        "ip":             cfg.get("publicAddress", "—"),
        "port":           cfg.get("publicPort", "—"),
        "scenario_id":    cfg.get("game", {}).get("scenarioId", ""),
        "missions":       missions,
        "missions_count": {"vanilla": sum(1 for m in missions if m.get("source") == "vanilla"),
                           "from_mods": sum(1 for m in missions if m.get("source") != "vanilla")},
        "password":       cfg.get("game", {}).get("password", ""),
        "password_admin": cfg.get("game", {}).get("passwordAdmin", ""),
        "cpu":            cpu,
        "ram_process":    ram,
        "ram_used":       ram_used,
        "ram_total":      ram_total,
        "csrf":           _ensure_csrf(),
    })

@app.route("/api/scenarios/rescan", methods=["POST"])
def api_scenarios_rescan():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    missions, diag = all_scenarios(force_rescan=True)
    return jsonify({
        "ok": True,
        "missions": missions,
        "missions_count": {"vanilla": sum(1 for m in missions if m.get("source") == "vanilla"),
                           "from_mods": sum(1 for m in missions if m.get("source") != "vanilla")},
        "diag": diag,
    })

@app.route("/api/metrics")
def api_metrics():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    proc = get_server_process()
    cpu, ram = get_cpu_ram(proc) if proc else (0.0, 0.0)
    ram_used, ram_total = get_system_ram()
    return jsonify({
        "cpu": cpu, "ram_process": ram,
        "ram_used": ram_used, "ram_total": ram_total,
        "running": proc is not None, "ts": int(time.time()),
    })

@app.route("/api/logs")
def api_logs():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    n = max(1, min(int(request.args.get("lines", 100)), 5000))
    path = get_latest_log()
    if not path:
        return jsonify({"lines": [], "path": None})
    try:
        return jsonify({"lines": tail_lines(path, n), "path": path})
    except Exception as e:
        return jsonify({"lines": [], "error": str(e)})

@app.route("/api/config", methods=["POST"])
def api_config():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    data = request.get_json(silent=True) or {}
    cfg  = read_config()
    changed = False
    if "server_name" in data and data["server_name"].strip():
        cfg.setdefault("game", {})["name"] = data["server_name"].strip(); changed = True
    if "scenario_id" in data:
        sid = data["scenario_id"].strip()
        valid_ids = {m["id"] for m in all_scenarios_cached()}
        if sid not in valid_ids:
            return jsonify({"ok": False, "error": "Unknown scenario"})
        cfg.setdefault("game", {})["scenarioId"] = sid; changed = True
    if "password" in data:
        cfg.setdefault("game", {})["password"] = data["password"]; changed = True
    if "password_admin" in data and data["password_admin"].strip():
        cfg.setdefault("game", {})["passwordAdmin"] = data["password_admin"].strip(); changed = True
    if not changed:
        return jsonify({"ok": False, "error": "No changes"})
    try:
        write_config(cfg)
        return jsonify({"ok": True, "restart_required": get_server_pid() is not None})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/persistence", methods=["GET"])
def api_persistence_get():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    cfg = read_config()
    block = _get_persistence_block(cfg) or {}
    saves = _scan_saves()
    return jsonify({
        "enabled":          _persistence_enabled(cfg),
        "autoSaveInterval": block.get("autoSaveInterval", 10),
        "hiveId":           block.get("hiveId", 1),
        "saves":            saves,
        "profile_dir":      PROFILE_DIR,
    })

@app.route("/api/persistence", methods=["POST"])
def api_persistence_set():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    data = request.get_json(silent=True) or {}
    cfg  = read_config()
    enabled = bool(data.get("enabled"))
    if enabled:
        block = _get_persistence_block(cfg) or {}
        if "autoSaveInterval" in data:
            try:
                v = int(data["autoSaveInterval"])
            except (TypeError, ValueError):
                return jsonify({"ok": False, "error": "autoSaveInterval must be an integer"})
            if not 0 <= v <= 60:
                return jsonify({"ok": False, "error": "autoSaveInterval must be between 0 and 60"})
            block["autoSaveInterval"] = v
        else:
            block.setdefault("autoSaveInterval", 10)
        if "hiveId" in data:
            try:
                v = int(data["hiveId"])
            except (TypeError, ValueError):
                return jsonify({"ok": False, "error": "hiveId must be an integer"})
            if not 0 <= v <= 16383:
                return jsonify({"ok": False, "error": "hiveId must be between 0 and 16383"})
            block["hiveId"] = v
        else:
            block.setdefault("hiveId", 1)
        _set_persistence_block(cfg, block)
    else:
        _set_persistence_block(cfg, None)
    try:
        write_config(cfg)
        return jsonify({
            "ok": True,
            "restart_required": get_server_pid() is not None,
            "enabled":           _persistence_enabled(cfg),
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/persistence/flush", methods=["POST"])
def api_persistence_flush():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    # Refuse to delete saves while the server is running — the game holds file
    # handles and may rewrite them mid-flush, which leaves us with partials.
    if get_server_pid():
        return jsonify({"ok": False, "error": "Stop the server before flushing saves"})
    try:
        removed = _flush_saves()
        return jsonify({"ok": True, "removed": removed, "saves": _scan_saves()})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

# ─── MOD LISTS ───────────────────────────────────────────────────────────────
#
# Each mod list is a JSON array saved as modlists/<name>.json. One list is
# selected (stored in .panel-state.json); right before every server launch its
# contents replace game.mods in config.json. On first run the mods currently in
# config.json become a list named "default".

MODLISTS_DIR = os.path.join(_BASE_DIR, "modlists")
_STATE_FILE  = os.path.join(_BASE_DIR, ".panel-state.json")
_MODLIST_LOCK = threading.Lock()

_MODLIST_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _.()-]{0,63}")
_WIN_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"{p}{i}" for p in ("COM", "LPT") for i in range(1, 10)}

def _valid_modlist_name(name):
    # Names become file names, so keep them safe on both Linux and Windows.
    return (isinstance(name, str) and _MODLIST_NAME_RE.fullmatch(name) is not None
            and not name.endswith((".", " "))
            and name.split(".")[0].strip().upper() not in _WIN_RESERVED)

def _modlist_path(name):
    return os.path.join(MODLISTS_DIR, name + ".json")

def list_modlists():
    if not os.path.isdir(MODLISTS_DIR):
        return []
    names = [fn[:-5] for fn in os.listdir(MODLISTS_DIR) if fn.endswith(".json")]
    return sorted((n for n in names if _valid_modlist_name(n)), key=str.casefold)

def _find_modlist(name):
    """The stored list matching `name` ignoring case (Windows file names are
    case-insensitive), or None."""
    for n in list_modlists():
        if n.casefold() == name.casefold():
            return n
    return None

def parse_modlist(text):
    """Validate a mod list's JSON text. Returns (mods, error). Entries are kept
    exactly as written apart from the checks below."""
    try:
        mods = json.loads(text)
    except json.JSONDecodeError as e:
        return None, f"Invalid JSON: {e.msg} at line {e.lineno} col {e.colno}"
    if not isinstance(mods, list):
        return None, "A mod list must be a JSON array: [ ... ]"
    seen = set()
    for i, m in enumerate(mods, 1):
        if not isinstance(m, dict):
            return None, f"Entry #{i} is not an object"
        mod_id = m.get("modId")
        if not isinstance(mod_id, str) or not re.fullmatch(r"[0-9A-Fa-f]{1,32}", mod_id):
            return None, f"Entry #{i}: modId must be 1-32 hex characters"
        if mod_id.upper() in seen:
            return None, f"Entry #{i}: duplicate modId {mod_id}"
        seen.add(mod_id.upper())
    return mods, None

def load_modlist(name):
    with open(_modlist_path(name), encoding="utf-8") as f:
        mods, error = parse_modlist(f.read())
    if error:
        raise ValueError(f"Mod list '{name}': {error}")
    return mods

def save_modlist(name, mods):
    os.makedirs(MODLISTS_DIR, exist_ok=True)
    tmp = _modlist_path(name) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(mods, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, _modlist_path(name))

def get_selected_modlist():
    try:
        with open(_STATE_FILE, encoding="utf-8") as f:
            name = json.load(f).get("selected_modlist")
    except (OSError, ValueError, AttributeError):
        return None
    return name if isinstance(name, str) and _find_modlist(name) == name else None

def set_selected_modlist(name):
    with open(_STATE_FILE, "w", encoding="utf-8") as f:
        json.dump({"selected_modlist": name}, f)

def ensure_modlists():
    """First run: turn the mods currently in config.json into a "default" list."""
    with _MODLIST_LOCK:
        if os.path.isdir(MODLISTS_DIR):
            return
        save_modlist("default", read_config().get("game", {}).get("mods", []))
        set_selected_modlist("default")

def apply_selected_modlist():
    """Write the selected mod list into config.json's game.mods. Called right
    before every launch; with no list selected config.json is left alone."""
    name = get_selected_modlist()
    if not name:
        return
    mods = load_modlist(name)
    # Not read_config(): it returns {} on a read error, and writing that back
    # would wipe the rest of the server config.
    with open(SERVER_CONFIG, encoding="utf-8") as f:
        cfg = json.load(f)
    cfg.setdefault("game", {})["mods"] = mods
    write_config(cfg)

def _modlists_response(**extra):
    return jsonify({"ok": True, "lists": list_modlists(), "selected": get_selected_modlist(), **extra})

@app.route("/api/modlists")
def api_modlists():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    ensure_modlists()
    return _modlists_response()

@app.route("/api/modlists/get")
def api_modlists_get():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    name = _find_modlist(request.args.get("name", ""))
    if not name:
        return jsonify({"ok": False, "error": "Mod list not found"})
    try:
        with open(_modlist_path(name), encoding="utf-8") as f:
            return jsonify({"ok": True, "name": name, "text": f.read()})
    except OSError as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/modlists/save", methods=["POST"])
def api_modlists_save():
    """Body: {name, text, create}. create=true makes a new list (and selects
    it); otherwise an existing list is overwritten."""
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    create = bool(data.get("create"))
    if not _valid_modlist_name(name):
        return jsonify({"ok": False, "error": "Name must be 1-64 characters: letters, numbers, spaces and _ . ( ) -"})
    mods, error = parse_modlist(str(data.get("text", "")))
    if error:
        return jsonify({"ok": False, "error": error})
    with _MODLIST_LOCK:
        existing = _find_modlist(name)
        if create and existing:
            return jsonify({"ok": False, "error": f"A mod list named '{existing}' already exists"})
        if not create and not existing:
            return jsonify({"ok": False, "error": "Mod list not found"})
        name = existing or name
        try:
            save_modlist(name, mods)
            if create:
                set_selected_modlist(name)
        except OSError as e:
            return jsonify({"ok": False, "error": str(e)})
    affects_server = get_selected_modlist() == name and get_server_pid() is not None
    return _modlists_response(name=name, count=len(mods), restart_required=affects_server)

@app.route("/api/modlists/select", methods=["POST"])
def api_modlists_select():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    name = _find_modlist(str((request.get_json(silent=True) or {}).get("name", "")))
    if not name:
        return jsonify({"ok": False, "error": "Mod list not found"})
    try:
        set_selected_modlist(name)
    except OSError as e:
        return jsonify({"ok": False, "error": str(e)})
    return _modlists_response(restart_required=get_server_pid() is not None)

@app.route("/api/modlists/delete", methods=["POST"])
def api_modlists_delete():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    with _MODLIST_LOCK:
        name = _find_modlist(str((request.get_json(silent=True) or {}).get("name", "")))
        if not name:
            return jsonify({"ok": False, "error": "Mod list not found"})
        was_selected = get_selected_modlist() == name
        try:
            os.remove(_modlist_path(name))
            remaining = list_modlists()
            if was_selected:
                set_selected_modlist(remaining[0] if remaining else None)
        except OSError as e:
            return jsonify({"ok": False, "error": str(e)})
    return _modlists_response(restart_required=was_selected and get_server_pid() is not None)

@app.route("/api/start", methods=["POST"])
def api_start():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    if _LIFECYCLE["action"]:
        return jsonify({"ok": False, "error": f"A {_LIFECYCLE['action']} is already in progress"})
    if get_server_pid():
        return jsonify({"ok": False, "error": "Server is already running"})
    try:
        launch_server()
        time.sleep(1)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

# ─── STOP / RESTART ──────────────────────────────────────────────────────────
#
# These can take minutes (the server writes its save before exiting), so they
# run in a background thread; /api/status reports progress under "lifecycle".
#   stop          ask the server to save and exit
#   hard-reset    kill the server without saving, delete the world and player
#                 saves, and start it again on a fresh world
#   soft-restart  ask the server to save and exit, then start it again; the
#                 launch always passes -loadSessionSave, so it resumes from
#                 that save

_LIFECYCLE_LOCK = threading.Lock()
_LIFECYCLE = {"action": None, "phase": None, "last": None}

def _wait_for_exit(proc, what):
    try:
        proc.wait(SHUTDOWN_TIMEOUT)
    except psutil.TimeoutExpired:
        raise RuntimeError(f"Server did not {what} within {SHUTDOWN_TIMEOUT}s and was left running")

def _run_lifecycle(action, proc):
    error = None
    removed = None
    try:
        try:
            if proc is not None and action == "hard-reset":
                _LIFECYCLE["phase"] = "stopping"
                proc.terminate()  # SIGTERM on Linux, an immediate kill on Windows
                try:
                    proc.wait(SHUTDOWN_TIMEOUT)
                except psutil.TimeoutExpired:
                    proc.kill()
                    proc.wait(10)
            elif proc is not None:
                _LIFECYCLE["phase"] = "saving"
                request_shutdown(proc)
                _wait_for_exit(proc, "save and exit")
        except psutil.NoSuchProcess:
            pass  # it exited on its own in the meantime
        if action == "hard-reset":
            # Without this the relaunch (-loadSessionSave) would just resume
            # from the last autosave, making it no different from a soft restart.
            _LIFECYCLE["phase"] = "flushing"
            removed = _flush_saves()
        if action != "stop":
            _LIFECYCLE["phase"] = "starting"
            launch_server()
            time.sleep(1)  # let the new process show up before reporting done
    except Exception as e:
        error = str(e)
    _LIFECYCLE["last"] = {"action": action, "ok": error is None, "error": error,
                          "removed": removed, "ts": int(time.time())}
    _LIFECYCLE["phase"] = None
    _LIFECYCLE["action"] = None

def _begin_lifecycle(action, require_running):
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    proc = get_server_process()
    if require_running and proc is None:
        return jsonify({"ok": False, "error": "Server is not running"})
    with _LIFECYCLE_LOCK:
        if _LIFECYCLE["action"]:
            return jsonify({"ok": False, "error": f"A {_LIFECYCLE['action']} is already in progress"})
        _LIFECYCLE["action"] = action
        _LIFECYCLE["phase"] = None
    threading.Thread(target=_run_lifecycle, args=(action, proc), daemon=True).start()
    return jsonify({"ok": True, "pending": True, "persistence": _persistence_enabled()})

@app.route("/api/stop", methods=["POST"])
def api_stop():
    return _begin_lifecycle("stop", require_running=True)

@app.route("/api/hard-reset", methods=["POST"])
def api_hard_reset():
    return _begin_lifecycle("hard-reset", require_running=False)

@app.route("/api/soft-restart", methods=["POST"])
def api_soft_restart():
    return _begin_lifecycle("soft-restart", require_running=True)

if __name__ == "__main__":
    app.run(host=PANEL_HOST, port=PANEL_PORT, threaded=True)
