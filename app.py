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
import calendar
import contextvars
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
import hashlib
import shutil

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
# How often (ms) the server logs its stats line, which carries the FPS.
LOG_STATS_INTERVAL_MS = 1000
# Seconds to wait for the server to save and exit on stop / soft restart.
SHUTDOWN_TIMEOUT = int(_cfg.get("SHUTDOWN_TIMEOUT", 180))
# Every running server gets a soft restart at this time each day ("HH:MM", in
# DAILY_RESTART_TZ). Blank or "off" turns it off.
DAILY_RESTART_TIME = _cfg.get("DAILY_RESTART_TIME", "04:00").strip()
DAILY_RESTART_TZ   = _cfg.get("DAILY_RESTART_TZ", "Europe/Copenhagen").strip() or "Europe/Copenhagen"
# Small helper that delivers Ctrl+C to the server's console on Windows.
_CTRL_C_HELPER = os.path.join(_BASE_DIR, "win_ctrl_c.py")

# ─── SERVERS ──────────────────────────────────────────────────────────────────
#
# The panel runs two server instances from the same installation. Server 2
# has its own config file (config2.json next to config.json, or
# SERVER2_CONFIG) and its own profile folder (SERVER2_PROFILE), passed as
# -profile: per Bohemia's Startup Parameters page, -profile X keeps the
# profile (saves, the stats file) in X/profile and logs in X/logs. Its mods
# are its own too: it gets -addonDownloadDir X as well (downloads go to
# <that folder>/addons), so it downloads into X/addons and never touches
# server 1's addons folder (WORKSHOP_DIR).
# Running servers are told apart by the -config path on their command line,
# and logs by the -config path on their CLI Params line (which also keeps
# them apart if both ever share a logs folder).
# Each request names its server in an X-Server header (the pages add it), and
# srv() returns that server; the monitor and lifecycle threads set it too.

SERVER2_CONFIG = _cfg.get("SERVER2_CONFIG", os.path.join(os.path.dirname(SERVER_CONFIG), "config2.json"))
# Server 1's profile root is the folder holding its "profile" and "logs"
# folders (e.g. Documents\My Games\ArmaReforger); server 2's sits next to it.
_PROFILE_ROOT_1 = os.path.dirname(PROFILE_DIR.rstrip("/\\"))
SERVER2_PROFILE = _cfg.get("SERVER2_PROFILE", "").strip() or \
    os.path.join(os.path.dirname(_PROFILE_ROOT_1), os.path.basename(_PROFILE_ROOT_1) + "-Server2")
# -addonDownloadDir X downloads into X/addons. Server 2's X is its profile
# folder unless SERVER2_ADDON_DOWNLOAD_DIR says otherwise.
SERVER2_ADDON_DOWNLOAD_DIR = _cfg.get("SERVER2_ADDON_DOWNLOAD_DIR", "").strip() or SERVER2_PROFILE
_WORKSHOP_PARENT = os.path.dirname(WORKSHOP_DIR.rstrip("/\\"))
if os.path.normcase(os.path.abspath(SERVER2_ADDON_DOWNLOAD_DIR.rstrip("/\\"))) == \
        os.path.normcase(os.path.abspath(_WORKSHOP_PARENT)) and \
        os.path.basename(WORKSHOP_DIR.rstrip("/\\")).lower() == "addons":
    print("[panel] WARNING: SERVER2_ADDON_DOWNLOAD_DIR points at server 1's mods folder, so both servers "
          "share their mods. Remove it from config.env to give server 2 its own.", flush=True)

class Server:
    def __init__(self, num, config, profile_root=None, addon_download_dir=None):
        self.num = num
        self.label = f"Server {num}"
        self.config = config
        # With a profile root of its own the server gets -profile, and its
        # profile and logs folders live inside that root.
        self.profile_root = profile_root
        self.profile_dir = os.path.join(profile_root, "profile") if profile_root else PROFILE_DIR
        self.log_dir = os.path.join(profile_root, "logs") if profile_root else LOG_DIR
        self.extra_args = ["-profile", profile_root] if profile_root else []
        # Where its workshop mods are: the default for server 1 (WORKSHOP_DIR),
        # <addon_download_dir>/addons for a server started with -addonDownloadDir.
        self.addons_dir = os.path.join(addon_download_dir, "addons") if addon_download_dir else WORKSHOP_DIR
        if addon_download_dir:
            self.extra_args += ["-addonDownloadDir", addon_download_dir]
        # Its psutil.Process is kept between calls: cpu_percent() measures
        # usage since the previous call on the same object.
        self.proc = None
        # When the panel last launched it and why, so the monitor can tell
        # panel starts from ones that happened outside it.
        self.last_launch = {"ts": 0.0, "action": None}
        self.lifecycle = {"action": None, "phase": None, "last": None}
        self.lifecycle_lock = threading.Lock()
        # Log follower state (persisted). midnight: epoch of 00:00 on the day
        # the log began; days: midnights passed since; last_sod: last line's
        # second-of-day.
        # joined: the log's rplIdentity -> {name, id}; present: the players on
        # the server as the timeline knows them, identityId -> {name}.
        self.mon = {"path": None, "offset": 0, "midnight": 0.0, "days": 0, "last_sod": 0.0,
                    "joined": {}, "present": {}}
        # seen_in_stats: present players the stats file has listed since they
        # joined; missing: how many snapshots in a row each has been absent
        # from; left_at: when players last left (see _sync_stats_players).
        self.mon_rt = {"pid": None, "fps": None, "fps_at": None, "seeded": False,
                       "seen_in_stats": set(), "missing": {}, "left_at": {}}
        self.monitor_state_file = os.path.join(
            _BASE_DIR, ".monitor-state.json" if num == 1 else f".monitor-state-{num}.json")

SERVERS = {1: Server(1, SERVER_CONFIG), 2: Server(2, SERVER2_CONFIG, SERVER2_PROFILE, SERVER2_ADDON_DOWNLOAD_DIR)}
_current_server = contextvars.ContextVar("current_server", default=SERVERS[1])

def srv():
    """The server the current request, monitor step or lifecycle run is about."""
    return _current_server.get()

def other_server(server=None):
    return SERVERS[2 if (server or srv()).num == 1 else 1]

def build_server_args(load_save=True):
    """Build the launch arguments. `-loadSessionSave` is passed on every launch
    except a hard restart: with no save files it's a no-op, and including it
    keeps panel-launched and systemd-launched starts behaving the same way.
    The 'enabled' toggle in the UI controls only the `persistence` block in
    config.json (autosave). `-logStats` makes the server log its FPS every
    second; the panel's FPS graph reads it from console.log."""
    args = ["-config", srv().config] + srv().extra_args
    if load_save:
        args.append("-loadSessionSave")
    if MAX_FPS:
        args.append(f"-maxFPS={MAX_FPS}")
    args += ["-logStats", str(LOG_STATS_INTERVAL_MS)]
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
def _scan_cache_file():
    # Each server has its own mods, so its own list of scenarios found in them.
    n = srv().num
    return os.path.join(_BASE_DIR, ".scenario-cache.json" if n == 1 else f".scenario-cache-{n}.json")


# Bumped when the scan finds things differently, so old caches are redone.
_SCAN_CACHE_VERSION = 3

def _scan_cache_load():
    try:
        with open(_scan_cache_file(), encoding="utf-8") as f:
            data = json.load(f)
        if data.get("version") != _SCAN_CACHE_VERSION:
            return {}, {}
        return data.get("mods", {}), data.get("mtimes", {})
    except (OSError, json.JSONDecodeError):
        return {}, {}


def _scan_cache_save(mods, mtimes):
    try:
        with open(_scan_cache_file(), "w", encoding="utf-8") as f:
            json.dump({"version": _SCAN_CACHE_VERSION, "mods": mods, "mtimes": mtimes, "saved_at": time.time()}, f)
    except OSError as e:
        print(f"[panel] WARNING: could not write scenario cache: {e}", flush=True)


_SCAN_LOCK = threading.Lock()
_LAST_SCAN_RESULTS = {}  # server num -> {"scenarios", "diag", "ts"}


def _candidate_addon_roots():
    """Locations to scan for the current server's addons. Each entry is (path,
    is_vanilla). `is_vanilla=True` means anything found there is
    Bohemia-shipped game content (the dedicated server's bundled addons), not
    a workshop mod. Server 2 downloads into its own folder, so only that one
    is scanned for its workshop mods; server 1 also tries the usual default
    locations."""
    home = os.path.dirname(SERVER_DIR.rstrip("/")) if SERVER_DIR else os.path.expanduser("~")
    if not home or home == "/":
        home = os.path.expanduser("~arma") if os.path.isdir("/home/arma") else os.path.expanduser("~")

    roots = []
    # Workshop mod dirs (downloaded via SteamCMD / the game)
    if srv().addons_dir:
        roots.append((srv().addons_dir, False))
    if srv().num == 1:
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
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel = os.path.relpath(dirpath, root)
        depth = 0 if rel == "." else rel.count(os.sep) + 1
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


# Scenario paths are .conf files in the addon's Missions folder, or in a
# map's (Worlds/MyMap/Missions/Conflict.conf); a Missions folder elsewhere
# (e.g. Configs/Missions/Tasks) holds other configs. Names may
# contain spaces and other characters (e.g. "Missions/ARCL Arland.conf"), so
# a path is taken to run from the control byte before "Missions/" to the
# null after it; the record check confirms it is a whole path. (A plain
# search rather than a regex, which backtracks badly on long text runs.)
_RDB_CTRL_RE = re.compile(rb'[\x00-\x1f]')

def _rdb_mission_paths(data):
    """(start, end) of each candidate scenario path in an .rdb's bytes."""
    pos, last_start = 0, -1
    while True:
        i = data.find(b"Missions/", pos)
        if i < 0:
            return
        pos = i + 1
        end = data.find(b"\x00", i)
        if end < 0:
            return
        start, floor = i, max(0, i - 1024)  # no real path is that long
        while start > floor and data[start - 1] >= 0x20:
            start -= 1
        if start == floor and start > 0 and data[start - 1] >= 0x20:
            continue
        if start == last_start:
            continue  # a second "Missions/" in the same path
        last_start = start
        path = data[start:end]
        if not (path.startswith(b"Missions/") or (path.startswith(b"Worlds/") and b"/Missions/" in path)):
            continue
        if path.lower().endswith(b".conf") and not _RDB_CTRL_RE.search(data, i, end):
            yield start, end

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
    for ps, pe in _rdb_mission_paths(data):
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
        path_str = data[ps:pe].decode("utf-8", errors="replace")
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
            # 2. Add what the .rdb lists: the meta may have no scenarios
            #    (the dedicated server's downloader often strips them), only
            #    some of them (e.g. an older version's), or not exist at all
            #    (Bohemia's bundled vanilla addons).
            if rdb_path:
                if not mod_name:
                    mod_name = _addon_name_from_gproj(addon_dir) or os.path.basename(addon_dir)
                source = "vanilla" if is_vanilla else mod_name
                known = {x["id"].upper() for x in scenarios}
                scenarios += [x for x in _scenarios_from_rdb(rdb_path, source) if x["id"].upper() not in known]
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
        last = _LAST_SCAN_RESULTS.get(srv().num) or {}
        return last.get("scenarios", []), (last.get("diag") or {"busy": True})
    try:
        scenarios, diag = _discover_locked(force_rescan)
        _LAST_SCAN_RESULTS[srv().num] = {"scenarios": scenarios, "diag": diag, "ts": time.time()}
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


# Mods change on disk without the panel doing anything (the server downloads
# them when it starts), so a background thread keeps each server's scenario
# list current: every _SCENARIO_WATCH_EVERY seconds it checks the server's
# mods folders (each mod's meta and resourceDatabase.rdb modification times)
# and rescans when something changed, and once when the panel starts. The
# rescan only re-reads the mods that changed.

_SCENARIO_WATCH_EVERY = 30
_scenario_watch_fp = {}  # server num -> mods folder fingerprint at the last scan

def _addons_fingerprint():
    fp = []
    for root, is_vanilla in _candidate_addon_roots():
        if is_vanilla:
            continue
        try:
            names = sorted(os.listdir(root))
        except OSError:
            continue
        for name in names:
            for fn in ("meta", "resourceDatabase.rdb"):
                try:
                    st = os.stat(os.path.join(root, name, fn))
                    fp.append((root, name, fn, st.st_mtime, st.st_size))
                except OSError:
                    pass
    return hash(tuple(fp))

def refresh_scenarios():
    """Rescan the current server's mods, re-reading only those that changed."""
    with _SCAN_LOCK:
        scenarios, diag = _discover_locked(False)
        _LAST_SCAN_RESULTS[srv().num] = {"scenarios": scenarios, "diag": diag, "ts": time.time()}
    return scenarios, diag

def _scenario_watch_loop():
    while True:
        for server in SERVERS.values():
            _current_server.set(server)
            try:
                fp = _addons_fingerprint()
                if _scenario_watch_fp.get(server.num) == fp:
                    continue
                before = {x["id"] for x in cached_scenarios()}
                scenarios, _diag = refresh_scenarios()
                _scenario_watch_fp[server.num] = fp
                after = {x["id"] for x in scenarios}
                if after != before:
                    print(f"[panel] {server.label}: scenarios from mods now {len(after)} "
                          f"({len(after - before)} new, {len(before - after)} gone)", flush=True)
            except Exception as e:
                print(f"[panel] scenario scan for {server.label} failed: {e}", flush=True)
        time.sleep(_SCENARIO_WATCH_EVERY)


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

def _is_server_process(p):
    # Linux truncates process names to 15 chars, so also look at argv[0].
    if (p.info.get("name") or "").startswith("ArmaReforgerSer"):
        return True
    cmd = p.info.get("cmdline") or []
    return bool(cmd) and os.path.basename(cmd[0]).startswith("ArmaReforgerServer")

def _config_arg(cmdline):
    """The -config path in a command line, or None."""
    for i, a in enumerate(cmdline):
        if a.lower() == "-config" and i + 1 < len(cmdline):
            return cmdline[i + 1]
        if a.lower().startswith("-config="):
            return a.split("=", 1)[1]
    return None

def _is_config_of(path, server):
    """Whether a -config path (from a command line or a log) is `server`'s."""
    if not path:
        return server.num == 1  # started without -config: count it as server 1
    path = path.strip().strip('"')
    if os.path.isabs(path):
        return os.path.normcase(os.path.normpath(path)) == os.path.normcase(os.path.normpath(server.config))
    return os.path.basename(path).lower() == os.path.basename(server.config).lower()

def get_server_process(server=None):
    s = server or srv()
    p = s.proc
    if p is not None:
        try:
            if p.is_running() and p.status() != psutil.STATUS_ZOMBIE:
                return p
        except psutil.Error:
            pass
        s.proc = None
    for p in psutil.process_iter(["name", "cmdline"]):
        try:
            if (_is_server_process(p) and p.status() != psutil.STATUS_ZOMBIE
                    and _is_config_of(_config_arg(p.info.get("cmdline") or []), s)):
                s.proc = p
                return p
        except psutil.Error:
            continue
    return None

def get_server_pid(server=None):
    p = get_server_process(server)
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

def _config_ports(cfg):
    ports = {cfg.get("bindPort") or 2001, cfg.get("publicPort"),
             (cfg.get("a2s") or {}).get("port"), (cfg.get("rcon") or {}).get("port")}
    return {p for p in ports if isinstance(p, int) and p > 0}

def _check_can_launch():
    s, other = srv(), other_server()
    if not os.path.exists(s.config):
        raise RuntimeError(f"{os.path.basename(s.config)} doesn't exist yet. Create it on the Config file page.")
    if get_server_process(other) is not None:
        clash = _config_ports(read_config()) & _config_ports(read_config(other))
        if clash:
            raise RuntimeError(
                f"{s.label} would use port{'s' if len(clash) > 1 else ''} {', '.join(map(str, sorted(clash)))}, which {other.label} "
                f"(running) also uses. Give {os.path.basename(s.config)} its own ports.")

def launch_server(load_save=True):
    _check_can_launch()
    apply_selected_modlist()
    srv().last_launch.update(ts=time.time(), action=srv().lifecycle["action"] or "start")
    args = [SERVER_BINARY] + build_server_args(load_save)
    if IS_WINDOWS:
        # Give the server its own console, as if started by hand, so the panel
        # can later send it Ctrl+C for a clean save-and-exit.
        subprocess.Popen(args, cwd=SERVER_DIR, creationflags=subprocess.CREATE_NEW_CONSOLE)
    else:
        subprocess.Popen(args, cwd=SERVER_DIR,
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

_log_config_cache = {}  # log folder -> the -config path its console.log records

def _log_config(folder):
    """The -config path a log was started with ("" for none), or None while
    its CLI Params line hasn't been written yet."""
    if folder in _log_config_cache:
        return _log_config_cache[folder]
    try:
        with open(os.path.join(folder, "console.log"), encoding="utf-8", errors="replace") as f:
            head = f.read(65536)
    except OSError:
        return None
    m = re.search(r"CLI Params:(.*)", head)
    if not m:
        return None
    a = re.search(r"-config\s+(.+?)(?=\s+-[A-Za-z]|\s*$)", m.group(1).strip())
    _log_config_cache[folder] = a.group(1) if a else ""
    return _log_config_cache[folder]

def get_latest_log(server=None):
    """The newest console.log written by `server` (logs of both servers share
    a folder; each log names its config file on its CLI Params line)."""
    s = server or srv()
    try:
        dirs = sorted(glob.glob(os.path.join(s.log_dir, "logs_*")), reverse=True)
    except Exception:
        return None
    for d in dirs[:30]:
        path = os.path.join(d, "console.log")
        cfg = _log_config(d) if os.path.exists(path) else None
        if cfg is not None and _is_config_of(cfg, s):
            return path
    return None

def read_config(server=None):
    try:
        with open((server or srv()).config, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def write_config(cfg):
    with open(srv().config, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent="\t")

def read_config_strict(server=None):
    """Like read_config(), but raises instead of returning {} on a missing or
    broken file, for callers that write the result back."""
    with open((server or srv()).config, encoding="utf-8") as f:
        return json.load(f)

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
        p = os.path.join(srv().profile_dir, sub)
        if os.path.isdir(p):
            return p
    return os.path.join(srv().profile_dir, ".save")  # canonical Linux dedicated path

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

def _scenario_save_folders(scenario_id):
    """The folders in `.save/game/` that hold sessions of `scenario_id`. The
    server names them after the scenario's GUID and file name, e.g.
    {424AE7D5DFD33E8B}Missions/PvE_Kolgujev_Fixed_WCS_loadout.conf ->
    424AE7D5DFD33E8B-PvE-Kolgujev-Fixed-WCS-loadout; matching on the GUID
    prefix avoids depending on exactly how the name part is rewritten."""
    m = re.match(r"\{([0-9A-Fa-f]{16})\}", scenario_id or "")
    game_dir = os.path.join(_save_root(), "game")
    if not m or not os.path.isdir(game_dir):
        return []
    guid = m.group(1).upper()
    return sorted(name for name in os.listdir(game_dir)
                  if os.path.isdir(os.path.join(game_dir, name))
                  and (name.upper() == guid or name.upper().startswith(guid + "-")))

def _archive_scenario_save(scenario_id):
    """Move the session save of `scenario_id` (its folder(s) in `.save/game/`)
    into `PROFILE_DIR/save-archive/<timestamp>/game/`, so the next launch
    finds no session for it and starts a fresh world. Other scenarios' saves,
    player saves and settings stay where they are, and nothing is deleted;
    moving the folder back restores that world. Returns (files moved, archive
    path or None if there was nothing to move, folder names moved). Raises if
    a file can't be moved, so a half-moved save is never launched."""
    folders = _scenario_save_folders(scenario_id)
    if not folders:
        return 0, None, []
    archive = os.path.join(srv().profile_dir, "save-archive", time.strftime("%Y-%m-%d_%H-%M-%S"))
    while os.path.exists(archive):
        archive += "_"
    os.makedirs(os.path.join(archive, "game"))
    moved = 0
    for name in folders:
        src = os.path.join(_save_root(), "game", name)
        moved += sum(len(files) for _dp, _dn, files in os.walk(src))
        shutil.move(src, os.path.join(archive, "game", name))
    return moved, archive, folders


def get_map_name(cfg=None):
    try:
        if cfg is None:
            cfg = read_config()
        sid = cfg.get("game", {}).get("scenarioId", "")
        if not sid:
            return "Unknown"
        # Consult the full merged list (vanilla + discovered, with overrides
        # already applied) so the dashboard tile matches the dropdown.
        for m in all_scenarios_cached():
            if m["id"] == sid:
                return m["name"]
        return sid.split("/")[-1].replace(".conf", "")
    except Exception:
        return "Unknown"

# Server and gameplay settings edited from the panel. Each entry: request key ->
# (label, section ("game" or "gameProperties"), config.json key, type,
#  (min, max) for numbers, value the server uses when the key is absent).
_GAME_SETTINGS = {
    "max_players":               ("Max players",                "game",           "maxPlayers",                 int,  (1, 128),     64),
    "server_max_view_distance":  ("Server max view distance",   "gameProperties", "serverMaxViewDistance",      int,  (500, 12000), 1600),
    "network_view_distance":     ("Network view distance",      "gameProperties", "networkViewDistance",        int,  (500, 5000),  1500),
    "server_min_grass_distance": ("Server min grass distance",  "gameProperties", "serverMinGrassDistance",     int,  (50, 150),    50),
    "disable_third_person":      ("Disable third person",       "gameProperties", "disableThirdPerson",         bool, None,         False),
    "von_cross_faction":         ("Cross-faction voice (VON)",  "gameProperties", "VONCanTransmitCrossFaction", bool, None,         False),
}

def _settings_section(cfg, section):
    game = cfg.setdefault("game", {})
    return game if section == "game" else game.setdefault("gameProperties", {})

def get_game_settings(cfg):
    return {k: _settings_section(cfg, section).get(key, default)
            for k, (_label, section, key, _type, _range, default) in _GAME_SETTINGS.items()}

def apply_game_settings(cfg, data):
    """Copy the settings present in `data` into cfg. Returns (changed, error)."""
    changed = False
    for k, (label, section, key, typ, bounds, _default) in _GAME_SETTINGS.items():
        if k not in data:
            continue
        value = data[k]
        if typ is bool:
            if not isinstance(value, bool):
                return changed, f"{label} must be true or false"
        else:
            try:
                if isinstance(value, bool):
                    raise ValueError
                value = int(value)
            except (TypeError, ValueError):
                return changed, f"{label} must be a whole number"
            lo, hi = bounds
            if not lo <= value <= hi:
                return changed, f"{label} must be between {lo} and {hi}"
        _settings_section(cfg, section)[key] = value
        changed = True
    return changed, None

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

@app.before_request
def _select_server():
    n = request.headers.get("X-Server") or request.args.get("server") or "1"
    _current_server.set(SERVERS.get(int(n) if n.isdigit() else 1, SERVERS[1]))

@app.route("/mods")
def mods_page():
    if not session.get("logged_in"):
        return redirect("/login")
    _ensure_csrf()
    with open(os.path.join(_BASE_DIR, "mods.html"), encoding="utf-8") as f:
        return f.read()

@app.route("/config")
def config_page():
    if not session.get("logged_in"):
        return redirect("/login")
    _ensure_csrf()
    with open(os.path.join(_BASE_DIR, "config.html"), encoding="utf-8") as f:
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
        "server":         srv().num,
        "servers":        [{"num": x.num, "label": x.label, "config": x.config,
                            "profile": x.profile_root or os.path.dirname(x.profile_dir),
                            "config_exists": os.path.exists(x.config),
                            "running": get_server_pid(x) is not None} for x in SERVERS.values()],
        "running":        pid is not None,
        "pid":            pid,
        "lifecycle":      dict(srv().lifecycle),
        "daily_restart":  daily_restart_info(),
        "map":            get_map_name(cfg),
        "players":        len(srv().mon["present"]) if pid is not None else 0,
        "max_players":    cfg.get("game", {}).get("maxPlayers"),
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
        "settings":       get_game_settings(cfg),
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
    try:
        _scenario_watch_fp[srv().num] = _addons_fingerprint()
    except Exception:
        pass
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
        "fps": current_fps(),
        "net_up": _net["up"], "net_down": _net["down"],
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
        return jsonify({"lines": recent_log_lines(path, n), "path": path})
    except Exception as e:
        return jsonify({"lines": [], "error": str(e)})

# The live log leaves out the FPS line the server writes every second
# (-logStats; the FPS graph reads it). So that a quiet server, whose log is
# mostly FPS lines, still shows its last real lines without re-reading the log
# on every poll, the other lines of each log are kept here and only what was
# added since the last poll is read.
_LIVE_LOG_SEED_BYTES = 4 * 1024 * 1024  # how far back a log is read the first time
_live_log = {}  # path -> {"offset", "partial", "lines"}
_live_log_lock = threading.Lock()

# Other lines the server writes every second because of -logStats, e.g.
#   19:28:05.564 WORLD        : UpdateEntities
#   19:28:05.575  WORLD        : Frame
_LIVE_LOG_HIDE_RE = re.compile(r"^\d{2}:\d{2}:\d{2}\.\d{3}\s+WORLD\s*:\s*(?:UpdateEntities|Frame)\s*$")

def _live_log_keep(line):
    return not (_FPS_RE.search(line) or _LIVE_LOG_HIDE_RE.match(line))

def recent_log_lines(path, n):
    """The last `n` lines of the log at `path`, without the FPS lines."""
    from collections import deque
    with _live_log_lock:
        size = os.path.getsize(path)
        st = _live_log.get(path)
        if st is None or size < st["offset"]:  # new, or rewritten from the start
            if len(_live_log) > 8:
                _live_log.clear()
            start = max(0, size - _LIVE_LOG_SEED_BYTES)
            st = _live_log[path] = {"offset": start, "partial": b"", "lines": deque(maxlen=5000),
                                    "skip_first": start > 0}
        if size > st["offset"]:
            with open(path, "rb") as f:
                f.seek(st["offset"])
                data = st["partial"] + f.read(size - st["offset"])
            st["offset"] = size
            # A line still being written is kept back until it is complete.
            complete, sep, st["partial"] = data.rpartition(b"\n")
            raw = complete.split(b"\n") if sep else []
            if raw and st.pop("skip_first", False):
                raw = raw[1:]  # began mid-line
            st["lines"].extend(l for l in (r.decode("utf-8", errors="replace").rstrip("\r") for r in raw)
                               if _live_log_keep(l))
        return list(st["lines"])[-n:]

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
        # The scenario already in config.json stays allowed even when no
        # installed mod lists it (e.g. typed into the file by hand).
        valid_ids.add(cfg.get("game", {}).get("scenarioId", ""))
        if sid not in valid_ids:
            return jsonify({"ok": False, "error": "Unknown scenario"})
        cfg.setdefault("game", {})["scenarioId"] = sid; changed = True
    if "password" in data:
        cfg.setdefault("game", {})["password"] = data["password"]; changed = True
    if "password_admin" in data and data["password_admin"].strip():
        cfg.setdefault("game", {})["passwordAdmin"] = data["password_admin"].strip(); changed = True
    settings_changed, error = apply_game_settings(cfg, data)
    if error:
        return jsonify({"ok": False, "error": error})
    changed = changed or settings_changed
    if not changed:
        return jsonify({"ok": False, "error": "No changes"})
    try:
        write_config(cfg)
        return jsonify({"ok": True, "restart_required": get_server_pid() is not None})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

# ─── RAW CONFIG EDITOR ───────────────────────────────────────────────────────
#
# The /config page edits config.json as JSON, except game.mods: the mod list
# is managed in Mod Lists and rewritten at every launch, so it is left out of
# the editor and put back in its old place on save. A version hash of the
# rest of the file stops a save from overwriting changes made in the meantime
# (by the panel's other cards or by hand).

def _config_without_mods(cfg):
    cfg = json.loads(json.dumps(cfg))  # deep copy
    if isinstance(cfg.get("game"), dict):
        cfg["game"].pop("mods", None)
    return cfg

def _config_version(cfg):
    data = json.dumps(_config_without_mods(cfg), sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()[:16]

def _insert_mods(new_game, old_game, mods):
    """new_game with "mods" added back where it sat in old_game: after the key
    that preceded it, if that key still exists, else at the end."""
    old_keys = list(old_game)
    items = list(new_game.items())
    pos = len(items)
    if "mods" in old_keys:
        i = old_keys.index("mods")
        if i == 0:
            pos = 0
        elif old_keys[i - 1] in new_game:
            pos = list(new_game).index(old_keys[i - 1]) + 1
    items.insert(pos, ("mods", mods))
    return dict(items)

@app.route("/api/config-file")
def api_config_file_get():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    if not os.path.exists(srv().config):
        # A new server: offer the other server's config as a starting point.
        try:
            text = json.dumps(_config_without_mods(read_config_strict(other_server())), indent="\t", ensure_ascii=False)
        except (OSError, ValueError):
            text = "{\n\t\"game\": {}\n}"
        return jsonify({"ok": True, "text": text, "version": None, "path": srv().config,
                        "warning": f"{os.path.basename(srv().config)} doesn't exist yet. Below is "
                                   f"{other_server().label}'s config as a starting point: give it its own "
                                   f"name and ports (bindPort, publicPort, a2s, rcon), then Save to create it."})
    try:
        cfg = read_config_strict()
    except (OSError, ValueError) as e:
        # Show the raw text so a broken file can be repaired from here.
        try:
            with open(srv().config, encoding="utf-8") as f:
                raw = f.read()
        except OSError:
            raw = ""
        return jsonify({"ok": True, "text": raw, "version": None, "path": srv().config,
                        "warning": f"config.json can't be read as JSON ({e}); it is shown as-is."})
    return jsonify({"ok": True, "path": srv().config, "version": _config_version(cfg),
                    "text": json.dumps(_config_without_mods(cfg), indent="\t", ensure_ascii=False)})

@app.route("/api/config-file", methods=["POST"])
def api_config_file_save():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    data = request.get_json(silent=True) or {}
    try:
        new = json.loads(str(data.get("text", "")))
    except json.JSONDecodeError as e:
        return jsonify({"ok": False, "error": f"Invalid JSON: {e.msg} at line {e.lineno} col {e.colno}"})
    if not isinstance(new, dict):
        return jsonify({"ok": False, "error": "config.json must be a JSON object: { ... }"})
    if not isinstance(new.get("game"), dict):
        return jsonify({"ok": False, "error": 'config.json needs a "game" object'})
    if "mods" in new["game"]:
        return jsonify({"ok": False, "error": 'Remove "mods" from "game": mods are managed in Mod Lists'})
    try:
        current = read_config_strict()
    except (OSError, ValueError):
        current = None  # missing or broken: nothing to merge or compare with
    if current is not None and data.get("version") != _config_version(current):
        return jsonify({"ok": False, "conflict": True,
                        "error": "config.json was changed since you opened it. Reload to see the "
                                 "current file (copy your edits first if you want to keep them)."})
    old_game = (current or {}).get("game") if isinstance((current or {}).get("game"), dict) else {}
    # With no readable old file, mods start empty; the selected mod list is
    # written in at the next launch anyway.
    new["game"] = _insert_mods(new["game"], old_game, old_game.get("mods", []))
    try:
        if os.path.exists(srv().config):
            shutil.copy2(srv().config, srv().config + ".bak")
        write_config(new)
    except OSError as e:
        return jsonify({"ok": False, "error": str(e)})
    return jsonify({"ok": True, "version": _config_version(new),
                    "restart_required": get_server_pid() is not None})

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
        "profile_dir":      srv().profile_dir,
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
    other = other_server()
    if other.profile_dir == srv().profile_dir and get_server_pid(other):
        return jsonify({"ok": False, "error": f"{other.label} is running and shares this save folder; stop it first"})
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

def _read_state():
    try:
        with open(_STATE_FILE, encoding="utf-8") as f:
            state = json.load(f)
        return state if isinstance(state, dict) else {}
    except (OSError, ValueError):
        return {}

def _selected_key(server):
    # Server 1 keeps the original key so existing installs carry over.
    return "selected_modlist" if server.num == 1 else f"selected_modlist_{server.num}"

def get_selected_modlist(server=None):
    name = _read_state().get(_selected_key(server or srv()))
    return name if isinstance(name, str) and _find_modlist(name) == name else None

_STATE_LOCK = threading.Lock()

def _update_state(key, value):
    with _STATE_LOCK:
        state = _read_state()
        state[key] = value
        with open(_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f)

def set_selected_modlist(name, server=None):
    _update_state(_selected_key(server or srv()), name)

def ensure_modlists():
    """First run: turn the mods currently in config.json into a "default" list."""
    with _MODLIST_LOCK:
        if os.path.isdir(MODLISTS_DIR):
            return
        save_modlist("default", read_config(SERVERS[1]).get("game", {}).get("mods", []))
        set_selected_modlist("default", SERVERS[1])

def apply_selected_modlist():
    """Write the selected mod list into config.json's game.mods. Called right
    before every launch; with no list selected config.json is left alone."""
    name = get_selected_modlist()
    if not name:
        return
    mods = load_modlist(name)
    # Not read_config(): it returns {} on a read error, and writing that back
    # would wipe the rest of the server config.
    cfg = read_config_strict()
    cfg.setdefault("game", {})["mods"] = mods
    write_config(cfg)

def _modlists_response(**extra):
    return jsonify({"ok": True, "lists": list_modlists(), "selected": get_selected_modlist(),
                    "backup": modlist_backup_info(), **extra})

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

# A mod's 16-hex-digit ID, on its own or in a workshop link such as
# https://reforger.armaplatform.com/workshop/595F2BF2F44836FB-RHS-StatusQuo
_MOD_ID_IN_TEXT_RE = re.compile(r"(?<![0-9A-Za-z])([0-9A-Fa-f]{16})(?![0-9A-Za-z])")

@app.route("/api/modlists/add-mod", methods=["POST"])
def api_modlists_add_mod():
    """Body: {input}: a workshop link or a mod ID. Adds the mod, named as on
    its workshop page, to the mod list selected for this server."""
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    text = str((request.get_json(silent=True) or {}).get("input", "")).strip()
    ids = list(dict.fromkeys(g.upper() for g in _MOD_ID_IN_TEXT_RE.findall(text)))
    if not ids:
        return jsonify({"ok": False, "error": "Enter a workshop link or a 16-character mod ID, e.g. 595F2BF2F44836FB"})
    if len(ids) > 1:
        return jsonify({"ok": False, "error": "That contains more than one mod ID; add one mod at a time"})
    guid = ids[0]
    name = get_selected_modlist()
    if not name:
        return jsonify({"ok": False, "error": "No mod list is selected; create one first"})
    def existing_entry():
        return next((m for m in load_modlist(name) if str(m.get("modId", "")).upper() == guid), None)
    try:
        found = existing_entry()
    except (OSError, ValueError) as e:
        return jsonify({"ok": False, "error": str(e)})
    if found:
        return jsonify({"ok": False, "error": f"{found.get('name') or guid} is already in {name}"})
    entry = _ws_fetch(guid)  # the workshop page, for the mod's name
    if "error" in entry and entry["error"] != "no such mod on the workshop":
        time.sleep(1)
        entry = _ws_fetch(guid)  # one retry for a dropped connection
    if "error" in entry:
        return jsonify({"ok": False, "error": f"Could not get mod {guid} from the workshop: {entry['error']}"})
    mod_name = str(entry["data"].get("name") or "").strip()
    if not mod_name:
        return jsonify({"ok": False, "error": f"The workshop page of mod {guid} has no name"})
    with _MODLIST_LOCK:
        try:
            if existing_entry():  # added meanwhile
                return jsonify({"ok": False, "error": f"{mod_name} is already in {name}"})
            mods = load_modlist(name)
            mods.append({"modId": guid, "name": mod_name})
            save_modlist(name, mods)
        except (OSError, ValueError) as e:
            return jsonify({"ok": False, "error": str(e)})
    affects_server = get_server_pid() is not None
    return _modlists_response(name=name, added={"modId": guid, "name": mod_name,
                                                "version": entry["data"].get("version")},
                              count=len(mods), restart_required=affects_server)

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
            for server in SERVERS.values():
                # get_selected_modlist() ignores lists that no longer exist, so
                # read the raw state to find who had this one selected.
                if _read_state().get(_selected_key(server)) == name:
                    set_selected_modlist(remaining[0] if remaining else None, server)
        except OSError as e:
            return jsonify({"ok": False, "error": str(e)})
    return _modlists_response(restart_required=was_selected and get_server_pid() is not None)

@app.route("/api/start", methods=["POST"])
def api_start():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    if srv().lifecycle["action"]:
        return jsonify({"ok": False, "error": f"A {srv().lifecycle['action']} is already in progress"})
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
#   hard-restart  kill the server without saving, move the running scenario's
#                 session save into an archive folder and start it again on a
#                 fresh world (the server resumes a saved session even without
#                 -loadSessionSave, so the session has to be out of the way);
#                 other scenarios' saves and player saves stay put
#   soft-restart  ask the server to save and exit, then start it again; the
#                 launch always passes -loadSessionSave, so it resumes from
#                 that save (daily-soft-restart is the same, started by the
#                 daily schedule)

def _wait_for_exit(proc, what):
    try:
        proc.wait(SHUTDOWN_TIMEOUT)
    except psutil.TimeoutExpired:
        raise RuntimeError(f"Server did not {what} within {SHUTDOWN_TIMEOUT}s and was left running")

def _run_lifecycle(action, proc, server):
    _current_server.set(server)  # this runs in its own thread
    lc = server.lifecycle
    error = None
    archived = None
    try:
        try:
            if proc is not None and action == "hard-restart":
                lc["phase"] = "stopping"
                proc.terminate()  # SIGTERM on Linux, an immediate kill on Windows
                try:
                    proc.wait(SHUTDOWN_TIMEOUT)
                except psutil.TimeoutExpired:
                    proc.kill()
                    proc.wait(10)
            elif proc is not None:
                lc["phase"] = "saving"
                request_shutdown(proc)
                _wait_for_exit(proc, "save and exit")
        except psutil.NoSuchProcess:
            pass  # it exited on its own in the meantime
        if action == "hard-restart":
            # The scenario about to be launched is the one that starts fresh.
            scenario = read_config().get("game", {}).get("scenarioId", "")
            lc["phase"] = "archiving"
            count, path, folders = _archive_scenario_save(scenario)
            archived = {"count": count, "path": path, "folders": folders,
                        "scenario": scenario, "save_root": _save_root()}
        if action != "stop":
            lc["phase"] = "starting"
            launch_server(load_save=action != "hard-restart")
            time.sleep(1)  # let the new process show up before reporting done
    except Exception as e:
        error = str(e)
    lc["last"] = {"action": action, "ok": error is None, "error": error,
                          "archived": archived, "ts": int(time.time())}
    lc["phase"] = None
    lc["action"] = None

def _begin_lifecycle(action, require_running):
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    s, other = srv(), other_server()
    proc = get_server_process()
    if require_running and proc is None:
        return jsonify({"ok": False, "error": "Server is not running"})
    if action != "stop" and not os.path.exists(s.config):
        return jsonify({"ok": False, "error": f"{os.path.basename(s.config)} doesn't exist yet. Create it on the Config file page."})
    if action == "hard-restart" and other.profile_dir == s.profile_dir and get_server_pid(other):
        # Both servers keep their sessions in the same save folder.
        scenario = read_config().get("game", {}).get("scenarioId")
        if scenario and scenario == read_config(other).get("game", {}).get("scenarioId"):
            return jsonify({"ok": False, "error": f"{other.label} is running the same scenario from the same "
                                                  f"save folder; a hard restart would move its save too"})
    with s.lifecycle_lock:
        if s.lifecycle["action"]:
            label = _ACTION_LABELS.get(s.lifecycle["action"], s.lifecycle["action"]).lower()
            return jsonify({"ok": False, "error": f"A {label} is already in progress"})
        s.lifecycle["action"] = action
        s.lifecycle["phase"] = None
    threading.Thread(target=_run_lifecycle, args=(action, proc, s), daemon=True).start()
    return jsonify({"ok": True, "pending": True, "persistence": _persistence_enabled()})

@app.route("/api/stop", methods=["POST"])
def api_stop():
    return _begin_lifecycle("stop", require_running=True)

@app.route("/api/hard-restart", methods=["POST"])
def api_hard_restart():
    return _begin_lifecycle("hard-restart", require_running=False)

@app.route("/api/soft-restart", methods=["POST"])
def api_soft_restart():
    return _begin_lifecycle("soft-restart", require_running=True)

# ─── DAILY SOFT RESTART ──────────────────────────────────────────────────────
#
# At DAILY_RESTART_TIME (in DAILY_RESTART_TZ, Copenhagen time by default) the
# monitor thread soft-restarts every server that is running: save and exit,
# then start again from the save, exactly like the Soft restart button. A
# server that is stopped, or busy with another stop/restart, is left alone.
# The last restart time handled is kept in .panel-state.json, so restarting
# the panel right after 04:00 doesn't restart the servers twice; if the panel
# was down at 04:00 it still catches up within _DAILY_RESTART_GRACE seconds.

_DAILY_RESTART_GRACE = 600
_daily_restart = {"done": None}  # the scheduled moment last handled (epoch seconds)

def _parse_hhmm(text, setting, what):
    """(hour, minute) from "HH:MM", or None for blank/"off" or a bad value."""
    if not text or text.lower() in ("off", "no", "false", "0", "none"):
        return None
    m = re.fullmatch(r"(\d{1,2}):(\d{2})", text)
    if not m or int(m.group(1)) > 23 or int(m.group(2)) > 59:
        print(f"[panel] {setting}={text!r} isn't HH:MM; {what} is off", flush=True)
        return None
    return int(m.group(1)), int(m.group(2))

_DAILY_RESTART_HM = _parse_hhmm(DAILY_RESTART_TIME, "DAILY_RESTART_TIME", "the daily soft restart")

# Zones on Central European Time, which the built-in rule below covers when
# Python has no time zone database (Windows without the tzdata package).
_CET_ZONES = {"CET", "Europe/Copenhagen", "Europe/Berlin", "Europe/Oslo", "Europe/Stockholm",
              "Europe/Amsterdam", "Europe/Brussels", "Europe/Paris", "Europe/Madrid", "Europe/Rome",
              "Europe/Vienna", "Europe/Prague", "Europe/Warsaw", "Europe/Zurich", "Europe/Budapest"}

def _last_sunday_1am_utc(year, month):
    last = calendar.monthrange(year, month)[1]
    day = last - (calendar.weekday(year, month, last) + 1) % 7
    return calendar.timegm((year, month, day, 1, 0, 0))

def _cet_offset(utc_ts):
    """UTC offset in seconds of Central European Time at `utc_ts`: +1h, or
    +2h in summer (EU rule: last Sunday of March to last Sunday of October,
    switching at 01:00 UTC)."""
    year = time.gmtime(utc_ts).tm_year
    summer = _last_sunday_1am_utc(year, 3) <= utc_ts < _last_sunday_1am_utc(year, 10)
    return 7200 if summer else 3600

def _make_clock(tzname):
    """(local_date(ts) -> (y, m, d), to_ts(y, m, d, hh, mm) -> epoch) for the
    time zone `tzname`."""
    import datetime
    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(tzname)
        def local_date(ts):
            d = datetime.datetime.fromtimestamp(ts, tz)
            return d.year, d.month, d.day
        def to_ts(y, mo, d, hh, mm):
            return datetime.datetime(y, mo, d, hh, mm, tzinfo=tz).timestamp()
        return local_date, to_ts
    except Exception:
        pass
    if tzname in _CET_ZONES:
        def local_date(ts):
            t = time.gmtime(ts + _cet_offset(ts))
            return t.tm_year, t.tm_mon, t.tm_mday
        def to_ts(y, mo, d, hh, mm):
            naive = calendar.timegm((y, mo, d, hh, mm, 0))
            return naive - _cet_offset(naive - 3600)
        return local_date, to_ts
    print(f"[panel] Unknown time zone {tzname!r} (on Windows, pip install tzdata); "
          f"using this machine's local time instead", flush=True)
    def local_date(ts):
        t = time.localtime(ts)
        return t.tm_year, t.tm_mon, t.tm_mday
    def to_ts(y, mo, d, hh, mm):
        return time.mktime((y, mo, d, hh, mm, 0, 0, 0, -1))
    return local_date, to_ts

_daily_clock = _make_clock(DAILY_RESTART_TZ) if _DAILY_RESTART_HM else None

def _daily_moments(clock, hm, now):
    """(the last moment at or before now that a clock showed hm, the next one)."""
    import datetime
    local_date, to_ts = clock
    y, mo, d = local_date(now)
    base = datetime.date(y, mo, d)
    moments = sorted(to_ts(x.year, x.month, x.day, *hm)
                     for x in (base + datetime.timedelta(days=k) for k in (-1, 0, 1)))
    last = max(t for t in moments if t <= now)
    return last, min(t for t in moments if t > now)

def _daily_restart_moments(now):
    return _daily_moments(_daily_clock, _DAILY_RESTART_HM, now)

def daily_restart_info():
    if not _daily_clock:
        return None
    return {"time": "%02d:%02d" % _DAILY_RESTART_HM, "tz": DAILY_RESTART_TZ,
            "next": int(_daily_restart_moments(time.time())[1])}

def _start_daily_restart(server):
    _current_server.set(server)
    proc = get_server_process()
    if proc is None:
        return
    with server.lifecycle_lock:
        if server.lifecycle["action"]:
            print(f"[panel] Daily soft restart skipped for {server.label}: "
                  f"a {server.lifecycle['action']} is in progress", flush=True)
            return
        server.lifecycle["action"] = "daily-soft-restart"
        server.lifecycle["phase"] = None
    print(f"[panel] Daily soft restart of {server.label}", flush=True)
    threading.Thread(target=_run_lifecycle, args=("daily-soft-restart", proc, server), daemon=True).start()

def _check_daily_restart():
    if not _daily_clock:
        return
    now = time.time()
    moment = _daily_restart_moments(now)[0]
    if _daily_restart["done"] is None:
        saved = _read_state().get("daily_restart_done")
        _daily_restart["done"] = saved if isinstance(saved, (int, float)) else 0
    if moment <= _daily_restart["done"]:
        return
    _daily_restart["done"] = moment
    _update_state("daily_restart_done", moment)
    if now - moment > _DAILY_RESTART_GRACE:
        return  # the panel wasn't running at the time
    for server in SERVERS.values():
        _start_daily_restart(server)

# ─── DAILY MOD LIST BACKUP ───────────────────────────────────────────────────
#
# Every day at MODLIST_BACKUP_TIME (in MODLIST_BACKUP_TZ; 04:00 Copenhagen
# time by default) all mod lists are copied to
# MODLIST_BACKUP_DIR/<date>/<list>.json, one folder per day. The folder is
# named after the day of that 04:00. If the panel was off at the time, the
# backup is made as soon as it runs again. Old backups are kept.

MODLIST_BACKUP_DIR = _cfg.get("MODLIST_BACKUP_DIR", "").strip() or os.path.join(_BASE_DIR, "modlist-backups")
_MODLIST_BACKUP_HM = _parse_hhmm(_cfg.get("MODLIST_BACKUP_TIME", "04:00").strip(),
                                 "MODLIST_BACKUP_TIME", "the daily mod list backup")
_MODLIST_BACKUP_TZ = _cfg.get("MODLIST_BACKUP_TZ", "").strip() or "Europe/Copenhagen"
_backup_clock = _make_clock(_MODLIST_BACKUP_TZ) if _MODLIST_BACKUP_HM else None
_modlist_backup = {"done": None}

def backup_modlists(moment):
    """Copy every mod list into a folder named after `moment`'s date."""
    y, mo, d = _backup_clock[0](moment)
    folder = os.path.join(MODLIST_BACKUP_DIR, "%04d-%02d-%02d" % (y, mo, d))
    os.makedirs(folder, exist_ok=True)
    with _MODLIST_LOCK:
        names = list_modlists()
        for name in names:
            shutil.copy2(_modlist_path(name), os.path.join(folder, name + ".json"))
    print(f"[panel] Backed up {len(names)} mod list{'' if len(names) == 1 else 's'} to {folder}", flush=True)
    return folder, len(names)

def _check_modlist_backup():
    if not _backup_clock:
        return
    moment = _daily_moments(_backup_clock, _MODLIST_BACKUP_HM, time.time())[0]
    if _modlist_backup["done"] is None:
        saved = _read_state().get("modlist_backup_done")
        _modlist_backup["done"] = saved if isinstance(saved, (int, float)) else 0
    if moment <= _modlist_backup["done"] or time.time() < _modlist_backup.get("retry_at", 0):
        return
    _modlist_backup["retry_at"] = time.time() + 300  # if it fails, try again in 5 minutes
    backup_modlists(moment)
    _modlist_backup["done"] = moment
    _update_state("modlist_backup_done", moment)

def modlist_backup_info():
    if not _backup_clock:
        return None
    return {"time": "%02d:%02d" % _MODLIST_BACKUP_HM, "tz": _MODLIST_BACKUP_TZ, "dir": MODLIST_BACKUP_DIR,
            "next": int(_daily_moments(_backup_clock, _MODLIST_BACKUP_HM, time.time())[1])}

# ─── RELAUNCH AFTER A REBOOT ─────────────────────────────────────────────────
#
# The panel keeps, in .panel-state.json under "autostart", the machine's boot
# time, a heartbeat written every _ALIVE_EVERY seconds, and per server whether
# it is running. When the panel starts and the boot time has changed, the
# machine was restarted: every server that was running before is launched
# again (as with Start, from the session save), once the machine has been up
# _BOOT_SETTLE seconds so the network is ready. Servers that were stopped stay
# stopped. A server that stopped outside the panel within _SHUTDOWN_WINDOW
# seconds of the panel's last heartbeat counts as running: the shutdown closed
# it (Windows may close the servers just before the panel). A stop from the
# panel, or a crash well before the restart, counts as stopped.

_ALIVE_EVERY     = 15
_SHUTDOWN_WINDOW = 60
_BOOT_SETTLE     = 60
_BOOT_CHANGED    = 120  # boot times further apart than this mean a reboot

_autostart = {"state": None, "pending": [], "written": 0.0}

def _write_autostart(now=None):
    st = _autostart["state"]
    st["alive"] = round(now or time.time(), 3)
    _update_state("autostart", st)
    _autostart["written"] = time.time()

def _init_reboot_relaunch():
    """Runs once when the monitor starts, before it touches the servers'
    player lists. Returns {server num: last heartbeat} for the servers that
    were running when the machine went down."""
    saved = _read_state().get("autostart")
    saved = saved if isinstance(saved, dict) else {}
    boot = psutil.boot_time()
    rebooted = isinstance(saved.get("boot_time"), (int, float)) and abs(boot - saved["boot_time"]) > _BOOT_CHANGED
    alive = saved.get("alive") if isinstance(saved.get("alive"), (int, float)) else None
    was_running = {}
    if rebooted:
        for num, info in (saved.get("servers") or {}).items():
            server = SERVERS.get(int(num)) if str(num).isdigit() else None
            if server is None or not isinstance(info, dict):
                continue
            stop = info.get("outside_stop_at")
            if info.get("running") or (alive and isinstance(stop, (int, float)) and alive - stop <= _SHUTDOWN_WINDOW):
                was_running[server.num] = alive if info.get("running") else None
        names = ", ".join(SERVERS[n].label for n in sorted(was_running)) or "none"
        print(f"[panel] The machine was restarted; servers running before: {names}", flush=True)
    servers = {}
    for server in SERVERS.values():
        running = get_server_pid(server) is not None
        if server.num in was_running and not running:
            _autostart["pending"].append(server)
        # Until it is relaunched, a pending server still counts as wanted.
        servers[str(server.num)] = {"running": running or server.num in was_running, "outside_stop_at": None}
    _autostart["state"] = {"boot_time": boot, "alive": None, "servers": servers}
    _write_autostart()
    return was_running

def _note_running(server, running, outside_stop_at=None):
    if _autostart["state"] is None:
        return
    _autostart["state"]["servers"][str(server.num)] = {"running": running, "outside_stop_at": outside_stop_at}
    _write_autostart()

def _reboot_relaunch_tick():
    if _autostart["state"] is None:
        return
    now = time.time()
    if now - _autostart["written"] >= _ALIVE_EVERY:
        _write_autostart(now)
    if not _autostart["pending"] or now - psutil.boot_time() < _BOOT_SETTLE:
        return
    pending, _autostart["pending"] = _autostart["pending"], []
    for server in pending:
        _current_server.set(server)
        if get_server_pid(server) is not None:
            continue  # someone already started it
        with server.lifecycle_lock:
            if server.lifecycle["action"]:
                continue
            server.lifecycle["action"] = "reboot-start"
            server.lifecycle["phase"] = None
        print(f"[panel] Starting {server.label} again after the machine restart", flush=True)
        threading.Thread(target=_run_lifecycle, args=("reboot-start", None, server), daemon=True).start()

# ─── MONITORING ──────────────────────────────────────────────────────────────
#
# A background thread runs every second and, for each server,
#   - follows its newest console.log for players joining and leaving,
#   - compares the player list in its Server Admin Tools stats file with the
#     previous one, for joins and leaves the log doesn't show,
#   - notices its process starting and stopping,
# and measures network throughput (whole machine, loopback excluded).
# Timeline entries are appended to events.jsonl, tagged with the server.
# Where each server's follower is in its log is kept in .monitor-state.json
# (server 2: .monitor-state-2.json) so a panel restart picks up where it left
# off, and lines written while the panel was down still become entries.
# Current server stats come from the Server Admin Tools mod's stats file.

EVENTS_FILE         = os.path.join(_BASE_DIR, "events.jsonl")
_MONITOR_INTERVAL   = 1.0
_STATS_FILE_NAME    = "serveradmintools_stats.json"

_LOG_TIME_RE = re.compile(r"^(\d{2}):(\d{2}):(\d{2})\.(\d{3})")
_LOG_DIR_RE  = re.compile(r"logs_(\d{4})-(\d{2})-(\d{2})_(\d{2})-(\d{2})-(\d{2})")
# "### Updating player" is logged once the player is fully in the game. Names
# can contain commas, so the name runs up to the last ", rplIdentity=".
_JOIN_RE  = re.compile(r"### Updating player: PlayerId=(\d+), Name=(.*), rplIdentity=(0x[0-9A-Fa-f]+), IdentityId=(\S+)")
_LEAVE_RE = re.compile(r"ServerImpl event: disconnected \(identity=(0x[0-9A-Fa-f]+)")
# The -logStats line, e.g. "FPS: 59.9, frame time (avg: ...". \b keeps "maxFPS" out.
_FPS_RE   = re.compile(r"\bFPS:\s*(\d+(?:\.\d+)?)")
# A logged FPS older than this (seconds since the panel read it) is not shown.
_FPS_MAX_AGE = 10

_EVENTS_LOCK = threading.Lock()
_monitor_started = False
_monitor_start_lock = threading.Lock()
_net = {"totals": None, "at": 0.0, "up": None, "down": None}  # machine-wide

_ACTION_LABELS = {"start": "Start", "stop": "Stop", "soft-restart": "Soft restart", "hard-restart": "Hard restart",
                  "daily-soft-restart": "Daily soft restart", "reboot-start": "Started again after the VPS restarted",
                  "hard-reset": "Hard reset"}  # older timeline entries

def record_event(kind, ts=None, **fields):
    entry = {"ts": round(ts if ts is not None else time.time(), 3), "type": kind, "server": srv().num, **fields}
    with _EVENTS_LOCK, open(EVENTS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

def read_events(limit, server=None):
    """The newest `limit` entries of `server` (entries from before the panel
    ran two servers have no server field and belong to server 1)."""
    num = (server or srv()).num
    if not os.path.exists(EVENTS_FILE):
        return []
    events = []
    for line in tail_lines(EVENTS_FILE, min(limit * 5, 20000)):
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("server", 1) == num:
            events.append(e)
    events.sort(key=lambda e: e.get("ts", 0), reverse=True)
    return events[:limit]

def _stats_path(server=None):
    s = server or srv()
    configured = (_cfg.get(f"SERVER{s.num}_STATS_FILE", "") if s.num > 1 else "").strip() \
        or _cfg.get("STATS_FILE", "").strip()
    if configured:
        return configured
    # Match the name case-insensitively: the mod may capitalise it, and Linux
    # file names are case-sensitive.
    try:
        for fn in os.listdir(s.profile_dir):
            if fn.lower() == _STATS_FILE_NAME:
                return os.path.join(s.profile_dir, fn)
    except OSError:
        pass
    return os.path.join(s.profile_dir, _STATS_FILE_NAME)

def read_server_stats():
    """Returns (stats dict or None, path, error or None)."""
    path = _stats_path()
    for attempt in range(2):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f), path, None
        except FileNotFoundError:
            return None, path, "not found"
        except (OSError, ValueError) as e:
            # The mod rewrites the file constantly; a read can catch it half-written.
            if attempt:
                return None, path, str(e)
            time.sleep(0.1)

def current_fps():
    """The server's own FPS from its latest -logStats line, if that is recent."""
    rt = srv().mon_rt
    if rt["fps_at"] is None or get_server_pid() is None:
        return None
    if time.time() - rt["fps_at"] > _FPS_MAX_AGE:
        return None
    return rt["fps"]

def _creation_time(path):
    try:
        st = os.stat(path)
    except OSError:
        return None
    birth = getattr(st, "st_birthtime", None)
    if birth is None and IS_WINDOWS:
        birth = st.st_ctime  # creation time on Windows
    return birth

def _log_day_start(path):
    """(epoch of midnight on the day the log began, second-of-day it began).

    Log lines carry only the server's local clock time. The folder name
    (logs_YYYY-MM-DD_HH-MM-SS) is the server's local start time, and the
    folder's creation time is the same moment as an absolute time, so the two
    give the server's UTC offset. That keeps join/leave times right even when
    the panel's own idea of the time zone is out of date (a running process
    doesn't pick up a change to the machine's time zone). Without a creation
    time (most Linux filesystems) the panel's local time zone is used."""
    folder = os.path.dirname(path)
    m = _LOG_DIR_RE.search(os.path.basename(folder))
    if not m:
        t = time.localtime(os.path.getmtime(path))
        return time.mktime((t.tm_year, t.tm_mon, t.tm_mday, 0, 0, 0, 0, 0, -1)), 0
    y, mo, d, h, mi, s = map(int, m.groups())
    start_sod = h * 3600 + mi * 60 + s
    created = _creation_time(folder)
    if created is not None:
        offset = round((created - calendar.timegm((y, mo, d, h, mi, s, 0, 0, 0))) / 900) * 900
        if abs(offset) <= 14 * 3600:  # anything else means the folder was copied/touched
            return calendar.timegm((y, mo, d, 0, 0, 0, 0, 0, 0)) + offset, start_sod
    return time.mktime((y, mo, d, 0, 0, 0, 0, 0, -1)), start_sod

def _switch_log(path):
    midnight, start_sod = _log_day_start(path)
    srv().mon.update(path=path, offset=0, midnight=midnight, days=0, last_sod=float(start_sod), joined={})

def _handle_log_line(line, record):
    m = _LOG_TIME_RE.match(line)
    if not m:
        return
    h, mi, s, ms = map(int, m.groups())
    sod = h * 3600 + mi * 60 + s + ms / 1000
    if sod < srv().mon["last_sod"] - 3600:  # clock went back a lot: past midnight
        srv().mon["days"] += 1
    srv().mon["last_sod"] = sod
    ts = srv().mon["midnight"] + srv().mon["days"] * 86400 + sod
    f = _FPS_RE.search(line)
    if f:
        if record:  # not while silently reading an old log on first run
            srv().mon_rt.update(fps=float(f.group(1)), fps_at=time.time())
        return
    j = _JOIN_RE.search(line)
    if j:
        name, rpl, ident = j.group(2).strip(), j.group(3), j.group(4)
        srv().mon["joined"][rpl] = {"name": name, "id": ident}
        _player_joined(ident, name, ts, record)
        return
    l = _LEAVE_RE.search(line)
    if l:
        # Players who drop while still loading never "joined"; skip those.
        entry = srv().mon["joined"].pop(l.group(1), None)
        if isinstance(entry, str):  # saved by an older version: name only
            entry = {"name": entry, "id": next((i for i, p in srv().mon["present"].items()
                                                if p.get("name") == entry), None)}
        if entry and entry.get("id"):
            _player_left(entry["id"], ts, record)

# ─── Who is on the server ────────────────────────────────────────────────────
# Joins and leaves come from two places: the console log (exact times) and the
# stats file's player list (catches what the log doesn't say). Both keep the
# same `present` list, keyed by the player's identity ID, so whichever notices
# a join or leave first records it and the other then finds nothing to do.

# A player has to be missing from this many stats snapshots in a row before
# the stats file counts them as gone, so one odd read can't log a leave.
_STATS_LEAVE_AFTER = 3
# For this long after a player leaves, the stats file can't log them joining
# again (it may still list them for a moment); the log still can.
_STATS_REJOIN_BLOCK = 20
# Stats not updated for this long (seconds) are ignored.
_STATS_MAX_AGE = 30

def _player_joined(ident, name, ts, record=True):
    present = srv().mon["present"]
    if ident in present:
        present[ident]["name"] = name
        return
    present[ident] = {"name": name, "since": ts}
    srv().mon_rt["missing"].pop(ident, None)
    if record:
        record_event("player_joined", ts, name=name, identity=ident)

def _player_left(ident, ts, record=True, **extra):
    rt = srv().mon_rt
    player = srv().mon["present"].pop(ident, None)
    rt["missing"].pop(ident, None)
    rt["seen_in_stats"].discard(ident)
    if player is None:
        return
    rt["left_at"][ident] = time.time()
    if record:
        record_event("player_left", ts, name=player.get("name", "?"), identity=ident, **extra)

def _stats_players():
    """identityId -> name from this server's stats file, or None when the file
    can't be trusted right now (missing, half-written, out of date, the server
    is off, or another running server writes the same file)."""
    if get_server_pid() is None:
        return None
    other = other_server()
    if os.path.normcase(_stats_path()) == os.path.normcase(_stats_path(other)) and get_server_pid(other):
        return None
    stats, _path, _err = read_server_stats()
    if not isinstance(stats, dict) or not isinstance(stats.get("connected_players"), dict):
        return None
    updated = stats.get("updated")
    if isinstance(updated, (int, float)) and time.time() - updated > _STATS_MAX_AGE:
        return None
    return {str(k): str(v) for k, v in stats["connected_players"].items()}

def _sync_stats_players():
    players = _stats_players()
    if players is None:
        return
    rt, present, now = srv().mon_rt, srv().mon["present"], time.time()
    if not rt["seeded"]:
        # First snapshot since the panel had no list (first run): take it as
        # the starting point rather than reporting everyone as joining now.
        for ident, name in players.items():
            _player_joined(ident, name, None, record=False)  # join time unknown
        rt["seen_in_stats"].update(players)
        rt["seeded"] = True
        return
    for ident, name in players.items():
        if ident not in present and now - rt["left_at"].get(ident, 0) > _STATS_REJOIN_BLOCK:
            _player_joined(ident, name, now)
        if ident in present:
            rt["seen_in_stats"].add(ident)
            rt["missing"].pop(ident, None)
    for ident in list(present):
        # Only players the file has listed can go missing from it: someone the
        # log just reported joining may not be in it yet.
        if ident in players or ident not in rt["seen_in_stats"]:
            continue
        rt["missing"][ident] = rt["missing"].get(ident, 0) + 1
        if rt["missing"][ident] >= _STATS_LEAVE_AFTER:
            _player_left(ident, now)

def _read_log(record):
    """Process complete lines after the saved offset in the current log."""
    path = srv().mon["path"]
    try:
        if os.path.getsize(path) < srv().mon["offset"]:
            _switch_log(path)  # file was replaced or truncated
        with open(path, "rb") as f:
            f.seek(srv().mon["offset"])
            while True:
                chunk = f.read(4 * 1024 * 1024)
                end = chunk.rfind(b"\n")
                if end < 0:
                    break
                for line in chunk[:end].decode("utf-8", errors="replace").splitlines():
                    _handle_log_line(line, record)
                srv().mon["offset"] += end + 1
                f.seek(srv().mon["offset"])
    except OSError:
        pass

def _log_folder_name(path):
    return os.path.basename(os.path.dirname(path)) if path else ""

def _follow_logs():
    mon = srv().mon
    if mon["path"] and os.path.exists(mon["path"]):
        _read_log(record=True)
    latest = get_latest_log()
    # Only ever move on to a newer log: while a just-started server's log has
    # no CLI Params line yet, get_latest_log() can still return an older one.
    if latest and latest != mon["path"] and _log_folder_name(latest) > _log_folder_name(mon["path"]):
        _switch_log(latest)
        _read_log(record=True)

def _recent_panel_action():
    if srv().lifecycle["action"]:
        return srv().lifecycle["action"]
    # A restart can finish between two monitor ticks; allow a few seconds.
    last = srv().lifecycle["last"]
    if last and time.time() - last["ts"] < 3 * _MONITOR_INTERVAL:
        return last["action"]
    return None

def _check_process():
    proc = get_server_process()
    pid = proc.pid if proc else None
    prev = srv().mon_rt["pid"]
    srv().mon_rt["pid"] = pid
    if pid == prev:
        return
    started = None
    if pid is not None:
        try:
            started = proc.create_time()
        except psutil.Error:
            started = time.time()
    if prev is not None:
        action = _recent_panel_action()
        # If it was already restarted by this tick, the stop came first.
        stopped = min(time.time(), started - 0.001) if started else None
        record_event("server_stopped", stopped,
                     detail=f"From the panel ({_ACTION_LABELS.get(action, action)})" if action
                     else "Outside the panel (crashed, or closed on the server)")
        for ident in list(srv().mon["present"]):
            _player_left(ident, stopped, reason="server stopped")
        srv().mon["joined"] = {}
        if pid is None:
            _note_running(srv(), False, None if action else (stopped or time.time()))
    if pid is not None:
        _note_running(srv(), True)
        # A freshly started server has nobody on it yet.
        srv().mon["present"], srv().mon["joined"] = {}, {}
        srv().mon_rt["missing"].clear()
        srv().mon_rt["seen_in_stats"].clear()
        from_panel = abs(started - srv().last_launch["ts"]) < 20
        action = srv().last_launch["action"]
        record_event("server_started", started,
                     detail=f"From the panel ({_ACTION_LABELS.get(action, action)})" if from_panel
                     else "Outside the panel")

def _net_totals():
    sent = recv = 0
    for name, c in psutil.net_io_counters(pernic=True).items():
        if name == "lo" or "loopback" in name.lower():
            continue
        sent += c.bytes_sent
        recv += c.bytes_recv
    return sent, recv

def _sample_network():
    now = time.time()
    totals = _net_totals()
    prev, prev_at = _net["totals"], _net["at"]
    _net.update(totals=totals, at=now)
    if prev is None or now <= prev_at:
        return
    up, down = totals[0] - prev[0], totals[1] - prev[1]
    if up < 0 or down < 0:  # counters reset (adapter re-enabled)
        return
    _net.update(up=up / (now - prev_at), down=down / (now - prev_at))

def _load_monitor_state():
    mon = srv().mon
    try:
        with open(srv().monitor_state_file, encoding="utf-8") as f:
            saved = json.load(f)
        if saved.get("path") and os.path.exists(saved["path"]):
            mon.update({k: saved[k] for k in mon if k in saved})
            # With a saved player list, joins and leaves since then are real.
            srv().mon_rt["seeded"] = "present" in saved
            srv().mon_rt["seen_in_stats"] = set(mon["present"])
            # Recompute rather than trust the saved value, which may have been
            # worked out with an outdated time zone.
            mon["midnight"] = _log_day_start(mon["path"])[0]
    except (OSError, ValueError):
        pass

def _save_monitor_state(last_saved):
    data = json.dumps(srv().mon, ensure_ascii=False)
    if data != last_saved:
        with open(srv().monitor_state_file, "w", encoding="utf-8") as f:
            f.write(data)
    return data

def _monitor_loop():
    try:
        was_running = _init_reboot_relaunch()
    except Exception as e:
        print(f"[panel] monitor error (reboot check): {e}", flush=True)
        was_running = {}
    for server in SERVERS.values():
        _current_server.set(server)
        _load_monitor_state()
        if server.mon["path"] is None:
            # First run: read the current log silently, only to learn who is
            # connected, so joins from before the panel was installed aren't
            # reported as new.
            initial = get_latest_log()
            if initial:
                _switch_log(initial)
                _read_log(record=False)
        # Whatever is running when the panel starts isn't a new start.
        server.mon_rt["pid"] = get_server_pid()
        if server.mon_rt["pid"] is None:
            # It stopped while the panel was down: nobody is on it any more.
            if was_running.get(server.num):
                # The panel didn't see it stop: the machine went down with it.
                down = was_running[server.num]
                record_event("server_stopped", down, detail="The VPS was shut down or restarted")
                for ident in list(server.mon["present"]):
                    _player_left(ident, down, reason="VPS restarted")
            server.mon["present"], server.mon["joined"] = {}, {}
    last_saved = {}
    while True:
        try:
            _sample_network()
        except Exception as e:
            print(f"[panel] monitor error (network): {e}", flush=True)
        try:
            _check_daily_restart()
            _reboot_relaunch_tick()
        except Exception as e:
            print(f"[panel] monitor error (schedule): {e}", flush=True)
        try:
            _check_modlist_backup()
        except Exception as e:
            print(f"[panel] mod list backup failed: {e}", flush=True)
        for server in SERVERS.values():
            _current_server.set(server)
            try:
                _follow_logs()
                _sync_stats_players()
                _check_process()
                last_saved[server.num] = _save_monitor_state(last_saved.get(server.num))
            except Exception as e:
                print(f"[panel] monitor error ({server.label}): {e}", flush=True)
        time.sleep(_MONITOR_INTERVAL)

def start_monitor():
    global _monitor_started
    with _monitor_start_lock:
        if _monitor_started:
            return
        _monitor_started = True
    threading.Thread(target=_monitor_loop, daemon=True, name="monitor").start()
    threading.Thread(target=_scenario_watch_loop, daemon=True, name="scenario-watch").start()

@app.before_request
def _ensure_monitor():
    start_monitor()

@app.route("/api/events")
def api_events():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    limit = max(1, min(int(request.args.get("limit", 200)), 2000))
    return jsonify({"ok": True, "events": read_events(limit)})

@app.route("/api/players")
def api_players():
    """The players on the server now, as the timeline knows them (from the
    console log and the stats file's player list)."""
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    running = get_server_pid() is not None
    players = [{"id": ident, "name": p.get("name", "?"), "since": p.get("since")}
               for ident, p in list(srv().mon["present"].items())] if running else []
    players.sort(key=lambda p: (p["since"] is None, p["since"] or 0, p["name"].lower()))
    return jsonify({"ok": True, "running": running, "now": time.time(), "players": players,
                    "max_players": read_config().get("game", {}).get("maxPlayers")})

@app.route("/api/server-stats")
def api_server_stats():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    stats, path, error = read_server_stats()
    other = other_server()
    # Both servers write the same file unless STATS_FILE settings tell them apart.
    shared = (os.path.normcase(path) == os.path.normcase(_stats_path(other))
              and get_server_pid() is not None and get_server_pid(other) is not None)
    return jsonify({"ok": stats is not None, "stats": stats, "path": path, "error": error,
                    "now": time.time(), "running": get_server_pid() is not None,
                    "shared_with": other.label if shared else None})

# ─── INSTALLED MODS ──────────────────────────────────────────────────────────
#
# The Mods page lists every mod installed on the server. From disk: the GUID,
# installed version and size (from the mod's folder and its `meta` file) and
# the dependencies (from `addon.gproj`). From the mod's workshop page: the
# name, latest version, created/modified dates and game version. Workshop
# pages are fetched in the background and cached in .workshop-cache.json.

WORKSHOP_URL         = "https://reforger.armaplatform.com/workshop/{guid}"
_WORKSHOP_CACHE_FILE = os.path.join(_BASE_DIR, ".workshop-cache.json")
_WORKSHOP_TTL        = 12 * 3600   # refetch successful pages after this long
_WORKSHOP_ERROR_TTL  = 3600        # retry failed pages after this long
# Arma Reforger's own GUID: listed first in every addon.gproj's Dependencies.
_REFORGER_CORE_GUID  = "58D0FB3206B6F859"
_GUID_RE             = re.compile(r"^[0-9A-F]{16}$")

_ws_lock = threading.Lock()
_ws_cache = None          # guid -> {"fetched_at", "data"} or {"fetched_at", "error"}
_ws_queued = set()
_ws_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="workshop")

def _gproj_info(addon_dir):
    """(GUID, title, dependency GUIDs) from addon.gproj, or Nones/[]."""
    try:
        with open(os.path.join(addon_dir, "addon.gproj"), encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return None, None, []
    guid = re.search(r'\bGUID\s+"([0-9A-Fa-f]{16})"', text)
    title = re.search(r'\bTITLE\s+"([^"]+)"', text)
    deps = []
    block = re.search(r"\bDependencies\s*\{([^}]*)\}", text)
    if block:
        deps = [g.upper() for g in re.findall(r"([0-9A-Fa-f]{16})", block.group(1))]
    # The first entry is Arma Reforger itself.
    if _REFORGER_CORE_GUID in deps:
        deps.remove(_REFORGER_CORE_GUID)
    elif deps:
        deps = deps[1:]
    return (guid.group(1).upper() if guid else None,
            title.group(1).strip() if title else None,
            list(dict.fromkeys(deps)))

def _meta_info(addon_dir):
    """The mod's `meta` file (written by the server's downloader), or {}."""
    try:
        with open(os.path.join(addon_dir, "meta"), encoding="utf-8-sig") as f:
            data = json.load(f)
        meta = data.get("meta") if isinstance(data, dict) else None
        return meta if isinstance(meta, dict) else {}
    except (OSError, ValueError):
        return {}

def _folder_size(path):
    total = 0
    for dirpath, _dirs, files in os.walk(path):
        for fn in files:
            try:
                total += os.path.getsize(os.path.join(dirpath, fn))
            except OSError:
                pass
    return total

def scan_installed_mods():
    """Every installed mod (workshop addon folders, not the game's own data):
    {guid: {guid, name, version, size, path, deps}}."""
    mods = {}
    for root, is_vanilla in _candidate_addon_roots():
        if is_vanilla or not os.path.isdir(root):
            continue
        for name in sorted(os.listdir(root)):
            addon_dir = os.path.join(root, name)
            if not os.path.isdir(addon_dir):
                continue
            has_gproj = os.path.isfile(os.path.join(addon_dir, "addon.gproj"))
            if not has_gproj and not os.path.isfile(os.path.join(addon_dir, "meta")):
                continue
            guid, title, deps = _gproj_info(addon_dir)
            meta = _meta_info(addon_dir)
            guid = guid or str(meta.get("id") or "").upper()
            if not guid:
                m = re.search(r"([0-9A-Fa-f]{16})$", name)
                guid = m.group(1).upper() if m else None
            if not guid or not _GUID_RE.match(guid) or guid in mods:
                continue
            versions = meta.get("versions") if isinstance(meta.get("versions"), list) else []
            v0 = versions[0] if versions and isinstance(versions[0], dict) else {}
            mods[guid] = {
                "guid": guid,
                "name": str(meta.get("name") or title or name).strip(),
                "version": str(v0.get("version") or meta.get("version") or "") or None,
                "size": _folder_size(addon_dir),
                "path": addon_dir,
                "deps": deps,
            }
    return mods

def _all_dependencies(guid, mods):
    """Every dependency of `guid`, direct and indirect, in discovery order.
    Dependencies that aren't installed are listed but can't be followed
    further (their addon.gproj isn't on disk)."""
    seen, order = set(), []
    stack = list(reversed(mods.get(guid, {}).get("deps", [])))
    while stack:
        g = stack.pop()
        if g in seen or g == guid:
            continue
        seen.add(g)
        order.append(g)
        stack.extend(reversed(mods.get(g, {}).get("deps", [])))
    return order

# Workshop pages are a Next.js app: the asset's data is embedded as JSON in
# <script id="__NEXT_DATA__">, at props.pageProps.asset (checked October
# 2026: name, currentVersionNumber, currentVersionSize, createdAt, updatedAt,
# gameVersion). The keys below are tried in order; the first one found
# (nearest the asset object's top level) wins, so a nested gameVersion such
# as dependencyTree.gameVersion isn't picked up.
_WS_FIELDS = {
    "name":         ("name", "title"),
    "version":      ("currentVersionNumber", "version", "versionNumber"),
    "size":         ("currentVersionSize", "totalFileSize", "fileSize", "size"),
    "created":      ("createdAt", "created", "publishedAt", "createDate"),
    "updated":      ("updatedAt", "lastModified", "modifiedAt", "updated"),
    "game_version": ("gameVersion", "gameVersionNumber", "requiredGameVersion"),
}
_NEXT_DATA_RE = re.compile(r'<script[^>]*id="__NEXT_DATA__"[^>]*>(.*?)</script>', re.S)

def _walk_dicts(obj, depth=0, max_depth=12):
    """Yield (depth, dict) for every dict inside obj, breadth-first."""
    queue = [(0, obj)]
    while queue:
        d, o = queue.pop(0)
        if isinstance(o, dict):
            yield d, o
            children = o.values()
        elif isinstance(o, list):
            children = o
        else:
            continue
        if d < max_depth:
            queue.extend((d + 1, c) for c in children if isinstance(c, (dict, list)))

def _find_field(asset, keys):
    for key in keys:
        for _d, o in _walk_dicts(asset, max_depth=3):
            v = o.get(key)
            if v not in (None, "", [], {}) and not isinstance(v, (dict, list)):
                return v
    return None

def _parse_workshop_page(html, guid):
    m = _NEXT_DATA_RE.search(html)
    if not m:
        raise ValueError("no embedded data (__NEXT_DATA__) on the page")
    data = json.loads(m.group(1))
    # The asset is the object whose id is this mod's GUID: normally
    # props.pageProps.asset; otherwise search for it.
    asset = ((data.get("props") or {}).get("pageProps") or {}).get("asset")
    if not (isinstance(asset, dict) and str(asset.get("id", "")).upper() == guid):
        asset = None
    for _d, o in ([] if asset else _walk_dicts(data)):
        if any(str(o.get(k, "")).upper() == guid for k in ("id", "guid", "assetId")) and ("name" in o or "title" in o):
            asset = o
            break
    if asset is None:
        raise ValueError("mod data not found in the page's embedded data")
    out = {k: _find_field(asset, keys) for k, keys in _WS_FIELDS.items()}
    if isinstance(out["size"], str):
        out["size"] = _parse_size(out["size"])
    return out

def _parse_size(text):
    m = re.match(r"\s*([\d.,]+)\s*([KMGT]?i?B)\b", text or "", re.I)
    if not m:
        return None
    mult = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3, "TB": 1024 ** 4}
    return int(float(m.group(1).replace(",", "")) * mult.get(m.group(2).upper().replace("I", ""), 1))

def _ws_load_cache():
    global _ws_cache
    if _ws_cache is None:
        try:
            with open(_WORKSHOP_CACHE_FILE, encoding="utf-8") as f:
                _ws_cache = json.load(f)
        except (OSError, ValueError):
            _ws_cache = {}
    return _ws_cache

def _ws_save_cache():
    tmp = _WORKSHOP_CACHE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(_ws_cache, f, ensure_ascii=False)
    os.replace(tmp, _WORKSHOP_CACHE_FILE)

def _ws_fetch(guid):
    try:
        req = urllib.request.Request(WORKSHOP_URL.format(guid=guid),
                                     headers={"User-Agent": "Mozilla/5.0 (arma-reforger-panel)"})
        with urllib.request.urlopen(req, timeout=20) as r:
            html = r.read().decode("utf-8", errors="replace")
        entry = {"fetched_at": time.time(), "data": _parse_workshop_page(html, guid)}
    except urllib.error.HTTPError as e:
        entry = {"fetched_at": time.time(), "error": "no such mod on the workshop" if e.code == 404 else str(e)[:300]}
    except Exception as e:
        entry = {"fetched_at": time.time(), "error": str(e)[:300]}
    with _ws_lock:
        _ws_load_cache()[guid] = entry
        _ws_queued.discard(guid)
        try:
            _ws_save_cache()
        except OSError:
            pass
    return entry

def _ws_queue_stale(guids, force=False):
    """Fetch workshop pages that are missing or out of date, in the background."""
    now = time.time()
    with _ws_lock:
        cache = _ws_load_cache()
        for g in guids:
            entry = cache.get(g)
            ttl = _WORKSHOP_ERROR_TTL if entry and "error" in entry else _WORKSHOP_TTL
            if g in _ws_queued or (entry and not force and now - entry["fetched_at"] < ttl):
                continue
            _ws_queued.add(g)
            _ws_pool.submit(_ws_fetch, g)
        return len(_ws_queued)

def _modlist_membership():
    """guid -> [names of the mod lists that include it]."""
    member = {}
    for name in list_modlists():
        try:
            mods = load_modlist(name)
        except (OSError, ValueError):
            continue
        for m in mods:
            member.setdefault(str(m.get("modId", "")).upper(), []).append(name)
    return member

@app.route("/api/mods/installed")
def api_mods_installed():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    installed = scan_installed_mods()
    membership = _modlist_membership()
    all_deps = {g: _all_dependencies(g, installed) for g in installed}
    # Dependencies that aren't installed are fetched too, for their names.
    wanted = set(installed) | {d for deps in all_deps.values() for d in deps}
    pending = _ws_queue_stale(sorted(wanted))
    with _ws_lock:
        cache = dict(_ws_load_cache())
    def ws(g):
        e = cache.get(g) or {}
        return e.get("data"), e.get("error")
    mods = []
    for g, m in installed.items():
        data, error = ws(g)
        data = data or {}
        mods.append({
            **{k: m[k] for k in ("guid", "version", "size", "path")},
            "name": data.get("name") or m["name"],
            "workshop_version": data.get("version"),
            "workshop_size": data.get("size"),
            "created": data.get("created"),
            "updated": data.get("updated"),
            "game_version": data.get("game_version"),
            "workshop_error": error,
            "deps_direct": m["deps"],
            "deps_all": all_deps[g],
            "modlists": membership.get(g, []),
        })
    names = {g: ((ws(g)[0] or {}).get("name") or (installed.get(g) or {}).get("name")) for g in wanted}
    lists = {}
    for name in list_modlists():
        try:
            lists[name] = [str(x.get("modId", "")).upper() for x in load_modlist(name)]
        except (OSError, ValueError):
            pass
    return jsonify({"ok": True, "server": srv().num, "addons_dir": srv().addons_dir,
                    "mods": mods, "names": names, "modlists": lists,
                    "selected": get_selected_modlist(),
                    "selected_by": {x.label: get_selected_modlist(x) for x in SERVERS.values()},
                    "workshop_pending": pending,
                    "workshop_url": WORKSHOP_URL})

@app.route("/api/mods/workshop-refresh", methods=["POST"])
def api_mods_workshop_refresh():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    installed = scan_installed_mods()
    wanted = set(installed) | {d for g in installed for d in _all_dependencies(g, installed)}
    return jsonify({"ok": True, "workshop_pending": _ws_queue_stale(sorted(wanted), force=True)})

# ─── PANEL UPDATE ────────────────────────────────────────────────────────────
#
# The Update button: the panel exits, update_panel.py (started as its own
# process) runs git pull in the panel folder, installs requirements.txt if it
# changed, and starts the panel again with the same command line. The game
# servers keep running. Under systemd the pull runs here instead and systemd
# restarts the panel (Restart=always). The outcome is kept in
# .panel-update.json and shown by the page after it reloads.

_PANEL_STARTED = time.time()
_UPDATER = os.path.join(_BASE_DIR, "update_panel.py")
_UPDATE_RESULT = os.path.join(_BASE_DIR, ".panel-update.json")
_update_lock = threading.Lock()
_updating = False

def _git_version():
    try:
        p = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=_BASE_DIR, capture_output=True,
                           text=True, timeout=10, stdin=subprocess.DEVNULL,
                           **({"creationflags": subprocess.CREATE_NO_WINDOW} if IS_WINDOWS else {}))
        return p.stdout.strip() if p.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None

def _exit_soon():
    def bye():
        time.sleep(1)  # let the response go out first
        print("[panel] Exiting for the update", flush=True)
        os._exit(0)
    threading.Thread(target=bye, daemon=True).start()

@app.route("/api/panel-update", methods=["GET"])
def api_panel_update_info():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    last = None
    try:
        with open(_UPDATE_RESULT, encoding="utf-8") as f:
            last = json.load(f)
    except (OSError, ValueError):
        pass
    return jsonify({"started": _PANEL_STARTED, "version": _git_version(), "last": last})

@app.route("/api/panel-update", methods=["POST"])
def api_panel_update():
    global _updating
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    if not shutil.which("git"):
        return jsonify({"ok": False, "error": "git isn't installed or isn't on PATH"})
    if not _git_version():
        return jsonify({"ok": False, "error": f"{_BASE_DIR} isn't a git checkout, so it can't be updated with git pull"})
    busy = [f"{x.label} ({_ACTION_LABELS.get(x.lifecycle['action'], x.lifecycle['action']).lower()})"
            for x in SERVERS.values() if x.lifecycle["action"]]
    if busy:
        return jsonify({"ok": False, "error": f"Wait for {', '.join(busy)} to finish first"})
    with _update_lock:
        if _updating:
            return jsonify({"ok": False, "error": "An update is already running"})
        _updating = True
    try:
        if not IS_WINDOWS and os.environ.get("INVOCATION_ID"):
            # A systemd service: a helper would be stopped along with the
            # panel, so pull here; systemd starts the panel again.
            def pull_then_exit():
                sys.path.insert(0, _BASE_DIR)
                import update_panel
                update_panel.run_update()
                _exit_soon()
            threading.Thread(target=pull_then_exit, daemon=True).start()
        else:
            cmd = [sys.executable] + [os.path.abspath(sys.argv[0])] + sys.argv[1:]
            args = [sys.executable, _UPDATER, str(os.getpid()), PANEL_HOST, str(PANEL_PORT), os.getcwd(), json.dumps(cmd)]
            if IS_WINDOWS:
                subprocess.Popen(args, cwd=_BASE_DIR, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL,
                                 creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)
            else:
                subprocess.Popen(args, cwd=_BASE_DIR, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, start_new_session=True)
            _exit_soon()
    except Exception as e:
        _updating = False
        return jsonify({"ok": False, "error": f"Could not start the update: {e}"})
    return jsonify({"ok": True, "started": _PANEL_STARTED})

if __name__ == "__main__":
    start_monitor()
    app.run(host=PANEL_HOST, port=PANEL_PORT, threaded=True)
