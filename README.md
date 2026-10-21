# Arma Reforger Server Management Panel

A lightweight, self-hosted web panel for managing your **Arma Reforger dedicated server** on Linux. The all-in-one installer sets up everything from scratch — SteamCMD, the game server, and the panel — on a clean Ubuntu VPS.

> **Live demo:** [demoarma.mateuszgolebiewski.pl](https://demoarma.mateuszgolebiewski.pl) — password: `demo`

---

## Features

- **One-command install** — sets up SteamCMD, downloads the Arma Reforger server and installs the panel automatically
- **Server control** — Start, stop and restart your server from the browser
- **Soft restart** — Save the game state, stop the server and bring it back up from that save
- **Linux and Windows** — Runs on Ubuntu (with the installer) or on Windows Server (manual setup)
- **Real-time monitoring** — Live CPU and RAM charts updated every 3 seconds
- **Live log streaming** — Server console logs with colour-coded output (errors, warnings, network events)
- **Mission selector** — 41 built-in missions including all vanilla and RHS — Status Quo scenarios
- **Mod management** — Add and remove Workshop mods directly from the panel
- **Config editor** — Edit server name, scenario, passwords without touching the filesystem
- **PWA support** — Installable as a native app on Android and iOS
- **Single config file** — All settings in one `config.env`, no code editing required

---

## Requirements

| Component | Requirement |
|-----------|-------------|
| OS | Ubuntu 20.04 / 22.04 / 24.04 |
| Architecture | x86_64 |
| RAM | 4 GB minimum, 8 GB recommended |
| Disk | 20 GB free (Arma server is ~15 GB) |
| Python | 3.10+ (installed automatically) |

---

## Installation

### Option A — Full install (recommended for a fresh VPS)

Sets up everything: SteamCMD, Arma Reforger Dedicated Server, and the management panel.

```bash
git clone https://github.com/mateuszgolebiewski-code/arma-reforger-panel.git
cd arma-reforger-panel
sudo bash install.sh
```

The installer will ask you for:
- System username (default: `arma`)
- Server name, game password, admin password
- Max players, game port, public IP
- Panel web password and port

After ~15 minutes your server is running and the panel is accessible at:
```
http://YOUR_SERVER_IP:8888
```

---

### Option B — Panel only (server already installed)

If you already have Arma Reforger server running and only want the web panel:

```bash
git clone https://github.com/mateuszgolebiewski-code/arma-reforger-panel.git
cd arma-reforger-panel
sudo bash install.sh --panel-only
```

The installer will ask for your existing server paths (`SERVER_DIR`, `config.json`, log directory).

---

### Option C — Windows Server

There is no installer for Windows; setup takes a few manual steps.

1. Install the server with [SteamCMD for Windows](https://developer.valvesoftware.com/wiki/SteamCMD#Windows):
   ```powershell
   steamcmd +force_install_dir C:\arma\server +login anonymous +app_update 1874900 validate +quit
   ```
2. Install [Python 3.10+](https://www.python.org/downloads/windows/) (tick **Add python.exe to PATH**), then in the panel folder:
   ```powershell
   pip install -r requirements.txt
   copy config.env.example config.env
   ```
3. Edit `config.env` with Windows paths, for example:
   ```env
   PANEL_PASSWORD=your-password
   SERVER_DIR=C:\arma\server
   SERVER_CONFIG=C:\arma\server\config.json
   LOG_DIR=C:\Users\Administrator\Documents\My Games\ArmaReforger\logs
   WORKSHOP_DIR=C:\Users\Administrator\Documents\My Games\ArmaReforger\addons
   PROFILE_DIR=C:\Users\Administrator\Documents\My Games\ArmaReforger\profile
   ```
   The `Documents\My Games\ArmaReforger` paths belong to the Windows user the server runs as. A plaintext `PANEL_PASSWORD` works but prints a warning; see `config.env.example` for setting a bcrypt hash instead.
4. Open the ports (PowerShell as Administrator):
   ```powershell
   New-NetFirewallRule -DisplayName "Arma Reforger" -Direction Inbound -Protocol UDP -LocalPort 2001,17777 -Action Allow
   New-NetFirewallRule -DisplayName "Arma Panel" -Direction Inbound -Protocol TCP -LocalPort 8888 -Action Allow
   ```
5. Start the panel with `python app.py` and open `http://YOUR_SERVER_IP:8888`.

To start the panel at boot, put a shortcut to `python app.py` in the Startup folder of the user that runs the server, or run it as a service with [NSSM](https://nssm.cc/). With NSSM, run `nssm set <service> AppKillProcessTree 0` so that restarting the panel doesn't also kill the game server.

**How stop and restart work on Windows.** The panel starts the server in its own console window, just like running it by hand. **Stop** and **Soft restart** send that console Ctrl+C, so the server saves the game state and exits cleanly. **Restart** is a hard restart: it kills the server immediately without saving, then starts it again. Start the server from the panel. If you start it by hand from a `.bat` file, the panel can still stop it, but the batch window will be left asking `Terminate batch job (Y/N)?`.

---

### Option D — Update panel files only

After pulling a new version from GitHub:

```bash
git pull
sudo bash install.sh --update
```

This copies updated panel files and restarts the service. Your `config.env` is preserved.

---

## Configuration

All settings live in `config.env` (created automatically by the installer):

```env
# Password for the panel web UI
PANEL_PASSWORD=changeme

# Port the panel listens on
PANEL_PORT=8888

# Path to your Arma Reforger server binary directory
SERVER_DIR=/home/arma/server

# Full path to your server config.json
SERVER_CONFIG=/home/arma/server/config.json

# Arma Reforger log directory
LOG_DIR=/home/arma/.config/ArmaReforger/logs

# Server FPS cap (passed as -maxFPS on startup)
MAX_FPS=60

# Seconds to wait for the server to save and exit on Stop / Soft restart
SHUTDOWN_TIMEOUT=180
```

After editing, restart the panel:
```bash
sudo systemctl restart arma-panel
```

---

## Useful Commands

```bash
# ── Panel ──────────────────────────────────────────────────
sudo systemctl status arma-panel      # check panel status
sudo systemctl restart arma-panel     # restart panel
sudo journalctl -u arma-panel -f      # live panel logs

# ── Arma Server ────────────────────────────────────────────
sudo systemctl start arma-server      # start server
sudo systemctl stop arma-server       # stop server
sudo systemctl status arma-server     # check server status
sudo journalctl -u arma-server -f     # live server logs

# ── Update ─────────────────────────────────────────────────
git pull && sudo bash install.sh --update
```

---

## HTTPS / Domain (optional)

To access the panel over HTTPS with a custom domain, use nginx as a reverse proxy with a Let's Encrypt certificate.

Nginx config example:
```nginx
location / {
    proxy_pass http://127.0.0.1:8888;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_buffering off;
    proxy_read_timeout 3600;
}
```

If you use **HestiaCP**, add a subdomain through its web interface — it handles SSL automatically.

---

## Project Structure

```
arma-reforger-panel/
├── app.py               # Flask backend — API, server control, metrics
├── win_ctrl_c.py        # Windows helper: sends Ctrl+C to the server console
├── requirements.txt     # Python dependencies (for pip / Windows)
├── index.html           # Main panel UI (English)
├── login.html           # Login screen
├── config.env           # Your local config (excluded from git)
├── config.env.example   # Config template
├── install.sh           # All-in-one installer
├── static/
│   ├── manifest.json        # PWA manifest
│   ├── service-worker.js    # PWA service worker
│   ├── icon-192.png         # App icon
│   └── icon-512.png         # App icon (large)
└── README.md
```

---

## RHS — Status Quo

The panel includes mission IDs for all RHS — Status Quo scenarios. They appear automatically in the mission dropdown once you add the [RHS mod](https://reforger.armaplatform.com/workshop/595F2BF2F44836FB-RHS-Status-Quo) to your server.

---

## Contributing

Pull requests and issues are welcome. Open an issue on GitHub if you run into problems or want to suggest a feature.

---

## License

MIT — free to use, modify and distribute.

---

*Built by [Mateusz Gołębiewski](https://mateuszgolebiewski.pl)*
