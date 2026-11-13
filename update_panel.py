"""
Update the panel from git: wait for the panel process to exit, run git pull,
then start the panel again with the same command line.

    python update_panel.py <panel pid> <panel host> <panel port> <cwd> <command line as JSON>

app.py starts this as a separate process when someone presses Update in the
panel, then exits. The game servers keep running throughout. The outcome is
written to .panel-update.json, which the restarted panel shows.

run_update() is also used by app.py directly when the panel runs as a systemd
service (systemd starts it again by itself).
"""

import hashlib
import json
import os
import socket
import subprocess
import sys
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULT_FILE = os.path.join(BASE_DIR, ".panel-update.json")
IS_WINDOWS = os.name == "nt"
# No console window flashing up for git/pip when run from a detached process.
_NO_WINDOW = {"creationflags": subprocess.CREATE_NO_WINDOW} if IS_WINDOWS else {}


def _run(args, timeout):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")  # fail instead of waiting for a password
    p = subprocess.run(args, cwd=BASE_DIR, capture_output=True, text=True, timeout=timeout,
                       env=env, stdin=subprocess.DEVNULL, **_NO_WINDOW)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def _head():
    code, out, _ = _run(["git", "rev-parse", "--short", "HEAD"], 30)
    return out if code == 0 else None


def _file_hash(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def _error_summary(text):
    """The part of git's/pip's output that says what went wrong."""
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    for i, line in enumerate(lines):
        if line.lower().startswith(("error", "fatal", "hint: diverging")):
            return " ".join(lines[i:i + 6])
    return " ".join(lines[-3:])


def run_update():
    """git pull (fast-forward only), plus pip install when requirements.txt
    changed. Returns the result that is also written to RESULT_FILE."""
    result = {"ts": time.time(), "ok": False, "before": None, "after": None, "commits": [], "output": "", "error": None}
    try:
        result["before"] = _head()
        req = os.path.join(BASE_DIR, "requirements.txt")
        req_before = _file_hash(req)
        code, out, err = _run(["git", "pull", "--ff-only"], 180)
        # On failure the error (stderr) first, as it says what went wrong.
        result["output"] = "\n".join(x for x in ((out, err) if code == 0 else (err, out)) if x)
        result["after"] = _head()
        if code != 0:
            result["error"] = "git pull failed: " + _error_summary(err or out)
        else:
            result["ok"] = True
            if result["before"] and result["after"] and result["before"] != result["after"]:
                _, log, _ = _run(["git", "log", "--format=%h %s", f"{result['before']}..{result['after']}"], 30)
                result["commits"] = log.splitlines()[:50]
            if _file_hash(req) != req_before:
                code, out, err = _run([sys.executable, "-m", "pip", "install", "-r", req], 600)
                if code != 0:
                    result["ok"] = False
                    result["error"] = "The update was pulled, but pip install -r requirements.txt failed: " + _error_summary(err or out)
                    result["output"] += "\n\npip install -r requirements.txt failed:\n" + (err + "\n" + out)[-2000:]
    except Exception as e:
        result["ok"] = False
        result["error"] = f"{type(e).__name__}: {e}"
        result["output"] = (result["output"] + "\n" if result["output"] else "") + result["error"]
    result["output"] = result["output"][-4000:]
    with open(RESULT_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f)
    return result


def _wait_for_exit(pid, timeout=60):
    try:
        import psutil
        psutil.Process(pid).wait(timeout)
    except ImportError:
        time.sleep(5)
    except Exception:
        pass  # already gone, or still there after the timeout: carry on


def _listening(host, port):
    host = "127.0.0.1" if host in ("", "0.0.0.0", "::") else host
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def main():
    pid, host, port, cwd, cmd = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), sys.argv[4], json.loads(sys.argv[5])
    _wait_for_exit(pid)
    run_update()
    # A service manager (e.g. NSSM) may have started the panel again already.
    time.sleep(2)
    if _listening(host, port):
        return
    if IS_WINDOWS:
        # Its own console window, like starting it from the Startup shortcut.
        subprocess.Popen(cmd, cwd=cwd, creationflags=subprocess.CREATE_NEW_CONSOLE)
    else:
        log = open(os.path.join(BASE_DIR, "panel-output.log"), "a")
        subprocess.Popen(cmd, cwd=cwd, stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)


if __name__ == "__main__":
    main()
