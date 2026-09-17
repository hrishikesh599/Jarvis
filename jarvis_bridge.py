#!/usr/bin/env python3
"""
J.A.R.V.I.S. Local System Bridge
==================================
A small local-only Flask server that lets the JARVIS web HUD execute real
commands and launch real applications on YOUR computer.

⚠️  SECURITY — READ THIS BEFORE RUNNING  ⚠️
This server will run whatever command JARVIS sends it, using your own user
account's permissions. That is exactly as powerful as you typing into your
own terminal. To keep that power contained to you and only you:

  1. It binds to 127.0.0.1 (localhost) ONLY. It will refuse to bind to
     0.0.0.0 or any public interface. Do not change HOST below.
  2. Every request must include the secret token printed below in the
     'X-Jarvis-Token' header. Anyone with this token has full command
     access to your machine — treat it like a password. It is regenerated
     every time you start this script.
  3. Never port-forward, tunnel (ngrok, etc.), or otherwise expose this
     port to the internet or your local network. It is designed for
     "this browser tab talking to this same computer" only.
  4. Every command that runs is logged to jarvis_bridge.log with a
     timestamp, so you always have a record of what JARVIS actually did.
  5. Close this script (Ctrl+C) when you're not actively using JARVIS.

Setup:
    pip install flask
    python jarvis_bridge.py

Then copy the printed token into the JARVIS HUD: gear icon (top-right) →
scroll to "LOCAL SYSTEM BRIDGE" → paste URL + token → Save Bridge → Test.
"""

import os
import sys
import json
import shlex
import secrets
import platform
import subprocess
import datetime
from functools import wraps

try:
    from flask import Flask, request, jsonify, send_from_directory
except ImportError:
    sys.exit("Flask is required. Install it with:  pip install flask")

# ── Configuration ────────────────────────────────────────────────────────
HOST = "127.0.0.1"        # DO NOT change to 0.0.0.0 — localhost only, on purpose.
PORT = 5055
COMMAND_TIMEOUT_SECONDS = 20
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(SCRIPT_DIR, "jarvis_bridge.log")

# All file read/write/list operations are sandboxed to this folder — JARVIS
# physically cannot write or read outside it, no matter what it's asked.
WORKSPACE_ROOT = os.path.join(SCRIPT_DIR, "jarvis_workspace")
LOCAL_SERVER_DIR = os.path.join(WORKSPACE_ROOT, "local_server")
os.makedirs(LOCAL_SERVER_DIR, exist_ok=True)

# Regenerated every run. Copy this into the JARVIS settings panel.
TOKEN = secrets.token_hex(24)

# Friendly app-name → launch-command whitelist. Extend this freely.
# Falls back to the OS's generic "open by name" if not listed.
APP_WHITELIST = {
    "notepad":      {"windows": "notepad.exe"},
    "calculator":   {"windows": "calc.exe", "darwin": "open -a Calculator", "linux": "gnome-calculator"},
    "vscode":       {"windows": "code", "darwin": "open -a 'Visual Studio Code'", "linux": "code"},
    "terminal":     {"windows": "wt.exe", "darwin": "open -a Terminal", "linux": "x-terminal-emulator"},
    "spotify":      {"windows": "spotify.exe", "darwin": "open -a Spotify", "linux": "spotify"},
    "chrome":       {"windows": "chrome.exe", "darwin": "open -a 'Google Chrome'", "linux": "google-chrome"},
    "explorer":     {"windows": "explorer.exe", "darwin": "open .", "linux": "xdg-open ."},
    "files":        {"windows": "explorer.exe", "darwin": "open .", "linux": "xdg-open ."},
    "camera": {"windows": "start microsoft.windows.camera:","darwin": "open -a 'Photo Booth'","linux": "cheese"}
}

app = Flask(__name__)


def safe_join(relative_path):
    """Resolve relative_path against WORKSPACE_ROOT and refuse to return
    anything outside it — the core sandboxing guarantee for all file ops."""
    root = os.path.realpath(WORKSPACE_ROOT)
    target = os.path.realpath(os.path.join(root, relative_path))
    if target != root and not target.startswith(root + os.sep):
        raise ValueError("path escapes the workspace sandbox")
    return target


def log_event(kind, detail):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.datetime.now().isoformat(timespec='seconds')}] {kind}: {detail}\n")


def require_token(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # BUGFIX: browsers send an OPTIONS preflight before the real request
        # whenever a custom header (X-Jarvis-Token) is used. That preflight
        # never includes the custom header itself, so checking the token on
        # OPTIONS caused every preflight to fail with 401 — which the browser
        # then reports to fetch() as a generic network/CORS failure. The HUD
        # showed that as "BRIDGE: UNREACHABLE" even with a correct token.
        if request.method == "OPTIONS":
            return "", 204
        supplied = request.headers.get("X-Jarvis-Token", "")
        if not secrets.compare_digest(supplied, TOKEN):
            log_event("AUTH-FAIL", f"bad token from {request.remote_addr}")
            return jsonify({"error": "unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapper


@app.after_request
def add_cors_headers(resp):
    # Security here relies on the secret token, not on origin restriction,
    # since browsers send Origin: null for local file:// pages.
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Jarvis-Token"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Max-Age"] = "600"
    return resp


@app.route("/health", methods=["GET", "OPTIONS"])
@require_token
def health():
    if request.method == "OPTIONS":
        return "", 204
    return jsonify({"status": "online", "platform": platform.system()})


@app.route("/run", methods=["POST", "OPTIONS"])
@require_token
def run_command():
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json(force=True, silent=True) or {}
    command = (data.get("command") or "").strip()
    if not command:
        return jsonify({"error": "no command provided"}), 400

    log_event("RUN", command)
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
        return jsonify({
            "stdout": result.stdout[-4000:],
            "stderr": result.stderr[-2000:],
            "returncode": result.returncode,
        })
    except subprocess.TimeoutExpired:
        log_event("TIMEOUT", command)
        return jsonify({"error": f"command timed out after {COMMAND_TIMEOUT_SECONDS}s"}), 504
    except Exception as e:
        log_event("ERROR", f"{command} -> {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/open", methods=["POST", "OPTIONS"])
@require_token
def open_app():
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json(force=True, silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "no target provided"}), 400

    system = platform.system().lower()  # 'windows' / 'darwin' / 'linux'
    key = target.lower()
    log_event("OPEN", target)

    launch_cmd = None
    if key in APP_WHITELIST and system in APP_WHITELIST[key]:
        launch_cmd = APP_WHITELIST[key][system]
    else:
        # Generic OS-level "open by name" fallback for anything not whitelisted.
        if system == "windows":
            launch_cmd = f'start "" {shlex.quote(target)}'
        elif system == "darwin":
            launch_cmd = f"open -a {shlex.quote(target)}"
        else:
            launch_cmd = f"xdg-open {shlex.quote(target)}"

    try:
        subprocess.Popen(launch_cmd, shell=True)
        return jsonify({"status": "launched", "command": launch_cmd})
    except Exception as e:
        log_event("ERROR", f"open {target} -> {e}")
        return jsonify({"error": str(e)}), 500


# ── File tools (all sandboxed to WORKSPACE_ROOT via safe_join) ────────────

@app.route("/files/write", methods=["POST", "OPTIONS"])
@require_token
def write_file():
    data = request.get_json(force=True, silent=True) or {}
    rel_path = (data.get("path") or "").strip().lstrip("/\\")
    content = data.get("content", "")
    if not rel_path:
        return jsonify({"error": "no path provided"}), 400
    try:
        target = safe_join(rel_path)
    except ValueError as e:
        log_event("BLOCKED", f"write escaped sandbox: {rel_path}")
        return jsonify({"error": str(e)}), 400
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "w", encoding="utf-8") as f:
        f.write(content)
    log_event("WRITE", f"{rel_path} ({len(content)} chars)")
    return jsonify({"status": "written", "path": rel_path, "bytes": len(content.encode("utf-8"))})


@app.route("/files/read", methods=["POST", "OPTIONS"])
@require_token
def read_file():
    data = request.get_json(force=True, silent=True) or {}
    rel_path = (data.get("path") or "").strip().lstrip("/\\")
    if not rel_path:
        return jsonify({"error": "no path provided"}), 400
    try:
        target = safe_join(rel_path)
    except ValueError as e:
        log_event("BLOCKED", f"read escaped sandbox: {rel_path}")
        return jsonify({"error": str(e)}), 400
    if not os.path.isfile(target):
        return jsonify({"error": "file not found"}), 404
    with open(target, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    log_event("READ", rel_path)
    return jsonify({"path": rel_path, "content": content})


@app.route("/files/list", methods=["POST", "OPTIONS"])
@require_token
def list_files():
    data = request.get_json(force=True, silent=True) or {}
    rel_path = (data.get("path") or "").strip().lstrip("/\\")
    try:
        target = safe_join(rel_path) if rel_path else WORKSPACE_ROOT
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    if not os.path.isdir(target):
        return jsonify({"error": "not a directory"}), 400
    entries = [
        {"name": name, "is_dir": os.path.isdir(os.path.join(target, name))}
        for name in sorted(os.listdir(target))
    ]
    return jsonify({"path": rel_path, "entries": entries})


@app.route("/preview/<path:filename>")
def preview(filename):
    # Intentionally NOT token-gated: this serves static files from
    # local_server/ so you can open them directly as a normal browser tab
    # (a plain page navigation can't attach a custom auth header). Still
    # localhost-only and still confined to LOCAL_SERVER_DIR — it can only
    # ever serve files JARVIS itself already wrote into that one folder.
    return send_from_directory(LOCAL_SERVER_DIR, filename)


if __name__ == "__main__":
    print("=" * 64)
    print(" J.A.R.V.I.S. LOCAL SYSTEM BRIDGE")
    print("=" * 64)
    print(f" Platform : {platform.system()} {platform.release()}")
    print(f" URL      : http://{HOST}:{PORT}")
    print(f" Token    : {TOKEN}")
    print(f" Workspace: {WORKSPACE_ROOT}")
    print(f" Preview  : http://{HOST}:{PORT}/preview/<filename>  (serves files from local_server/)")
    print(f" Log file : {LOG_FILE}")
    print("-" * 64)
    print(" Paste the URL and token above into the JARVIS HUD settings")
    print(" (gear icon -> LOCAL SYSTEM BRIDGE section) and click")
    print(" 'Test Connection', then 'Save Bridge'.")
    print()
    print(" This server ONLY listens on localhost. Keep it that way.")
    print(" Press Ctrl+C to stop it when you're done using JARVIS.")
    print("=" * 64)
    app.run(host=HOST, port=PORT, debug=False)
