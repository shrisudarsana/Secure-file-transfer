"""
AI-Based Secure File Transfer System — Flask Dashboard
=======================================================
Runs the web dashboard on port 5002.
The socket server (server.py) runs separately on port 5545.

Start order:
    1. python server.py          (terminal 1)
    2. python app.py             (terminal 2)
    3. Open http://localhost:5002
"""

import os
import csv
import json
import socket
import datetime
import threading
from flask import Flask, render_template, request, jsonify, send_from_directory
import werkzeug.utils

import sys
import traceback
sys.path.insert(0, os.path.dirname(__file__))

DEBUG_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "debug_errors.log")

def log_error(msg):
    with open(DEBUG_LOG, "a") as f:
        f.write(f"[{datetime.datetime.now()}] {msg}\n")
        traceback.print_exc(file=f)
        f.write("-" * 40 + "\n")

from detector import predict as ai_predict

# ─── Configuration ────────────────────────────────────────────────────────────

BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
CLIENT_DIR      = os.path.join(BASE_DIR, "client_directory")
SERVER_DIR      = os.path.join(BASE_DIR, "server_directory")
LOG_FILE        = os.path.join(BASE_DIR, "logs", "transfer_log.csv")
PUBLIC_KEY_FILE = os.path.join(BASE_DIR, "public_key.pem")

LOG_HEADERS = ["timestamp", "filename", "size_kb", "direction",
               "ai_label", "confidence", "reason", "transfer_status"]

app = Flask(__name__, 
            static_folder=os.path.join(BASE_DIR, "static"),
            template_folder=os.path.join(BASE_DIR, "templates"))

# ─── Ensure directories + log file exist ──────────────────────────────────────

os.makedirs(CLIENT_DIR, exist_ok=True)
os.makedirs(SERVER_DIR, exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)

if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(LOG_HEADERS)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def write_log(filename, size_kb, direction, ai_label, confidence, reason, transfer_status):
    """Append a row to the transfer log CSV."""
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            filename,
            round(size_kb, 2),
            direction,
            ai_label,
            f"{confidence}%",
            reason,
            transfer_status,
        ])


def _build_reason(features: dict, filename: str) -> str:
    """Generate a human-readable reason string for the UI."""
    reasons = []
    if features["ext_risk"] == 2:
        # Robustly get extension even for .exe or path/to/.bat
        ext = os.path.splitext(filename)[1]
        if not ext and filename.startswith('.'):
            ext = filename
        reasons.append(f"High-risk file extension ({ext})")
    elif features["ext_risk"] == 1:
        reasons.append("Medium-risk compressed archive")
    return ", ".join(reasons) if reasons else "None"


def read_logs(limit=50):
    """Return the last `limit` rows of the log as a list of dicts."""
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    return rows[-limit:][::-1]   # newest first


def do_socket_upload(filepath, filename):
    """
    Perform the actual secure socket upload using the existing client.py protocol.
    Returns (success: bool, message: str)
    """
    try:
        # Import client module components
        from client import Client

        client = Client()
        print(f"[DASHBOARD] Connecting to socket server at 127.0.0.1:5545...", flush=True)
        client.initiate_connection()
        print(f"[DASHBOARD] Socket connection established.", flush=True)

        with open(PUBLIC_KEY_FILE, "rb") as f:
            public_key = f.read()

        session_key = client.server_authentication(public_key)
        session = client.bytes_to_int(session_key)
        k1 = client.int_to_bytes(session + 2)
        k2 = client.int_to_bytes(session + 5)
        k3 = client.int_to_bytes(session + 7)
        k4 = client.int_to_bytes(session + 9)
        client.set_keys(k1, k2, k3, k4)

        # Send upload command
        seqA, seqB = client.send_seqA_receive_seqB()
        client.send_command("Upload,", seqA + 1, seqB + 1, k1, k2, filepath)

        with open(filepath, "rb") as f:
            data = f.read()
        client.send_data(data, seqA + 2, seqB + 2, k1, k2)
        client.close_connection()
        return True, "Transfer successful"

    except ConnectionRefusedError:
        log_error("Connection refused in do_socket_upload")
        return False, "Socket server not running (start server.py first)"
    except Exception as e:
        log_error(f"Error in do_socket_upload: {str(e)}")
        return False, f"Transfer error: {str(e)}"


def do_socket_download(filename):
    """
    Perform the actual secure socket download using the existing client.py protocol.
    Returns (success: bool, message: str)
    """
    try:
        from client import Client

        client = Client()
        client.initiate_connection()

        with open(PUBLIC_KEY_FILE, "rb") as f:
            public_key = f.read()

        session_key = client.server_authentication(public_key)
        session = client.bytes_to_int(session_key)
        k1 = client.int_to_bytes(session + 2)
        k2 = client.int_to_bytes(session + 5)
        k3 = client.int_to_bytes(session + 7)
        k4 = client.int_to_bytes(session + 9)
        client.set_keys(k1, k2, k3, k4)

        seqA, seqB = client.send_seqA_receive_seqB()
        client.send_command("Download,", seqA + 1, seqB + 1, k1, k2, filename)
        file_data = client.receive_data(seqA + 2, seqB + 2, k3, k4)

        save_path = os.path.join(CLIENT_DIR, filename)
        with open(save_path, "wb") as f:
            f.write(file_data)

        client.close_connection()
        return True, f"Downloaded to client_directory/{filename}"

    except ConnectionRefusedError:
        log_error("Connection refused in do_socket_download")
        return False, "Socket server not running (start server.py first)"
    except Exception as e:
        log_error(f"Error in do_socket_download: {str(e)}")
        return False, f"Download error: {str(e)}"


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Main dashboard page."""
    client_files = []
    if os.path.isdir(CLIENT_DIR):
        for fname in os.listdir(CLIENT_DIR):
            fpath = os.path.join(CLIENT_DIR, fname)
            if os.path.isfile(fpath):
                client_files.append({
                    "name": fname,
                    "size_kb": round(os.path.getsize(fpath) / 1024, 1)
                })
    return render_template("index.html", client_files=client_files)


# ─── Web File Management Routes ────────────────────────────────────

@app.route("/api/web-upload", methods=["POST"])
def web_upload():
    """Upload a file from the browser to the CLIENT_DIR."""
    if 'file' not in request.files:
        return jsonify({"success": False, "message": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"success": False, "message": "No selected file"}), 400

    filename = werkzeug.utils.secure_filename(file.filename)
    save_path = os.path.join(CLIENT_DIR, filename)
    file.save(save_path)
    
    return jsonify({
        "success": True, 
        "message": f"Successfully uploaded {filename} to client directory."
    })

@app.route("/api/web-download/<dir_type>/<filename>", methods=["GET"])
def web_download(dir_type, filename):
    """Download a file from either CLIENT_DIR or SERVER_DIR to the browser."""
    directory = CLIENT_DIR if dir_type == "client" else SERVER_DIR
    if not os.path.exists(os.path.join(directory, filename)):
        return "File not found", 404
    return send_from_directory(directory, filename, as_attachment=True)



@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    Run AI analysis on a file before transfer.
    Body: { "filename": str, "file_size": int (bytes), "direction": "upload"|"download" }
    Returns: { "label", "confidence", "reason", "features" }
    """
    body = request.get_json(force=True)
    filename  = body.get("filename", "")
    file_size = int(body.get("file_size", 0))
    direction = body.get("direction", "upload")

    if not filename:
        return jsonify({"error": "filename is required"}), 400

    result = ai_predict(filename, file_size)
    result["filename"] = filename
    result["direction"] = direction
    return jsonify(result)


@app.route("/api/transfer", methods=["POST"])
def transfer_file():
    print("\n>>> [API] /api/transfer request received", flush=True)
    """
    Execute the secure socket transfer after AI approval.
    Body: { "filename": str, "direction": "upload"|"download", "force": bool }
    Returns: { "success": bool, "message": str, "ai_result": {...} }
    """
    body = request.get_json(force=True)
    filename  = body.get("filename", "")
    direction = body.get("direction", "upload")
    force     = body.get("force", False)   # allow SUSPICIOUS transfer if user overrides

    if not filename:
        return jsonify({"error": "filename is required"}), 400

    # Determine file path and size
    if direction == "upload":
        filepath = os.path.join(CLIENT_DIR, filename)
        if not os.path.isfile(filepath):
            return jsonify({"error": f"File not found: {filename}"}), 404
        file_size = os.path.getsize(filepath)
    else:
        # Check server_directory for file size before download
        filepath = os.path.join(SERVER_DIR, filename)
        file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
        filepath = None # Reset filepath as it's only used for local upload data

    # Run AI analysis
    ai_result = ai_predict(filename, file_size)
    size_kb   = file_size / 1024.0

    # Block SUSPICIOUS unless force=True
    if ai_result["label"] == "SUSPICIOUS" and not force:
        write_log(filename, size_kb, direction,
                  ai_result["label"], ai_result["confidence"],
                  ai_result["reason"], "BLOCKED")
        return jsonify({
            "success": False,
            "message": "Transfer BLOCKED by AI — file flagged as SUSPICIOUS",
            "ai_result": ai_result,
            "blocked": True
        })

    # Perform actual socket transfer
    if force:
        print(f"[APP] Force transfer authorized for: {filename}")
    
    if direction == "upload":
        success, msg = do_socket_upload(filepath, filename)
    else:
        success, msg = do_socket_download(filename)

    if success:
        transfer_status = "SUCCESS" if ai_result["label"] == "SAFE" else "SUSPICIOUS-ALLOWED"
    else:
        transfer_status = "FAILED"

    write_log(filename, size_kb, direction,
              ai_result["label"], ai_result["confidence"],
              ai_result["reason"], transfer_status)

    return jsonify({
        "success": success,
        "message": msg,
        "ai_result": ai_result,
        "blocked": False
    })


@app.route("/api/logs", methods=["GET"])
def get_logs():
    """Return the last 50 transfer log entries as JSON."""
    rows = read_logs(50)
    return jsonify(rows)


@app.route("/api/client-files", methods=["GET"])
def client_files():
    """List files in client_directory with their sizes."""
    files = []
    if os.path.isdir(CLIENT_DIR):
        for fname in os.listdir(CLIENT_DIR):
            fpath = os.path.join(CLIENT_DIR, fname)
            if os.path.isfile(fpath):
                files.append({
                    "name": fname,
                    "size_bytes": os.path.getsize(fpath),
                    "size_kb": round(os.path.getsize(fpath) / 1024, 1)
                })
    return jsonify(files)


@app.route("/api/server-files", methods=["GET"])
def server_files():
    """List files in server_directory."""
    files = []
    if os.path.isdir(SERVER_DIR):
        for fname in os.listdir(SERVER_DIR):
            fpath = os.path.join(SERVER_DIR, fname)
            if os.path.isfile(fpath):
                files.append({
                    "name": fname,
                    "size_kb": round(os.path.getsize(fpath) / 1024, 1)
                })
    return jsonify(files)


# ─── Run ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  AI-Based Secure File Transfer System")
    print("  Dashboard -> http://localhost:5002")
    print("  Socket Server must run on port 5545")
    print("=" * 55)
    app.run(debug=True, port=5002, use_reloader=False)
