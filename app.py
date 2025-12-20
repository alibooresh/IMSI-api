from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import os
import json
import traceback
import threading
from datetime import datetime
from collections import defaultdict
import sqlite3
import shlex

from models import db, Scan, ScanDetail, Observation

app = Flask(__name__)
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SCRIPT_CONFIG = {
    "imsi":  "--sniff",
    "imsi2": "--sniff -a",
    "imsi3": "--sniff --port 4729",
    "imsi4": "--sniff --port 4730"
}

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(BASE_DIR, 'sherlock_scans.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

with app.app_context():
    db.create_all()


IMSI_SQLITE_PATH = os.path.join(BASE_DIR, "imsi.sqlite")

# --------------------------
# helper: safe open sqlite and run query
# --------------------------
def open_sqlite_db(path):
    
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn

# --------------------------
# In-memory process registry
# --------------------------
RUNNING_SCRIPTS = {}
LOCK = threading.Lock()

# --------------------------
# Helpers
# --------------------------
def is_safe_python_file(filename: str) -> bool:
    return filename.endswith(".py") and "/" not in filename and "\\" not in filename


def build_command(script_file, args, sqlite_file):
    return [
        "sudo",
        "-S",
        "python3",
        script_file,
        *args,
        "--sqlite",
        sqlite_file
    ]


# --------------------------
# Run script
# --------------------------
@app.route("/scripts/run", methods=["POST"])
def run_script():
    data = request.get_json(force=True)

    script_id   = data.get("scriptId")
    script_file = data.get("scriptFile")
    work_dir    = data.get("workDir")
    sqlite_file = data.get("sqliteFile")
    args        = data.get("args", [])
    password    = data.get("password")

    # ---- validation ----
    if not script_id:
        return jsonify({"error": "scriptId is required"}), 400

    if not is_safe_python_file(script_file):
        return jsonify({"error": "invalid scriptFile"}), 400

    if not work_dir or not os.path.isabs(work_dir):
        return jsonify({"error": "workDir must be absolute path"}), 400

    if not os.path.isdir(work_dir):
        return jsonify({"error": "workDir does not exist"}), 400

    script_path = os.path.join(work_dir, script_file)
    if not os.path.isfile(script_path):
        return jsonify({"error": "script file not found", "path": script_path}), 404

    if not sqlite_file:
        return jsonify({"error": "sqliteFile is required"}), 400

    if not isinstance(args, list):
        return jsonify({"error": "args must be an array"}), 400

    with LOCK:
        if script_id in RUNNING_SCRIPTS:
            return jsonify({"error": "script already running"}), 409

    command = build_command(script_file, args, sqlite_file)
    try:
        print(command)
        process = subprocess.Popen(
            command,
            cwd=work_dir,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        send sudo password
        process.stdin.write(password + "\n")
        process.stdin.flush()

    except Exception as e:
        return jsonify({"error": "failed to start script", "details": str(e)}), 500

    with LOCK:
        RUNNING_SCRIPTS[script_id] = {
            "process": "process",
            "pid": "process.pid",
            "status": "running",
            "startedAt": datetime.utcnow().isoformat(),
            "workDir": work_dir,
            "script": script_file,
            "sqlite": sqlite_file
        }

    return jsonify({
        "scriptId": script_id,
        "status": "running",
        "pid": "process.pid"
    })


# --------------------------
# Stop script
# --------------------------
@app.route("/scripts/stop", methods=["POST"])
def stop_script():
    data = request.get_json(force=True)
    script_id = data.get("scriptId")

    if not script_id:
        return jsonify({"error": "scriptId is required"}), 400

    with LOCK:
        entry = RUNNING_SCRIPTS.get(script_id)

    if not entry:
        return jsonify({"error": "script not running"}), 404

    process = entry["process"]

    try:
        process.terminate()
        process.wait(timeout=5)
    except Exception:
        process.kill()

    with LOCK:
        entry["status"] = "stopped"
        entry["stoppedAt"] = datetime.utcnow().isoformat()
        RUNNING_SCRIPTS.pop(script_id, None)

    return jsonify({
        "scriptId": script_id,
        "status": "stopped"
    })


# --------------------------
# Script status
# --------------------------
@app.route("/scripts/status/<script_id>", methods=["GET"])
def script_status(script_id):
    with LOCK:
        entry = RUNNING_SCRIPTS.get(script_id)

    if not entry:
        return jsonify({
            "scriptId": script_id,
            "status": "not_running"
        })

    process = entry["process"]

    if process.poll() is not None:
        with LOCK:
            entry["status"] = "exited"
            entry["exitCode"] = process.returncode
            RUNNING_SCRIPTS.pop(script_id, None)

        return jsonify({
            "scriptId": script_id,
            "status": "exited",
            "exitCode": process.returncode
        })

    return jsonify({
        "scriptId": script_id,
        "status": "running",
        "pid": entry["pid"],
        "startedAt": entry["startedAt"],
        "workDir": entry["workDir"],
        "script": entry["script"],
        "sqlite": entry["sqlite"]
    })


# --------------------------
# List running scripts (optional but useful)
# --------------------------
@app.route("/scripts", methods=["GET"])
def list_scripts():
    with LOCK:
        result = {
            k: {
                "pid": v["pid"],
                "status": v["status"],
                "startedAt": v["startedAt"]
            }
            for k, v in RUNNING_SCRIPTS.items()
        }

    return jsonify(result)



@app.route("/imsi", methods=["GET"])
def get_imsi():
    try:
        # params
        page = max(int(request.args.get("page", 0)), 0)
        size = max(int(request.args.get("size", 20)), 1)
        db_path = request.args.get("db_path") or IMSI_SQLITE_PATH

        if not os.path.isabs(db_path):
            db_path = os.path.join(BASE_DIR, db_path)
        if not os.path.exists(db_path):
            return jsonify({"error": "imsi sqlite file not found", "path": db_path}), 404

        # filters
        imsi_filter = request.args.get("imsi")
        operator_filter = request.args.get("operator")
        country_filter = request.args.get("country")
        brand_filter = request.args.get("brand")

        conn = open_sqlite_db(db_path)
        cur = conn.cursor()

        # Build WHERE clause dynamically
        where_clauses = ["imsi IS NOT NULL AND imsi != ''"]
        params = []

        if imsi_filter:
            where_clauses.append("imsi LIKE ?")
            params.append(f"%{imsi_filter}%")
        if operator_filter:
            where_clauses.append("imsioperator LIKE ?")
            params.append(f"%{operator_filter}%")
        if country_filter:
            where_clauses.append("imsicountry LIKE ?")
            params.append(f"%{country_filter}%")
        if brand_filter:
            where_clauses.append("imsibrand LIKE ?")
            params.append(f"%{brand_filter}%")

        where_sql = " AND ".join(where_clauses)

        # total distinct IMSI with filters
        cur.execute(f"SELECT COUNT(DISTINCT imsi) as cnt FROM observations WHERE {where_sql}", params)
        total_row = cur.fetchone()
        total = total_row["cnt"] if total_row and "cnt" in total_row.keys() else 0

        # pagination
        offset = page * size
        grouped_sql = f"""
            SELECT
                imsi,
                COUNT(imsi) AS count,
                MIN(stamp) AS first_seen,
                MAX(stamp) AS last_seen,
                MIN(tmsi1) AS tmsi1,
                MIN(tmsi2) AS tmsi2,
                MIN(imsicountry) AS country,
                MIN(imsibrand) AS brand,
                MIN(imsioperator) AS operator,
                MIN(mcc) AS mcc,
                MIN(mnc) AS mnc,
                MIN(lac) AS lac,
                MIN(cell) AS cell
            FROM observations
            WHERE {where_sql}
            GROUP BY imsi
            ORDER BY last_seen DESC
            LIMIT ? OFFSET ?;
        """
        cur.execute(grouped_sql, (*params, size, offset))
        rows = cur.fetchall()

        data = []
        for r in rows:
            def _iso(v):
                if v is None: return None
                if isinstance(v, str): return v
                try: return datetime.fromisoformat(v).isoformat()
                except: 
                    try: return datetime.utcfromtimestamp(float(v)).isoformat()
                    except: return str(v)

            data.append({
                "imsi": r["imsi"],
                "count": int(r["count"]) if r["count"] is not None else 0,
                "tmsi1": r["tmsi1"],
                "tmsi2": r["tmsi2"],
                "country": r["country"],
                "brand": r["brand"],
                "operator": r["operator"],
                "mcc": r["mcc"],
                "mnc": r["mnc"],
                "lac": r["lac"],
                "cellId": r["cell"],
                "first_seen": _iso(r["first_seen"]),
                "last_seen": _iso(r["last_seen"]),
            })

        conn.close()

        return jsonify({
            "total": total,
            "page": page,
            "size": size,
            "data": data
        })

    except Exception as e:
        return jsonify({"error": "internal server error", "details": str(e), "trace": traceback.format_exc()}), 500

# @app.route("/run/script", methods=["POST"])
# def run_script():
#     data = request.get_json()
#     print("RAW DATA:", data)
#     script_type = data.get("scriptType")
#     file_name   = data.get("filePath")   # فقط اسم فایل
#     password    = data.get("password")
#     work_dir    = data.get("workDir")

#     # ---- validation ----
#     if script_type not in SCRIPT_CONFIG:
#         return jsonify({"error": "Invalid scriptType"}), 400

#     # if not work_dir or not os.path.isabs(work_dir):
#     #     return jsonify({"error": "workDir must be an absolute path"}), 400

#     if not os.path.isdir(work_dir):
#         return jsonify({"error": "workDir does not exist"}), 400

#     if not file_name:
#         return jsonify({"error": "filePath (file name) is required"}), 400

#     script_path = os.path.join(work_dir, file_name)

#     if not os.path.isfile(script_path):
#         return jsonify({"error": "script file not found", "path": script_path}), 404

#     args = SCRIPT_CONFIG[script_type]

#     command = [
#         "sudo",
#         "-S",
#         "python3",
#         script_path,
#         *args.split(),
#         "--sqlite",
#         "imsi.sqlite"
#     ]

#     try:
#         process = subprocess.Popen(
#             command,
#             cwd=work_dir,                 
#             stdin=subprocess.PIPE,
#             stdout=subprocess.PIPE,
#             stderr=subprocess.STDOUT,
#             text=True,
#             bufsize=1
#         )

#         process.stdin.write(password + "\n")
#         process.stdin.flush()

#     except Exception as e:
#         return jsonify({"error": "failed to start process", "details": str(e)}), 500

#     return jsonify({
#         "status": "started",
#         "workDir": work_dir,
#         "script": script_path,
#         "command": " ".join(command)
#     })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
