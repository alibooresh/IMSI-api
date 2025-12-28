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
from sqlalchemy import Column, Integer, String, DateTime
import signal
import time


from models import db, Scan, ScanDetail, Observation
def stop_process(pid: int, timeout=5) -> bool:
    if not pid:
        return False

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return False

    # wait graceful
    for _ in range(timeout * 10):
        if not is_process_alive(pid):
            return True
        time.sleep(0.1)

    # force kill
    try:
        os.kill(pid, signal.SIGKILL)
        return True
    except Exception:
        return False

class ScriptRun(db.Model):
    __tablename__ = "script_runs"

    id = Column(Integer, primary_key=True)
    script_id = Column(Integer, nullable=False)
    pid = Column(Integer)
    status = Column(String(20))  # running | stopped | failed
    started_at = Column(DateTime, nullable=False)
    stopped_at = Column(DateTime)
    exit_code = Column(Integer)

with app.app_context():
    db.create_all()
app = Flask(__name__)
CORS(app)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


SCRIPTS_JSON_PATH = os.path.join(BASE_DIR, "scripts.json")

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
def is_process_alive(pid: int) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False

def get_script_by_id(script_id: int):
    scripts = load_scripts_config()

    for _, cfg in scripts.items():
        if cfg.get("id") == script_id:
            return cfg

    return None

def load_scripts_config():
    if not os.path.exists(SCRIPTS_JSON_PATH):
        raise FileNotFoundError("scripts.json not found")

    with open(SCRIPTS_JSON_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

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

@app.route("/scripts/status", methods=["GET"])
def script_status():
    script_id = request.args.get("scriptId", type=int)
    run_id    = request.args.get("runId", type=int)

    if not script_id and not run_id:
        return jsonify({"error": "scriptId or runId is required"}), 400

    # ---- get latest run ----
    query = ScriptRun.query

    if run_id:
        run = query.filter_by(id=run_id).first()
    else:
        run = query.filter_by(script_id=script_id)\
                   .order_by(ScriptRun.started_at.desc())\
                   .first()

    if not run:
        return jsonify({"status": "never_run"})

    alive = is_process_alive(run.pid)

    # ---- sync status if needed ----
    if run.status == "running" and not alive:
        run.status = "stopped"
        run.stopped_at = datetime.utcnow()
        db.session.commit()

    return jsonify({
        "runId": run.id,
        "scriptId": run.script_id,
        "status": run.status,
        "pid": run.pid,
        "startedAt": run.started_at.isoformat(),
        "stoppedAt": run.stopped_at.isoformat() if run.stopped_at else None,
        "isAlive": alive
    })

# --------------------------
# Run script
# --------------------------
@app.route("/scripts/run", methods=["POST"])
def run_script():
    data = request.get_json(force=True)

    script_id = data.get("scriptId")
    password  = data.get("password")

    if not script_id:
        return jsonify({"error": "scriptId is required"}), 400

    if not password:
        return jsonify({"error": "password is required"}), 400

    script_cfg = get_script_by_id(script_id)
    if not script_cfg:
        return jsonify({"error": "script not found"}), 404

    script_file = script_cfg["file"]
    work_dir    = script_cfg["path"]
    sqlite_file = script_cfg["dbName"]
    args        = shlex.split(script_cfg.get("args", ""))

    if not is_safe_python_file(script_file):
        return jsonify({"error": "invalid scriptFile"}), 400

    if not os.path.isabs(work_dir) or not os.path.isdir(work_dir):
        return jsonify({"error": "invalid workDir"}), 400

    script_path = os.path.join(work_dir, script_file)
    if not os.path.isfile(script_path):
        return jsonify({"error": "script file not found"}), 404

    with LOCK:
        if script_id in RUNNING_SCRIPTS:
            return jsonify({"error": "script already running"}), 409

    # ---------- DB: insert RUNNING ----------
    run = ScriptRun(
        script_id=script_id,
        status="running",
        started_at=datetime.utcnow()
    )
    db.session.add(run)
    db.session.commit()  # run.id ساخته می‌شه

    command = build_command(script_file, args, sqlite_file)

    try:
        process = subprocess.Popen(
            command,
            cwd=work_dir,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        process.stdin.write(password + "\n")
        process.stdin.flush()

    except Exception as e:
        run.status = "failed"
        db.session.commit()
        return jsonify({"error": "failed to start script"}), 500

    # ---------- DB: save PID ----------
    run.pid = process.pid
    db.session.commit()

    with LOCK:
        RUNNING_SCRIPTS[script_id] = {
            "process": process,
            "runId": run.id,
            "pid": process.pid
        }

    return jsonify({
        "runId": run.id,
        "scriptId": script_id,
        "status": "running",
        "pid": process.pid
    })

@app.route("/imsi", methods=["GET"])
def get_imsi():
    try:
        # ---------------- params ----------------
        page = max(int(request.args.get("page", 0)), 0)
        size = max(int(request.args.get("size", 20)), 1)

        script_id = request.args.get("scriptId", type=int)
        db_path = request.args.get("db_path")

        # ---------------- resolve sqlite path ----------------
        if script_id:
            script_cfg = get_script_by_id(script_id)
            if not script_cfg:
                return jsonify({"error": "script not found"}), 404

            sqlite_file = script_cfg.get("dbName")
            work_dir = script_cfg.get("path")

            if not sqlite_file or not work_dir:
                return jsonify({"error": "script db config invalid"}), 500

            db_path = os.path.join(work_dir, sqlite_file)

        else:
            db_path = db_path or IMSI_SQLITE_PATH
            if not os.path.isabs(db_path):
                db_path = os.path.join(BASE_DIR, db_path)

        if not os.path.exists(db_path):
            return jsonify({
                "error": "imsi sqlite file not found",
                "path": db_path
            }), 404

        # ---------------- filters ----------------
        imsi_filter     = request.args.get("imsi")
        operator_filter = request.args.get("operator")
        country_filter  = request.args.get("country")
        brand_filter    = request.args.get("brand")

        conn = open_sqlite_db(db_path)
        cur = conn.cursor()

        # ---------------- where clause ----------------
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

        # ---------------- total count ----------------
        cur.execute(
            f"SELECT COUNT(DISTINCT imsi) as cnt FROM observations WHERE {where_sql}",
            params
        )
        total = cur.fetchone()["cnt"]

        # ---------------- pagination query ----------------
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

        # ---------------- map result ----------------
        def _iso(v):
            if v is None:
                return None
            if isinstance(v, str):
                return v
            try:
                return datetime.fromisoformat(v).isoformat()
            except Exception:
                try:
                    return datetime.utcfromtimestamp(float(v)).isoformat()
                except Exception:
                    return str(v)

        data = []
        for r in rows:
            data.append({
                "imsi": r["imsi"],
                "count": int(r["count"] or 0),
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
            "scriptId": script_id,
            "dbPath": db_path,
            "total": total,
            "page": page,
            "size": size,
            "data": data
        })

    except Exception as e:
        return jsonify({
            "error": "internal server error",
            "details": str(e),
            "trace": traceback.format_exc()
        }), 500

@app.route("/script-list", methods=["GET"])
def script_list():
    """
    Returns:
    [
      { "id": 1, "name": "simple-imsi-catcher" },
      { "id": 2, "name": "pro-imsi-catcher" }
    ]
    """
    try:
        scripts = load_scripts_config()

        result = []
        for name, cfg in scripts.items():
            result.append({
                "id": cfg.get("id"),
                "name": name
            })

        return jsonify(result)

    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 500

    except Exception as e:
        return jsonify({
            "error": "failed to load scripts",
            "details": str(e)
        }), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
