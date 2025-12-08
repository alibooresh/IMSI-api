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

from models import db, Scan, ScanDetail, Observation

app = Flask(__name__)
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


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


@app.route("/imsi", methods=["GET"])
def get_imsi():
    """
    Query params:
      - page (int, default 0)
      - size (int, default 20)
      - db_path (optional) : absolute path to sqlite file (overrides default)
    Behavior:
      - reads table `observations` from sqlite
      - groups by imsi, returns one row per distinct imsi with a `count` field
      - supports pagination (OFFSET/LIMIT)
      - orders by last_seen (most recent) desc
    """
    try:
        # params
        page = max(int(request.args.get("page", 0)), 0)
        size = max(int(request.args.get("size", 20)), 1)
        db_path = request.args.get("db_path") or IMSI_SQLITE_PATH

        if not os.path.isabs(db_path):
            # if relative, resolve relative to BASE_DIR for safety
            db_path = os.path.join(BASE_DIR, db_path)

        if not os.path.exists(db_path):
            return jsonify({"error": "imsi sqlite file not found", "path": db_path}), 404

        conn = open_sqlite_db(db_path)
        cur = conn.cursor()

        # total distinct IMSI
        cur.execute("SELECT COUNT(DISTINCT imsi) as cnt FROM observations;")
        total_row = cur.fetchone()
        total = total_row["cnt"] if total_row and "cnt" in total_row.keys() else 0

        # Build grouped query:
        # - count occurrences
        # - pick representative values (min/max/any)
        # - order by last_seen desc (using MAX(stamp))
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
            WHERE imsi IS NOT NULL AND imsi != ''
            GROUP BY imsi
            ORDER BY last_seen DESC
            LIMIT ? OFFSET ?;
        """

        cur.execute(grouped_sql, (size, offset))
        rows = cur.fetchall()

        data = []
        for r in rows:
            # stamp values might be strings; keep as ISO if possible
            first_seen = r["first_seen"]
            last_seen = r["last_seen"]

            # try normalize (SQLite might store datetime as text); do not crash if format unexpected
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
                "first_seen": first_seen,
                "last_seen": last_seen,
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



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
