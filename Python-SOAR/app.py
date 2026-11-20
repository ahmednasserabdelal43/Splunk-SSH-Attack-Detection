
import os
import sqlite3
import ipaddress
import logging
from datetime import datetime, timezone

import requests
from flask import Flask, request, jsonify, redirect, url_for, render_template_string

app = Flask(__name__)

# =====================================
# Configuration
# =====================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "soar.db")

VT_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger("Python-SOAR")


# =====================================
# Database
# =====================================

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():

    with get_db() as db:

        db.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                alert_name TEXT,
                src_ip TEXT,
                malicious INTEGER DEFAULT 0,
                suspicious INTEGER DEFAULT 0,
                verdict TEXT,
                decision TEXT,
                status TEXT,
                response_action TEXT,
                failed_attempts INTEGER DEFAULT 0,
                targeted_users TEXT,
                unique_users INTEGER DEFAULT 0
            )
        """)

        # Migrate existing database safely
        existing_columns = {
            row["name"]
            for row in db.execute(
                "PRAGMA table_info(incidents)"
            ).fetchall()
        }

        new_columns = {
            "failed_attempts": "INTEGER DEFAULT 0",
            "targeted_users": "TEXT",
            "unique_users": "INTEGER DEFAULT 0"
        }

        for column, column_type in new_columns.items():
            if column not in existing_columns:
                db.execute(
                    f"ALTER TABLE incidents ADD COLUMN {column} {column_type}"
                )

    logger.info("Database initialized successfully")


# =====================================
# IP Validation
# =====================================

def validate_ip(ip):

    try:
        ipaddress.ip_address(ip)
        return True

    except (ValueError, TypeError):
        return False


# =====================================
# VirusTotal Enrichment
# =====================================

def check_virustotal(ip):

    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        return {"error": "VirusTotal API key is missing"}

    try:

        response = requests.get(
            VT_API_URL + ip,
            headers={"x-apikey": api_key},
            timeout=20
        )

        if response.status_code == 401:
            return {"error": "Invalid API key"}

        if response.status_code == 429:
            return {"error": "API rate limit reached"}

        response.raise_for_status()

        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious > 0:
            verdict = "Malicious"

        elif suspicious > 0:
            verdict = "Suspicious"

        else:
            verdict = "Benign_or_Unknown"

        return {
            "verdict": verdict,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0)
        }

    except requests.exceptions.RequestException as error:

        logger.error("VirusTotal connection error: %s", error)

        return {"error": "VirusTotal connection failed"}

    except (KeyError, TypeError, ValueError):

        return {"error": "Invalid VirusTotal response"}


# =====================================
# Helpers
# =====================================

def normalize_users(users):

    if users is None:
        return "Unknown"

    if isinstance(users, (list, tuple, set)):
        return ", ".join(str(user) for user in users)

    return str(users)


def safe_int(value, default=0):

    try:
        return int(value or 0)

    except (ValueError, TypeError):
        return default


# =====================================
# Home
# =====================================

@app.route("/")
def home():

    return jsonify({
        "service": "Python SOAR",
        "status": "running",
        "version": "2.0",
        "dashboard": "/approvals",
        "webhook": "/webhook"
    })


# =====================================
# Webhook / Event Ingestion
# =====================================

@app.route("/webhook", methods=["POST"])
def receive_alert():

    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return jsonify({"error": "Invalid JSON"}), 400

    # Support direct events and Splunk webhook format
    result = payload.get("result", payload)

    if not isinstance(result, dict):
        return jsonify({"error": "Invalid event result"}), 400

    # Extract source IP
    src_ip = (
        result.get("src_ip")
        or result.get("source_ip")
    )

    if not validate_ip(src_ip):
        return jsonify({"error": "Invalid IP address"}), 400

    # Extract alert information
    alert_name = (
        payload.get("search_name")
        or result.get("alert_name")
        or "SSH Security Detection"
    )

    failed_attempts = safe_int(
        result.get("failed_attempts", result.get("failures", 0))
    )

    unique_users = safe_int(
        result.get("unique_users", 0)
    )

    targeted_users = normalize_users(
        result.get("targeted_users")
        or result.get("target_user")
        or result.get("users")
        or result.get("user")
    )

    logger.info(
        "New event | Alert: %s | IP: %s",
        alert_name,
        src_ip
    )

    # =================================
    # Threat Intelligence Enrichment
    # =================================

    address = ipaddress.ip_address(src_ip)

    if address.is_global:

        vt_result = check_virustotal(src_ip)

    else:

        logger.info(
            "Private IP detected. VirusTotal enrichment skipped: %s",
            src_ip
        )

        vt_result = {
            "verdict": "Private_IP_Not_Checked",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0
        }

    verdict = vt_result.get(
        "verdict",
        "Enrichment_Failed"
    )

    malicious = safe_int(vt_result.get("malicious"))
    suspicious = safe_int(vt_result.get("suspicious"))

    # =================================
    # Risk Classification
    # =================================

    if (
        failed_attempts >= 3
        or unique_users >= 2
        or verdict == "Malicious"
    ):

        decision = "High Risk"
        status = "pending_approval"
        action = "Waiting for human approval"

    elif verdict == "Suspicious":

        decision = "Medium Risk"
        status = "pending_approval"
        action = "Waiting for human review"

    else:

        decision = "Low or Unknown Risk"
        status = "monitored"
        action = "Monitoring only"

    # =================================
    # Save Incident
    # =================================

    timestamp = datetime.now(timezone.utc).isoformat()

    with get_db() as db:

        cursor = db.execute("""
            INSERT INTO incidents (
                timestamp,
                alert_name,
                src_ip,
                malicious,
                suspicious,
                verdict,
                decision,
                status,
                response_action,
                failed_attempts,
                targeted_users,
                unique_users
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp,
            alert_name,
            src_ip,
            malicious,
            suspicious,
            verdict,
            decision,
            status,
            action,
            failed_attempts,
            targeted_users,
            unique_users
        ))

        incident_id = cursor.lastrowid

    logger.info(
        "Incident #%s | %s | %s",
        incident_id,
        decision,
        status
    )

    return jsonify({
        "status": "processed",
        "incident_id": incident_id,
        "alert_name": alert_name,
        "src_ip": src_ip,
        "failed_attempts": failed_attempts,
        "unique_users": unique_users,
        "targeted_users": targeted_users,
        "threat_intelligence": vt_result,
        "decision": decision,
        "approval_status": status,
        "dashboard": "/approvals"
    }), 200


# =====================================
# Approval Dashboard
# =====================================

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Python SOAR - Approval Center</title>

    <meta name="viewport"
          content="width=device-width, initial-scale=1">

    <style>

        body {
            font-family: Arial, sans-serif;
            background: #101827;
            color: #e5e7eb;
            margin: 0;
            padding: 30px;
        }

        h1 { color: #60a5fa; }

        .card {
            background: #1e293b;
            padding: 20px;
            margin: 15px 0;
            border-radius: 10px;
            border: 1px solid #334155;
        }

        .danger { color: #f87171; }
        .warning { color: #fbbf24; }
        .success { color: #4ade80; }

        button {
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            color: white;
            margin: 8px 5px 0 0;
        }

        .approve { background: #15803d; }
        .reject { background: #b91c1c; }

        .muted { color: #94a3b8; }

    </style>
</head>

<body>

<h1>Python SOAR | Approval Center</h1>

<p class="muted">
    Security Incident Response Dashboard
</p>

<h2>Pending Approval ({{ pending|length }})</h2>

{% if not pending %}

    <div class="card">
        No incidents waiting for approval.
    </div>

{% endif %}

{% for incident in pending %}

<div class="card">

    <h3>Incident #{{ incident.id }}</h3>

    <p><b>Alert:</b> {{ incident.alert_name }}</p>

    <p><b>Source IP:</b> {{ incident.src_ip }}</p>

    <p><b>Verdict:</b>
        <span class="danger">{{ incident.verdict }}</span>
    </p>

    <p><b>Decision:</b> {{ incident.decision }}</p>

    <p><b>Failed Attempts:</b>
        {{ incident.failed_attempts }}
    </p>

    <p><b>Targeted Users:</b>
        {{ incident.targeted_users }}
    </p>

    <p><b>Unique Users:</b>
        {{ incident.unique_users }}
    </p>

    <p><b>Malicious Detections:</b>
        {{ incident.malicious }}
    </p>

    <p><b>Suspicious Detections:</b>
        {{ incident.suspicious }}
    </p>

    <p><b>Time:</b> {{ incident.timestamp }}</p>

    <p><b>Status:</b> {{ incident.status }}</p>

    <form method="POST"
          action="/approve/{{ incident.id }}"
          onsubmit="return confirm('Approve this incident?')">

        <button class="approve" type="submit">
            Approve
        </button>

    </form>

    <form method="POST"
          action="/reject/{{ incident.id }}"
          onsubmit="return confirm('Reject this incident?')">

        <button class="reject" type="submit">
            Reject
        </button>

    </form>

</div>

{% endfor %}

<h2>Incident History</h2>

{% for incident in history %}

<div class="card">

    <b>
        #{{ incident.id }} -
        {{ incident.alert_name }}
    </b>

    <p>
        {{ incident.src_ip }} |
        {{ incident.verdict }} |
        {{ incident.status }}
    </p>

    <p>
        Failed Attempts: {{ incident.failed_attempts }}
    </p>

    <p>
        Targeted Users: {{ incident.targeted_users }}
    </p>

    <p class="muted">
        {{ incident.response_action }}
    </p>

</div>

{% endfor %}

</body>
</html>
"""


@app.route("/approvals")
def approvals():

    with get_db() as db:

        pending = db.execute("""
            SELECT * FROM incidents
            WHERE status = 'pending_approval'
            ORDER BY id DESC
        """).fetchall()

        history = db.execute("""
            SELECT * FROM incidents
            ORDER BY id DESC
        """).fetchall()

    return render_template_string(
        DASHBOARD_HTML,
        pending=pending,
        history=history
    )


# =====================================
# Approve Incident
# =====================================

@app.route("/approve/<int:incident_id>", methods=["POST"])
def approve_incident(incident_id):

    with get_db() as db:

        cursor = db.execute("""
            UPDATE incidents

            SET status = 'approved',
                response_action =
                'Approved by analyst - execution not configured'

            WHERE id = ?
            AND status = 'pending_approval'
        """, (incident_id,))

    if cursor.rowcount == 0:

        return "Incident not found or already reviewed", 404

    logger.info(
        "Incident #%s approved by analyst",
        incident_id
    )

    return redirect(url_for("approvals"))


# =====================================
# Reject Incident
# =====================================

@app.route("/reject/<int:incident_id>", methods=["POST"])
def reject_incident(incident_id):

    with get_db() as db:

        cursor = db.execute("""
            UPDATE incidents

            SET status = 'rejected',
                response_action =
                'Rejected by analyst - no response executed'

            WHERE id = ?
            AND status = 'pending_approval'
        """, (incident_id,))

    if cursor.rowcount == 0:

        return "Incident not found or already reviewed", 404

    logger.info(
        "Incident #%s rejected by analyst",
        incident_id
    )

    return redirect(url_for("approvals"))


# =====================================
# Start Application
# =====================================

if __name__ == "__main__":

    init_db()

    logger.info("Starting Python SOAR Engine")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
