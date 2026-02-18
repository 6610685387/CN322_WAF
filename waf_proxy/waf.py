import html
from flask import Flask, request, render_template
import sqlite3
import requests
import re
from datetime import datetime
from sqli_detector import SQLDetector
from xss_detector import XSSDetector

app = Flask(__name__)

TARGET_URL = "http://127.0.0.1:5001"
DB_NAME = "waf_logs.db"

# # ==============================
# # 🔎 SQL Injection Detector
# # ==============================
# class SQLDetector:
#     def __init__(self):
#         self.patterns = [
#             r"(\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b|\bDELETE\b|\bUPDATE\b)",
#             r"(--|#|;)",
#             r"(\bOR\b|\bAND\b).*(=)",
#             r"('|\")\s*=\s*('|\")",
#         ]

#     def check_sqli(self, data):
#         for pattern in self.patterns:
#             if re.search(pattern, data, re.IGNORECASE):
#                 return True
#         return False


# # ==============================
# # 🔎 XSS Detector
# # ==============================
# class XSSDetector:
#     def __init__(self):
#         self.patterns = [
#             r"<script.*?>.*?</script>",
#             r"on\w+\s*=",
#             r"javascript:",
#             r"<.*?>"
#         ]

#     def check_xss(self, data):
#         for pattern in self.patterns:
#             if re.search(pattern, data, re.IGNORECASE):
#                 return True
#         return False


# ==============================
# 🗃️ Database Setup
# ==============================
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            attack_type TEXT,
            payload TEXT,
            path TEXT,
            timestamp TEXT
        )
    """)

    conn.commit()
    conn.close()


def log_attack(ip, attack_type, payload, path):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO attack_logs (ip, attack_type, payload, path, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (ip, attack_type, payload, path, datetime.now()))

    conn.commit()
    conn.close()


# ==============================
# 🛡️ WAF Core
# ==============================
sql_detector = SQLDetector()
xss_detector = XSSDetector()

@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def waf(path):
    print(f"\n--- New Request to: /{path} ---")

    user_inputs = []

    for key, value in request.args.items():
        user_inputs.append((key, value))

    for key, value in request.form.items():
        user_inputs.append((key, value))

    # Security Zone
    for param_name, data in user_inputs:

        # XSS Check
        if xss_detector.check_xss(data):
            print(f"🚨 BLOCKED: XSS in '{param_name}': {data}")

            log_attack(
                ip=request.remote_addr,
                attack_type="XSS",
                payload=data,
                path=path,
            )

            safe_data = html.escape(data)
            return f"🚫 Blocked by WAF: XSS detected in '{safe_data}'", 403

        # SQLi Check
        if sql_detector.check_sqli(data):
            print(f"🚨 BLOCKED: SQLi in '{param_name}': {data}")

            log_attack(
                ip=request.remote_addr,
                attack_type="SQL Injection",
                payload=data,
                path=path,
            )

            safe_data = html.escape(data)
            return f"🚫 Blocked by WAF: SQL Injection detected in '{safe_data}'", 403

    # ✅ Clean → Forward
    print("✅ Traffic Clean. Forwarding...")

    target_url = f"{TARGET_URL}/{path}"

    try:
        response = requests.request(
            method=request.method,
            url=target_url,
            params=request.args,
            data=request.form,
            headers={"X-From-WAF": "true"},
        )

        return response.text, response.status_code

    except requests.exceptions.ConnectionError:
        return "❌ Error: Target Web Server (Port 5001) is down.", 502


# ==============================
# 📜 View Logs
# ==============================

@app.route("/logs")
def view_logs():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM attack_logs ORDER BY timestamp DESC")
    logs = cursor.fetchall()

    conn.close()

    return render_template("waf_log_page.html", logs=logs)

# ==============================
# 🚀 Run
# ==============================
if __name__ == "__main__":
    print("-- WAF Running on Port 5000 (Protected SQLi + XSS) --")
    init_db()
    app.run(port=5000, debug=True)
