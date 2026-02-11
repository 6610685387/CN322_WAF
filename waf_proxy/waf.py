from flask import Flask, request, abort, render_template_string
import sqlite3
from sqli_detector import SQLDetector
from xss_detector import XSSDetector
import requests

from logger import log_attack
from database import init_db, DB_NAME

app = Flask(__name__)

# สร้าง Instance ของนักสืบทั้ง 2 คน
sql_detector = SQLDetector()
xss_detector = XSSDetector()  # <--- 2. เรียกใช้ Class XSS

TARGET_URL = "http://127.0.0.1:5001"


@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def waf(path):
    print(f"\n--- New Request to: /{path} ---")

    # รวบรวม Input ทั้งหมดจาก URL (GET) และ Form (POST)
    user_inputs = []
    for key, value in request.args.items():
        user_inputs.append((key, value))

    for key, value in request.form.items():
        user_inputs.append((key, value))

    # --- 🛡️ ZONE ตรวจจับความปลอดภัย ---
    for param_name, data in user_inputs:

        # 1. ตรวจสอบ SQL Injection
        if sql_detector.check_sqli(data):
            print(f"🚨 BLOCKED: SQL Injection detected in param '{param_name}': {data}")

            # บันทึกลง Database ทันทีที่ตรวจเจอ
            log_attack(
                ip=request.remote_addr,
                attack_type="SQL Injection",
                payload=data,
                path=path,
            )
            return f"🚫 Blocked by WAF: SQL Injection detected in '{data}'", 403

        # 2. ตรวจสอบ XSS (Cross-Site Scripting)
        if xss_detector.check_xss(data):
            print(f"🚨 BLOCKED: XSS detected in param '{param_name}': {data}")

            log_attack(
                ip=request.remote_addr,
                attack_type="XSS",
                payload=data,
                path=path,
            )
            return f"🚫 Blocked by WAF: XSS detected in '{data}'", 403

    # --- ลบ Loop ช่วงล่างทิ้งไปได้เลย เพราะเราเช็คและ Log ไปข้างบนแล้ว ---

    # # Input checking
    # for data in user_inputs:
    #     if sql_detector.check_sqli(data):
    #         print("SQL Injection Detected: ", data)

    #         log_attack(
    #             ip=request.remote_addr,
    #             attack_type="SQL Injection",
    #             payload=data,
    #             path=path,
    #         )

    #         return f"🚫 Blocked by WAF: SQL Injection detected", 403

    target_url = f"{TARGET_URL}/{path}"

    # Forward request ถ้าปลอดภัย
    print("✅ Traffic Clean. Forwarding to Target...")
    try:
        response = requests.request(
            method=request.method,
            url=target_url,
            params=request.args,
            data=request.form,
            headers={"X-From-WAF": "true"},  # กุญแจผ่านทาง
        )
        return response.text, response.status_code

    except requests.exceptions.ConnectionError:
        return "❌ Error: Target Web Server (Port 5001) is down.", 502


@app.route("/logs")
def view_logs():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM attack_logs ORDER BY timestamp DESC")
    logs = cursor.fetchall()

    conn.close()

    html = """
    <h2>🚨 WAF Attack Logs</h2>
    <table border="1" cellpadding="5">
        <tr>
            <th>ID</th>
            <th>IP</th>
            <th>Attack Type</th>
            <th>Payload</th>
            <th>Path</th>
            <th>Time</th>
        </tr>
        {% for log in logs %}
        <tr>
            <td>{{ log[0] }}</td>
            <td>{{ log[1] }}</td>
            <td>{{ log[2] }}</td>
            <td>{{ log[3] }}</td>
            <td>{{ log[4] }}</td>
            <td>{{ log[5] }}</td>
        </tr>
        {% endfor %}
    </table>
    """

    return render_template_string(html, logs=logs)


if __name__ == "__main__":
    print("-- WAF Running on Port 5000 (Protected SQLi + XSS) --")
    print("-- Running WAF --")
    init_db()
    app.run(port=5000, debug=True)
