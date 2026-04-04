import html
from flask import Flask, request, render_template
import requests
from werkzeug.middleware.proxy_fix import ProxyFix  # ✅ เพิ่มตรงนี้
from sqli_detector import SQLDetector
from xss_detector import XSSDetector
from database_manager import add_log, is_ip_banned

app = Flask(__name__)

# ✅ ทำให้รองรับ X-Forwarded-For จาก proxy (production-ready)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

TARGET_URL = "http://127.0.0.1:5001"

# ==============================
# 🛡️ WAF Core
# ==============================
sql_detector = SQLDetector()
xss_detector = XSSDetector()

@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def waf(path):
    print(f"--- New Request to: /{path} ---")

    # ✅ ตรวจ IP ก่อนเลย
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    if is_ip_banned(client_ip):
        print(f"⛔ BLOCKED (BANNED IP): {client_ip}")
        return f"🚫 Your IP ({client_ip}) is banned.", 403

    # ✅ ใช้ IP แบบ production-ready
    ip_address = request.remote_addr
    print(f"Client IP: {ip_address}")

    user_inputs = []

    # Collect GET parameters
    for key, value in request.args.items():
        user_inputs.append((key, value))

    # Collect POST form data
    for key, value in request.form.items():
        user_inputs.append((key, value))

    # Security Zone
    for param_name, data in user_inputs:

        # XSS Check
        if xss_detector.check_xss(data):
            print(f"🚨 BLOCKED: XSS in '{param_name}': {data}")

            add_log(
                ip_address=ip_address,  # ✅ ใช้ตัวแปรนี้
                attack_type="XSS",
                payload=data,
                score=85,
                path=path,
            )

            safe_data = html.escape(data)
            return f"🚫 Blocked by WAF: XSS detected in '{safe_data}'", 403

        # SQLi Check
        if sql_detector.check_sqli(data):
            print(f"🚨 BLOCKED: SQLi in '{param_name}': {data}")

            add_log(
                ip_address=ip_address,  # ✅ ใช้ตัวแปรนี้
                attack_type="SQL Injection",
                payload=data,
                score=90,
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
        print(f"❌ Error: Target Web Server at {TARGET_URL} is down.")
        return "❌ Error: Target Web Server is down.", 502


# ==============================
# 🚀 Run WAF Proxy
# ==============================
if __name__ == "__main__":
    print("-- WAF Proxy Running on Port 5000 --")
    app.run(port=5000, debug=True)