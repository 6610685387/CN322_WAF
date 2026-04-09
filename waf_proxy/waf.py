import html
from flask import Flask, request, render_template
import requests
from werkzeug.middleware.proxy_fix import ProxyFix  # ✅ เพิ่มตรงนี้
from detectors.sqli_detector import SQLDetector
from detectors.xss_detector import XSSDetector
from detectors import scan_payload
from database_manager import add_log, is_ip_banned

app = Flask(__name__)

# ✅ ทำให้รองรับ X-Forwarded-For จาก proxy (production-ready)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

TARGET_URL = "http://127.0.0.1:5001"
# TARGET_URL = "http://dummy_web:5001"
# DB_NAME = "waf_logs.db"


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
        # ✅ 2. เรียกใช้ระบบตรวจสอบขั้นสูง (รวม Normalization + Scoring)
        result = scan_payload(data)

        if result["is_blocked"]:
            print(f"🚨 BLOCKED: {result['attack_type']} in '{param_name}'")
            print(f"📈 Score: {result['total_score']} | Payload: {data}")
            print(f"🧹 Cleaned: {result['cleaned_payload']}")

            # ✅ 3. ส่งค่าไปบันทึก Log (ใช้คะแนนจริง และประเภทการโจมตีที่ตรวจพบจริง)
            add_log(
                ip_address=ip_address,
                attack_type=result["attack_type"],
                payload=data,
                score=result["total_score"], # ใช้คะแนนที่คำนวณมาได้จริง ไม่ใช่ค่า Hardcode
                path=path,
            )

            safe_data = html.escape(data)
            return f"🚫 Blocked by WAF: {result['attack_type']} detected in '{safe_data}'", 403


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
    print("-- WAF Running on Port 5000 (Protected SQLi + XSS) --")
    # init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
