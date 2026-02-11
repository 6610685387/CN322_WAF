# from flask import Flask, request, abort
# from sqli_detector import SQLDetector
# import requests

# app = Flask(__name__)
# detector = SQLDetector()

# TARGET_URL = "http://127.0.0.1:5001"

# @app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
# @app.route('/<path:path>', methods=['GET', 'POST'])
# def waf(path):
#     print("WAF Activated at: ", path)
#     user_inputs = []

#     for value in request.args.values():
#         user_inputs.append(value)

#     for value in request.form.values():
#         user_inputs.append(value)


#     # Input checking
#     for data in user_inputs:
#         if detector.check_sqli(data):
#             print("SQL Injection Detected: ", data)
#             return f"🚫 Blocked by WAF: SQL Injection detected", 403

#     target_url = f"{TARGET_URL}/{path}"

#     # forward request
#     print("Forwarding request")
#     response = requests.request(
#         method=request.method,
#         url=target_url,
#         params=request.args,
#         data=request.form,
#         headers={
#         "X-From-WAF": "true"
#         }
#     )


#     return response.text, response.status_code

# if __name__ == "__main__":
#     print("-- Running WAF --")
#     app.run(port=5000, debug=True)


from flask import Flask, request, abort
from sqli_detector import SQLDetector
from xss_detector import XSSDetector
import requests

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

        # ตรวจสอบ 1: SQL Injection
        if sql_detector.check_sqli(data):
            print(f"🚨 BLOCKED: SQL Injection detected in param '{param_name}': {data}")
            return f"🚫 Blocked by WAF: SQL Injection detected in '{data}'", 403

        # ตรวจสอบ 2: XSS (Cross-Site Scripting)  <--- 3. เพิ่ม Logic เช็ค XSS ตรงนี้
        if xss_detector.check_xss(data):
            print(f"🚨 BLOCKED: XSS detected in param '{param_name}': {data}")
            return f"🚫 Blocked by WAF: XSS detected in '{data}'", 403

    # ------------------------------------

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


if __name__ == "__main__":
    print("-- WAF Running on Port 5000 (Protected SQLi + XSS) --")
    app.run(port=5000, debug=True)
