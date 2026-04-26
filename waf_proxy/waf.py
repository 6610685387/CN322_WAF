import html
import json
from flask import Flask, request, render_template
import requests
from werkzeug.middleware.proxy_fix import ProxyFix
from detectors.sqli_detector import SQLDetector
from detectors.xss_detector import XSSDetector
from detectors import scan_payload
from database_manager import add_log, is_ip_banned, init_db

DEBUG = False 

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

# Pre-load ban cache at startup so first request isn't slow
try:
    init_db()
except Exception as _e:
    print(f"⚠️ init_db failed at startup (fail-open): {_e}")

TARGET_URL = "http://dummy_web:5001"
# Connection pool ขนาดใหญ่พอสำหรับ 4 workers * 8 threads = 32 concurrent
_adapter = requests.adapters.HTTPAdapter(
    pool_connections=32,
    pool_maxsize=64,
    max_retries=0,
)
session = requests.Session()
session.mount('http://', _adapter)
session.mount('https://', _adapter)

sql_detector = SQLDetector()
xss_detector = XSSDetector()

# Headers ที่ไม่ต้องสแกน — เป็นค่าที่ browser/infra สร้างเอง ไม่ใช่ user input
# หลักการ: skip เฉพาะ header ที่มีรูปแบบ structured (quotes, semicolons, version strings)
# ซึ่งทำให้ SQLi score พุ่งโดยไม่ใช่ attack จริง
_SKIP_HEADERS = frozenset([
    # Infrastructure / connection
    "host", "content-length", "content-type", "transfer-encoding",
    "connection", "upgrade-insecure-requests",
    # Caching
    "cache-control", "pragma", "if-none-match", "if-modified-since",
    # Fetch metadata — browser-generated, structured
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-user",
    # Client hints (sec-ch-ua-*) — มี quotes/semicolons เยอะ → FP สูงมาก
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "sec-ch-ua-arch", "sec-ch-ua-bitness", "sec-ch-ua-full-version",
    "sec-ch-ua-full-version-list", "sec-ch-ua-model",
    # Proxy / WAF internal
    "x-forwarded-for", "x-forwarded-proto", "x-real-ip", "x-from-waf",
    # Content negotiation
    "accept", "accept-encoding", "accept-language",
    # CORS preflight
    "origin", "access-control-request-method", "access-control-request-headers",
    # *** หมายเหตุ: user-agent, cookie, referer, authorization ยังคง SCAN อยู่ ***
])


def collect_inputs(path, request):
    """รวบรวม input ทุกจุดที่ผู้โจมตีอาจซ่อน payload รวม HTTP Headers"""
    user_inputs = []

    # 1. URL path
    user_inputs.append(("__path__", path))

    # 2. GET parameters
    for key, value in request.args.items():
        user_inputs.append((key, value))

    # 3. POST form data
    for key, value in request.form.items():
        user_inputs.append((key, value))

    # 4. JSON body
    if request.is_json:
        try:
            body = request.get_json(force=True, silent=True) or {}
            for key, value in body.items():
                user_inputs.append((key, str(value)))
        except Exception:
            pass

    # 5. Raw body fallback
    if (
        not request.form
        and not request.is_json
        and request.content_length
        and request.content_length < 65536
    ):
        raw = request.get_data(as_text=True)
        if raw:
            user_inputs.append(("__raw_body__", raw))

    # 6. HTTP Request Headers — สแกนทุก header ที่ไม่ใช่ infrastructure
    for header_name, header_value in request.headers:
        header_name_lower = header_name.lower()

        if header_name_lower in _SKIP_HEADERS:
            continue

        # ไม่จำกัดเฉพาะ 4 headers — สแกนทุก header ที่ user ส่งมาได้
        # (GoTestWAF ส่ง attack ใน custom headers เช่น X-Api-Version ด้วย)
        user_inputs.append((f"__header__{header_name}", header_value))

    return user_inputs


@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def waf(path):
    if DEBUG:
        print(f"--- New Request to: /{path} ---")

    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    if is_ip_banned(client_ip):
        if DEBUG:
            print(f"🚫 BLOCKED (BANNED IP): {client_ip}")
        return f"🚫 Your IP ({client_ip}) is banned.", 403

    ip_address = request.remote_addr
    if DEBUG:
        print(f"Client IP: {ip_address}")

    user_inputs = collect_inputs(path, request)

    # Security scan
    for param_name, data in user_inputs:
        if not data:
            continue

  
        if len(data) > 500:
            data = data[:500]

    
        if len(data) < 3:
            continue

        # *** ลบ isalnum() ออก: Base64 payload ดูเหมือน alnum แต่ซ่อน attack ได้ ***
        # ข้ามเฉพาะตัวเลขล้วน (เช่น user ID) ซึ่งไม่มีทางเป็น injection
        if data.isdigit():
            continue

        result = scan_payload(data)

        if result["is_blocked"]:
            if DEBUG:
                print(f"🚨 BLOCKED: {result['attack_type']} in '{param_name}'")
                print(f"📈 Score: {result['total_score']} | Payload: {data}")
                print(f"🧹 Cleaned: {result['cleaned_payload']}")

            add_log(
                ip_address=ip_address,
                attack_type=result["attack_type"],
                payload=data,
                score=result["total_score"],
                path=path,
            )

            safe_data = html.escape(data)
            return (
                f"🚫 Blocked by WAF: {result['attack_type']} detected in '{safe_data}'",
                403,
            )

    # Clean → Forward
    if DEBUG:
        print("✅ Traffic Clean. Forwarding...")

    target_url = f"{TARGET_URL}/{path}"

    try:
        response = session.request(
            method=request.method,
            url=target_url,
            params=request.args,
            data=request.form,
            headers={"X-From-WAF": "true"},
            timeout=(1, 3),
        )
        return response.text, response.status_code

    except requests.exceptions.Timeout:
        return "Gateway Timeout", 504

    except requests.exceptions.ConnectionError:
        return "Target Down", 502

    except requests.exceptions.RequestException:
        return "Bad Gateway", 502


if __name__ == "__main__":
    print("-- WAF Running on Port 5000 (Protected SQLi + XSS) --")
    app.run(host="0.0.0.0", port=5000, debug=True)