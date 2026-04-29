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

try:
    init_db()
except Exception as _e:
    print(f"⚠️ init_db failed at startup (fail-open): {_e}")

TARGET_URL = "http://dummy_web:5001"
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

_SKIP_HEADERS = frozenset([
    "host", "content-length", "content-type", "transfer-encoding",
    "connection", "upgrade-insecure-requests",
    "cache-control", "pragma", "if-none-match", "if-modified-since",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-user",
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "sec-ch-ua-arch", "sec-ch-ua-bitness", "sec-ch-ua-full-version",
    "sec-ch-ua-full-version-list", "sec-ch-ua-model",
    "x-forwarded-for", "x-forwarded-proto", "x-real-ip", "x-from-waf",
    "accept", "accept-encoding", "accept-language",
    "origin", "access-control-request-method", "access-control-request-headers",
])

def collect_inputs(path, request):
    user_inputs = []
    user_inputs.append(("__path__", path))
    for key, value in request.args.items():
        user_inputs.append((key, value))
    for key, value in request.form.items():
        user_inputs.append((key, value))
    if request.is_json:
        try:
            body = request.get_json(force=True, silent=True) or {}
            for key, value in body.items():
                user_inputs.append((key, str(value)))
        except Exception:
            pass
    if (not request.form and not request.is_json and request.content_length and request.content_length < 65536):
        raw = request.get_data(as_text=True)
        if raw:
            user_inputs.append(("__raw_body__", raw))
    for header_name, header_value in request.headers:
        header_name_lower = header_name.lower()
        if header_name_lower in _SKIP_HEADERS:
            continue
        user_inputs.append((f"__header__{header_name}", header_value))
    return user_inputs

@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def waf(path):
    if DEBUG:
        print(f"--- New Request to: /{path} ---")

    
    client_ip = request.headers.get("X-Forwarded-For")
    if client_ip:
        client_ip = client_ip.split(",")[0].strip()
    else:
        client_ip = request.remote_addr

    if DEBUG:
        print(f"Client IP: {client_ip}")

    if is_ip_banned(client_ip):
        if DEBUG:
            print(f"🚫 BLOCKED (BANNED IP): {client_ip}")
        return f"🚫 Your IP ({client_ip}) is banned.", 403

    user_inputs = collect_inputs(path, request)

    for param_name, data in user_inputs:
        if not data:
            continue

        if len(data) > 500:
            data = data[:500]
        if len(data) < 3:
            continue
        if data.isdigit():
            continue

        result = scan_payload(data)

        if result["is_blocked"]:
            if DEBUG:
                print(f"🚨 BLOCKED: {result['attack_type']} in '{param_name}'")
                print(f"📈 Score: {result['total_score']} | Payload: {data}")
                print(f"🧹 Cleaned: {result['cleaned_payload']}")

            
            add_log(
                ip_address=client_ip,
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