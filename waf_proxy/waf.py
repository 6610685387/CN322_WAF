from flask import Flask, request, abort, render_template_string
import sqlite3
from sqli_detector import SQLDetector
import requests

from logger import log_attack
from database import init_db, DB_NAME

app = Flask(__name__)
detector = SQLDetector()

TARGET_URL = "http://127.0.0.1:5001"

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def waf(path):
    print("WAF Activated at: ", path)
    user_inputs = []

    for value in request.args.values():
        user_inputs.append(value)

    for value in request.form.values():
        user_inputs.append(value)


    # Input checking
    for data in user_inputs:
        if detector.check_sqli(data):
            print("SQL Injection Detected: ", data) 

            log_attack(
                ip=request.remote_addr,
                attack_type="SQL Injection",
                payload=data,
                path=path
            )

            return f"🚫 Blocked by WAF: SQL Injection detected", 403
            
    target_url = f"{TARGET_URL}/{path}"

    # forward request
    print("Forwarding request")
    response = requests.request(
        method=request.method,
        url=target_url,
        params=request.args,
        data=request.form,
        headers={
        "X-From-WAF": "true"
        }
    )
    

    return response.text, response.status_code

@app.route('/logs')
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
    print("-- Running WAF --")
    init_db()
    app.run(port=5000, debug=True)



