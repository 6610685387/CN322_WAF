from flask import Flask, request, abort
from sqli_detector import SQLDetector
import requests

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

if __name__ == "__main__":
    print("-- Running WAF --")
    app.run(port=5000, debug=True)



