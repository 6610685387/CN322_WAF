from flask import Flask, request, render_template_string

app = Flask(__name__)

# หน้า Home แบบง่ายๆ
@app.route('/')
def home():
    return """
    <h1>🏠 Target Web Application (Protected)</h1>
    <p>This is the backend server running on port 5001.</p>
    <ul>
        <li><a href="/search?q=hello">Test Search (XSS Target)</a></li>
        <li><a href="/login?username=admin">Test Login (SQLi Target)</a></li>
    </ul>
    """

@app.route('/login')
def login():
    user = request.args.get('username', 'Guest')
    return f"<h2>Login Page</h2><p>Attempting login for: <b>{user}</b></p>"

@app.route('/search')
def search():
    query = request.args.get('q', '')
    return f"<h2>Search Results</h2><p>You searched for: <b>{query}</b></p>"

if __name__ == '__main__':
    # รันที่ Port 5001 เพื่อให้ WAF (Port 5000) ส่ง Request มาหาเราได้
    print("Dummy Web is starting on http://127.0.0.1:5001")
    app.run(port=5001, debug=True)