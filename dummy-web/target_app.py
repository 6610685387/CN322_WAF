from flask import Flask, request, render_template, abort

app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static"
)

@app.before_request
def block_direct_access():
    if request.headers.get("X-From-WAF") != "true":
        abort(403)

@app.route('/')
def home():
    return render_template("home.html")

@app.route('/login')
def login():
    user = request.args.get('username', 'Guest')
    return render_template("login.html", username=user)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    return render_template("search.html", query=query)

if __name__ == '__main__':
    print("Dummy Web is starting on http://127.0.0.1:5001")
    app.run(port=5001, debug=True)
