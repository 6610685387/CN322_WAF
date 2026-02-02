from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("home.html")

@app.route("/login")
def login():
    return render_template("login.html")

@app.route("/comment")
def main():
    return render_template("comment.html")

@app.route("/blocked_login")
def blocked_login():
    return "Access Denied: Login is blocked."

if __name__ == "__main__":
    app.run(debug=True)