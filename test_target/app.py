"""
test_target/app.py
-------------------
A tiny local Flask app whose ONLY purpose is to generate real HTTP GET/POST
traffic on localhost:8080 so you have something to point the Scapy sniffer
at (scripts/04_run_realtime.py) during a live demo.

IMPORTANT: this app does NOT execute, interpret, or store any of the
parameters it receives -- every endpoint just echoes back what it got as
plain text. There is no database, no template rendering of user input, and
no real SQL/JS execution happening here. It is a harmless traffic
generator, not a deliberately vulnerable app. The "attack" happens only in
the sense that an SQLi/XSS-shaped STRING travels over HTTP to this
endpoint -- exactly like it would to any real login/search form -- so the
sniffer has real packets to classify.

Run:
    python test_target/app.py
Then in another terminal, generate traffic with curl (see README.md), while
scripts/04_run_realtime.py is sniffing on the loopback interface.
"""

from flask import Flask, request

app = Flask(__name__)


@app.route("/search", methods=["GET"])
def search():
    q = request.args.get("q", "")
    return f"You searched for: {q}\n", 200, {"Content-Type": "text/plain"}


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    return f"Login attempt received for username={username!r}\n", 200, {"Content-Type": "text/plain"}


@app.route("/profile", methods=["GET"])
def profile():
    user_id = request.args.get("id", "")
    return f"Profile lookup for id={user_id}\n", 200, {"Content-Type": "text/plain"}


@app.route("/", methods=["GET"])
def index():
    return (
        "Test target app is running.\n"
        "Endpoints: GET /search?q=..  GET /profile?id=..  POST /login (username, password)\n"
    ), 200, {"Content-Type": "text/plain"}


if __name__ == "__main__":
    # Plaintext HTTP on purpose (Chapter 1 scope: this study only covers
    # plaintext HTTP traffic). Bind to 0.0.0.0 only if you understand the
    # exposure; localhost-only (127.0.0.1) is the safe default for a demo.
    app.run(host="127.0.0.1", port=8080, debug=False)
