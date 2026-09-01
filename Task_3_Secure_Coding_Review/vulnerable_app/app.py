"""
VulnBank - Demo Flask Application (INTENTIONALLY VULNERABLE)
==============================================================
This is a small, self-contained mock "banking" web app created ONLY as a
target for a manual secure-coding review. It must never be deployed or
exposed to a real network. Every vulnerability in this file is documented,
explained, and remediated in SECURITY_REVIEW.md, and a corrected version
lives in /fixed_app.

Run locally for demonstration purposes only:
    pip install flask
    python app.py
"""

import sqlite3
from flask import Flask, request, g, redirect, session, render_template_string

app = Flask(__name__)

# --- FINDING SC-04: Hardcoded secret key -----------------------------------
app.secret_key = "supersecret123"

DB_PATH = "vulnbank.db"


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
    return db


def init_db():
    db = get_db()
    db.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            balance REAL
        )"""
    )
    # --- FINDING SC-02: Passwords stored in plaintext ----------------------
    db.execute(
        "INSERT OR IGNORE INTO users (id, username, password, balance) "
        "VALUES (1, 'alice', 'alice123', 5000.0)"
    )
    db.execute(
        "INSERT OR IGNORE INTO users (id, username, password, balance) "
        "VALUES (2, 'bob', 'bobpass', 1200.0)"
    )
    db.commit()


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # --- FINDING SC-01: SQL Injection (string concatenation) ----------
        query = (
            "SELECT * FROM users WHERE username = '"
            + username
            + "' AND password = '"
            + password
            + "'"
        )
        cur = get_db().execute(query)
        user = cur.fetchone()

        if user:
            session["user_id"] = user[0]
            session["username"] = user[1]
            return redirect("/profile")
        return "Invalid credentials"

    return """
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit">
        </form>
    """


@app.route("/profile")
def profile():
    username = session.get("username", "")

    # --- FINDING SC-03: Reflected XSS (unescaped template rendering) ------
    name_param = request.args.get("name", username)
    template = "<h1>Welcome, " + name_param + "!</h1>"
    return render_template_string(template)


@app.route("/account/<int:account_id>")
def account(account_id):
    # --- FINDING SC-05: Insecure Direct Object Reference (IDOR) -----------
    # Any logged-in (or even anonymous) user can view any account by
    # guessing/incrementing the ID — there is no ownership check.
    cur = get_db().execute(
        "SELECT username, balance FROM users WHERE id = ?", (account_id,)
    )
    row = cur.fetchone()
    if row:
        return f"Account owner: {row[0]}, Balance: ${row[1]}"
    return "Account not found"


@app.route("/transfer", methods=["POST"])
def transfer():
    # --- FINDING SC-06: No CSRF protection on a state-changing action -----
    from_id = session.get("user_id")
    to_id = request.form["to_id"]
    amount = float(request.form["amount"])

    db = get_db()
    db.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, from_id))
    db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, to_id))
    db.commit()
    return "Transfer complete"


if __name__ == "__main__":
    with app.app_context():
        init_db()
    # --- FINDING SC-07: Debug mode enabled -> remote code execution risk --
    app.run(debug=True, host="0.0.0.0")
