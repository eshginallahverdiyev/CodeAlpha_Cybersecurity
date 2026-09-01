"""
VulnBank - Remediated Version
==============================
This file mirrors vulnerable_app/app.py after applying every fix
recommended in SECURITY_REVIEW.md. Compare the two files side by side
to see exactly what changed and why.

Run locally:
    pip install -r requirements.txt
    python app.py
"""

import os
import secrets
import sqlite3
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, g, redirect, session, render_template_string, abort
from flask_wtf import CSRFProtect

app = Flask(__name__)

# --- FIX SC-04: secret key comes from environment, never hardcoded --------
app.secret_key = os.environ.get("VULNBANK_SECRET_KEY") or secrets.token_hex(32)

# Session hardening
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,  # requires HTTPS in production
)

# --- FIX SC-06: CSRF protection enabled globally ---------------------------
csrf = CSRFProtect(app)

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
            username TEXT UNIQUE,
            password_hash TEXT,
            balance REAL
        )"""
    )
    # --- FIX SC-02: passwords are hashed, never stored in plaintext -------
    seed = [
        (1, "alice", "alice123", 5000.0),
        (2, "bob", "bobpass", 1200.0),
    ]
    for uid, uname, pwd, bal in seed:
        db.execute(
            "INSERT OR IGNORE INTO users (id, username, password_hash, balance) "
            "VALUES (?, ?, ?, ?)",
            (uid, uname, generate_password_hash(pwd), bal),
        )
    db.commit()


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # --- FIX SC-01: parameterized query, no string concatenation -----
        cur = get_db().execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        )
        user = cur.fetchone()

        # --- FIX SC-02 (cont.): verify against hashed password -----------
        if user and check_password_hash(user[2], password):
            session.clear()
            session["user_id"] = user[0]
            session["username"] = user[1]
            return redirect("/profile")
        return "Invalid credentials", 401

    return """
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit">
        </form>
    """


@app.route("/profile")
def profile():
    if "user_id" not in session:
        return redirect("/login")

    username = session.get("username", "")
    # --- FIX SC-03: user input is escaped before rendering -------------
    name_param = request.args.get("name", username)
    template = "<h1>Welcome, {{ name }}!</h1>"
    return render_template_string(template, name=escape(name_param))


@app.route("/account/<int:account_id>")
def account(account_id):
    if "user_id" not in session:
        return redirect("/login")

    # --- FIX SC-05: enforce ownership before returning data ------------
    if account_id != session["user_id"]:
        abort(403)

    cur = get_db().execute(
        "SELECT username, balance FROM users WHERE id = ?", (account_id,)
    )
    row = cur.fetchone()
    if row:
        return f"Account owner: {row[0]}, Balance: ${row[1]}"
    return "Account not found", 404


@app.route("/transfer", methods=["POST"])
def transfer():
    # CSRFProtect (enabled above) now validates a CSRF token on this
    # state-changing POST automatically -- see FIX SC-06.
    if "user_id" not in session:
        return redirect("/login")

    from_id = session["user_id"]
    try:
        to_id = int(request.form["to_id"])
        amount = float(request.form["amount"])
    except (ValueError, KeyError):
        return "Invalid input", 400

    if amount <= 0:
        return "Amount must be positive", 400

    db = get_db()
    row = db.execute("SELECT balance FROM users WHERE id = ?", (from_id,)).fetchone()
    if not row or row[0] < amount:
        return "Insufficient funds", 400

    db.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, from_id))
    db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, to_id))
    db.commit()
    return "Transfer complete"


if __name__ == "__main__":
    with app.app_context():
        init_db()
    # --- FIX SC-07: debug mode disabled in the app's default runtime ----
    app.run(debug=False, host="127.0.0.1")
