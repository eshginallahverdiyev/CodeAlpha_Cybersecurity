# 🔍 Task 3 — Secure Coding Review


A manual security code review of a small demo web application
("**VulnBank**"), performed to identify common vulnerability classes
(SQL Injection, XSS, insecure auth, IDOR, CSRF, and misconfiguration),
document the findings, and ship a remediated version of the code.

---

## 📌 What's in this folder

| Path | Description |
|---|---|
| [`SECURITY_REVIEW.md`](./SECURITY_REVIEW.md) | Full audit report — 7 findings with severity, OWASP/CWE mapping, impact, and fix for each |
| [`vulnerable_app/app.py`](./vulnerable_app/app.py) | The intentionally vulnerable Flask app used as the review target |
| [`fixed_app/app.py`](./fixed_app/app.py) | The same app after every fix has been applied |
| [`bandit_report.txt`](./bandit_report.txt) | Output of the `bandit` static analyzer run against the vulnerable app, corroborating the manual findings |

> ⚠️ **`vulnerable_app/` is deliberately insecure and is for local,
> offline demonstration only.** Do not deploy it to a public server.

## 🧪 Methodology

1. Manual line-by-line review of every route and data flow (input → SQL
   / input → HTML / input → business logic).
2. Mapped each issue to the **OWASP Top 10 (2021)** and a **CWE** ID.
3. Corroborated findings with the `bandit` static analysis tool.
4. Fixed every issue and re-scanned to confirm remediation (`bandit`
   reports **0 issues** on `fixed_app/app.py`).

## 🐞 Findings Summary

| ID | Vulnerability | Severity | OWASP Category |
|---|---|---|---|
| SC-01 | SQL Injection | 🔴 Critical | A03:2021 – Injection |
| SC-02 | Plaintext password storage | 🔴 Critical | A02:2021 – Cryptographic Failures |
| SC-03 | Reflected XSS | 🟠 High | A03:2021 – Injection |
| SC-04 | Hardcoded secret key | 🟠 High | A02:2021 – Cryptographic Failures |
| SC-05 | IDOR (broken access control) | 🟠 High | A01:2021 – Broken Access Control |
| SC-06 | Missing CSRF protection | 🟡 Medium | A01:2021 – Broken Access Control |
| SC-07 | Debug mode / insecure bind | 🟢 Low | A05:2021 – Security Misconfiguration |

Full write-up, code snippets, and fixes for each finding are in
[`SECURITY_REVIEW.md`](./SECURITY_REVIEW.md).

## ▶️ Running the demo locally (optional)

```bash
# Vulnerable version (for demonstration only — keep it offline)
cd vulnerable_app
pip install -r requirements.txt
python app.py

# Fixed version
cd fixed_app
pip install -r requirements.txt
python app.py
```

## 🛠️ Tools Used

- Python 3 / Flask
- Manual (white-box) code review
- [`bandit`](https://bandit.readthedocs.io/) — Python static analysis (SAST)
- OWASP Top 10 (2021) and CWE for classification

## 📚 Skills Demonstrated

- Identifying and root-causing common web app vulnerabilities
- Writing a clear, structured security audit report
- Applying secure coding fixes: parameterized queries, password hashing,
  output encoding, secrets management, access control, CSRF protection
- Using static analysis tooling to validate manual findings

---
