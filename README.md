<div align="center">

### Hands-on projects completed during Cyber Security Internship

[![Internship](https://img.shields.io/badge/Internship-CodeAlpha-blueviolet)](https://www.codealpha.tech)
[![Domain](https://img.shields.io/badge/Domain-Cyber%20Security-critical)]()
[![Status](https://img.shields.io/badge/Status-Completed-brightgreen)]()
[![Tasks](https://img.shields.io/badge/Tasks-4%2F4%20Done-success)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

</div>

---

## 📖 About

This repository contains all the tasks I completed as part of the **Cyber Security Internship**. The internship focuses on core cybersecurity skills — network security, ethical hacking, encryption, and threat detection — through practical, real-world projects built under expert mentorship.

Each task lives in its own folder with its own source code, documentation, and (where relevant) tests and sample output, so it can be explored independently.

---

## 🗂️ Tasks

| # | Task | Description | Status | Link |
|---|------|-------------|--------|------|
| 1 | 🕵️ **Basic Network Sniffer** | A Python tool built with Scapy to capture live network traffic, parse packet structure, and display source/destination IPs, protocols, and payloads. | ✅ Done | [`Task_1_Network_Sniffer`](./Task_1_Network_Sniffer) |
| 2 | 🎣 **Phishing Awareness Training** | An educational presentation and reference kit covering how phishing attacks work, common red flags, real-world (mock) examples, and best practices for staying protected. | ✅ Done | [`Task_2_Phishing_Awareness`](./Task_2_Phishing_Awareness) |
| 3 | 🔎 **Secure Coding Review** | A manual security code review of a demo web app to identify vulnerabilities (SQL Injection, XSS, insecure auth, IDOR, CSRF) — documented with severity, OWASP/CWE mapping, and a fully remediated version of the code. | ✅ Done | [`Task_3_Secure_Coding_Review`](./Task_3_Secure_Coding_Review) |
| 4 | 🚨 **Network Intrusion Detection System** | A Python-based, rule-driven NIDS that monitors live traffic (or replays a `.pcap`), flags suspicious activity — port scans, SYN/ICMP floods, blacklisted IPs, payload signatures — and logs alerts in real time. | ✅ Done | [`Task_4_Network_Intrusion_Detection_System`](./Task_4_Network_Intrusion_Detection_System) |

---

## 🧰 Tech Stack

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-Packet%20Analysis-orange)
![Flask](https://img.shields.io/badge/Flask-Demo%20App-000000?logo=flask&logoColor=white)
![Bandit](https://img.shields.io/badge/Bandit-Static%20Analysis-yellow)
![Pytest](https://img.shields.io/badge/Pytest-Unit%20Testing-0A9EDC?logo=pytest&logoColor=white)
![Wireshark](https://img.shields.io/badge/Wireshark-Traffic%20Inspection-1679A7?logo=wireshark&logoColor=white)
![Git](https://img.shields.io/badge/Git-GitHub-181717?logo=github&logoColor=white)

---

## 📁 Repository Structure

```
Internship_Tasks/
├── Task_1_Network_Sniffer/
│   ├── sniffer.py
│   ├── requirements.txt
│   └── README.md
│
├── Task_2_Phishing_Awareness/
│   ├── Phishing_Awareness_Training.pptx
│   ├── Phishing_Awareness_Training.pdf
│   ├── mock_phishing_examples.md
│   ├── phishing_red_flags_checklist.md
│   └── README.md
│
├── Task_3_Secure_Coding_Review/
│   ├── vulnerable_app/          # intentionally vulnerable demo Flask app (review target)
│   ├── fixed_app/                # remediated version of the same app
│   ├── SECURITY_REVIEW.md        # full audit: 7 findings, OWASP/CWE, fixes
│   ├── bandit_report.txt         # static-analysis scan backing the manual review
│   └── README.md
│
├── Task_4_Network_Intrusion_Detection_System/
│   ├── nids/                     # sniffer, detectors, rules, alerting, CLI
│   ├── rules/rules.yaml          # configurable thresholds, blacklist, signatures
│   ├── tests/test_detectors.py   # automated unit tests
│   ├── sample_output/            # real demo alert log + dashboard chart
│   └── README.md
│
├── LICENSE
└── README.md   ← you are here
```

---

## 🚀 Getting Started

Clone the repository and open any task folder to see its own setup and usage instructions:

```bash
git clone https://github.com/eshginallahverdiyev/Internship_Tasks.git
cd Internship_Tasks
```

Each task folder is self-contained — its own `README.md` covers installation, how to run it, and what it demonstrates. A few highlights:

```bash
# Task 1 — capture and inspect live packets
cd Task_1_Network_Sniffer && pip install -r requirements.txt

# Task 3 — read the full audit report
cd Task_3_Secure_Coding_Review && cat SECURITY_REVIEW.md

# Task 4 — see the NIDS catch synthetic attacks end-to-end
cd Task_4_Network_Intrusion_Detection_System
pip install -r requirements.txt
python -m nids.main --demo
```
---

## ⚖️ Disclaimer

All projects in this repository were built **strictly for educational purposes** as part of an internship program. The vulnerable demo app in Task 3 and the NIDS in Task 4 are meant for local, offline learning — any security or network tooling here should only be used on systems and networks you own or have explicit permission to test.

---

## 📄 License

This repository is licensed under the [MIT License](LICENSE).

---

<div align="center">

</div>
