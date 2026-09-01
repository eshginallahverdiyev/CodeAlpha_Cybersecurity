"""
visualize_alerts.py — Turns the NIDS's JSON-Lines alert log into a simple
two-panel dashboard PNG: alert counts by rule, and by severity.

Usage:
    python visualize_alerts.py                       # uses logs/alerts.log
    python visualize_alerts.py --log sample_output/sample_alerts.log
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

SEVERITY_COLORS = {
    "LOW": "#4FC3F7",
    "MEDIUM": "#FFB300",
    "HIGH": "#E53935",
    "CRITICAL": "#8E0000",
}


def load_alerts(log_path: str) -> list[dict]:
    alerts = []
    p = Path(log_path)
    if not p.exists():
        raise SystemExit(f"No alert log found at {log_path}. Run the NIDS first (e.g. --demo).")
    with p.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                alerts.append(json.loads(line))
    return alerts


def plot(alerts: list[dict], out_path: str) -> None:
    rule_counts = Counter(a["rule"] for a in alerts)
    severity_counts = Counter(a["severity"] for a in alerts)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    fig.suptitle("NIDS Alert Dashboard", fontsize=14, fontweight="bold")

    rules = list(rule_counts.keys())
    ax1.barh(rules, [rule_counts[r] for r in rules], color="#546E7A")
    ax1.set_title("Alerts by Rule")
    ax1.set_xlabel("Count")

    sev_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    sevs = [s for s in sev_order if s in severity_counts]
    ax2.bar(sevs, [severity_counts[s] for s in sevs],
            color=[SEVERITY_COLORS[s] for s in sevs])
    ax2.set_title("Alerts by Severity")
    ax2.set_ylabel("Count")

    fig.tight_layout(rect=[0, 0, 1, 0.95])
    fig.savefig(out_path, dpi=150)
    print(f"Saved dashboard -> {out_path}")
    print(f"Total alerts: {len(alerts)}")
    print("By rule:", dict(rule_counts))
    print("By severity:", dict(severity_counts))


def main():
    parser = argparse.ArgumentParser(description="Visualize NIDS alert logs")
    parser.add_argument("--log", default="logs/alerts.log", help="Path to JSONL alert log")
    parser.add_argument("--out", default="sample_output/alert_dashboard.png", help="Output PNG path")
    args = parser.parse_args()

    alerts = load_alerts(args.log)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    plot(alerts, args.out)


if __name__ == "__main__":
    main()
