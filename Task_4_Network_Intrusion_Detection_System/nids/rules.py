"""
rules.py — Loads detection thresholds, IP blacklists, and payload
signatures from a YAML rules file, with sane defaults if a field is
missing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import yaml


@dataclass
class Signature:
    name: str
    pattern: str
    severity: str = "MEDIUM"


@dataclass
class RuleSet:
    # Port scan detection
    port_scan_window_seconds: int = 10
    port_scan_unique_ports_threshold: int = 15

    # SYN flood detection
    syn_flood_window_seconds: int = 5
    syn_flood_threshold: int = 100

    # ICMP flood detection
    icmp_flood_window_seconds: int = 5
    icmp_flood_threshold: int = 50

    # Static blacklist of known-bad source IPs
    blacklist_ips: set[str] = field(default_factory=set)

    # Plaintext payload signatures (e.g. credential leakage, known malware strings)
    signatures: list[Signature] = field(default_factory=list)

    @staticmethod
    def load(path: str) -> "RuleSet":
        p = Path(path)
        if not p.exists():
            return RuleSet()

        with p.open(encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

        thresholds = raw.get("thresholds", {})
        signatures = [
            Signature(
                name=s["name"],
                pattern=s["pattern"],
                severity=s.get("severity", "MEDIUM"),
            )
            for s in raw.get("signatures", [])
        ]

        return RuleSet(
            port_scan_window_seconds=thresholds.get("port_scan_window_seconds", 10),
            port_scan_unique_ports_threshold=thresholds.get(
                "port_scan_unique_ports_threshold", 15
            ),
            syn_flood_window_seconds=thresholds.get("syn_flood_window_seconds", 5),
            syn_flood_threshold=thresholds.get("syn_flood_threshold", 100),
            icmp_flood_window_seconds=thresholds.get("icmp_flood_window_seconds", 5),
            icmp_flood_threshold=thresholds.get("icmp_flood_threshold", 50),
            blacklist_ips=set(raw.get("blacklist_ips", [])),
            signatures=signatures,
        )
