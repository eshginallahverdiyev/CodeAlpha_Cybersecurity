"""
NIDS - A lightweight, rule-based Network Intrusion Detection System.

Modules:
    sniffer     - live packet capture (Scapy) and packet -> detector pipeline
    detectors   - stateful detection logic (port scans, floods, signatures, blacklist)
    rules       - loads and validates detection rules / thresholds from YAML
    alert       - structured, leveled alert logging (console + JSONL file)
"""

__version__ = "1.0.0"
