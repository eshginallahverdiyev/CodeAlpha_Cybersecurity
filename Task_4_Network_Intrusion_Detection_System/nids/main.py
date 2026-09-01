"""
main.py — Command-line entrypoint for the NIDS.

Usage:
    python -m nids.main --demo
    python -m nids.main --pcap sample_output/sample_capture.pcap
    sudo python -m nids.main --iface eth0
"""

from __future__ import annotations

import argparse
import sys
import time

import yaml

from .alert import AlertManager
from .detectors import build_default_detectors, PacketEvent
from .rules import RuleSet
from .sniffer import NIDSEngine


def load_config(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}


def build_engine(config: dict) -> NIDSEngine:
    rules_path = config.get("rules_path", "rules/rules.yaml")
    log_path = config.get("log_path", "logs/alerts.log")

    rules = RuleSet.load(rules_path)
    alert_manager = AlertManager(log_path=log_path, echo=True)
    detectors = build_default_detectors(rules)
    return NIDSEngine(detectors, alert_manager)


def run_demo(engine: NIDSEngine) -> None:
    """
    Generates synthetic traffic that deliberately trips every detector, so
    the whole pipeline can be demonstrated end-to-end without root access,
    a live interface, or a pre-recorded .pcap file.
    """
    print("=== Running NIDS in DEMO mode (synthetic traffic) ===\n")
    now = time.time()
    attacker = "203.0.113.66"
    victim = "10.0.0.5"

    events: list[PacketEvent] = []

    # 1) Port scan: 20 different destination ports in under a second
    for i, port in enumerate(range(2000, 2020)):
        events.append(
            PacketEvent(
                timestamp=now + i * 0.01,
                src_ip=attacker,
                dst_ip=victim,
                proto="TCP",
                src_port=51000 + i,
                dst_port=port,
                tcp_flags={"S"},
            )
        )

    # 2) SYN flood: 120 bare-SYN packets in under a second
    for i in range(120):
        events.append(
            PacketEvent(
                timestamp=now + 1 + i * 0.005,
                src_ip=attacker,
                dst_ip=victim,
                proto="TCP",
                src_port=52000 + i,
                dst_port=80,
                tcp_flags={"S"},
            )
        )

    # 3) ICMP (ping) flood: 60 echo requests in under a second
    for i in range(60):
        events.append(
            PacketEvent(
                timestamp=now + 2 + i * 0.01,
                src_ip=attacker,
                dst_ip=victim,
                proto="ICMP",
                icmp_type=8,
            )
        )

    # 4) Blacklisted IP hit
    events.append(
        PacketEvent(
            timestamp=now + 3,
            src_ip="198.51.100.23",
            dst_ip=victim,
            proto="TCP",
            dst_port=22,
            tcp_flags={"S", "A"},
        )
    )

    # 5) Cleartext credential signature over an unencrypted channel
    events.append(
        PacketEvent(
            timestamp=now + 4,
            src_ip="192.0.2.15",
            dst_ip=victim,
            proto="TCP",
            dst_port=21,
            payload="USER admin\r\nPASS Sup3rSecret!\r\n",
        )
    )

    for event in sorted(events, key=lambda e: e.timestamp):
        engine.handle_event(event)

    print("\n=== Demo complete ===")
    print("Alert counts by rule:", engine.alert_manager.summary())
    print(f"Total packets processed: {engine.packet_count}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Lightweight rule-based NIDS")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--demo", action="store_true", help="Run with synthetic demo traffic")
    group.add_argument("--pcap", help="Replay a .pcap file offline")
    group.add_argument("--iface", help="Live-capture on this network interface (requires root)")
    parser.add_argument("--filter", default=None, help="Optional BPF filter for live capture")
    parser.add_argument("--timeout", type=int, default=None, help="Stop live capture after N seconds")
    args = parser.parse_args(argv)

    config = load_config(args.config)
    engine = build_engine(config)

    if args.pcap:
        print(f"Replaying {args.pcap} ...")
        engine.replay_pcap(args.pcap)
        print("Alert counts by rule:", engine.alert_manager.summary())
    elif args.iface:
        print(f"Starting live capture on {args.iface} (Ctrl+C to stop)...")
        try:
            engine.sniff_live(iface=args.iface, bpf_filter=args.filter, timeout=args.timeout)
        except KeyboardInterrupt:
            pass
        print("\nAlert counts by rule:", engine.alert_manager.summary())
    else:
        run_demo(engine)

    return 0


if __name__ == "__main__":
    sys.exit(main())
