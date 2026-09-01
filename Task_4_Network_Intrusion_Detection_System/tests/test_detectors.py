"""
Unit tests for the detection engine. These use synthetic PacketEvent
objects rather than live capture, so they run anywhere -- no root
privileges, network interface, or pcap file required.

Run with:
    python -m pytest tests/ -v
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nids.detectors import (
    PacketEvent,
    BlacklistDetector,
    PortScanDetector,
    SynFloodDetector,
    IcmpFloodDetector,
    SignatureDetector,
)
from nids.rules import RuleSet, Signature


def make_rules(**overrides) -> RuleSet:
    base = RuleSet(
        port_scan_window_seconds=10,
        port_scan_unique_ports_threshold=5,
        syn_flood_window_seconds=5,
        syn_flood_threshold=10,
        icmp_flood_window_seconds=5,
        icmp_flood_threshold=10,
        blacklist_ips={"1.2.3.4"},
        signatures=[Signature("test_sig", r"PASSWORD=\w+", "HIGH")],
    )
    for k, v in overrides.items():
        setattr(base, k, v)
    return base


# ---- BlacklistDetector -----------------------------------------------------

def test_blacklist_detector_flags_known_bad_ip():
    rules = make_rules()
    det = BlacklistDetector(rules)
    event = PacketEvent(timestamp=0, src_ip="1.2.3.4", dst_ip="10.0.0.1")
    alerts = det.process(event)
    assert len(alerts) == 1
    assert alerts[0].rule == "blacklist_ip"


def test_blacklist_detector_ignores_clean_ip():
    rules = make_rules()
    det = BlacklistDetector(rules)
    event = PacketEvent(timestamp=0, src_ip="9.9.9.9", dst_ip="10.0.0.1")
    assert det.process(event) == []


# ---- PortScanDetector -------------------------------------------------------

def test_port_scan_detected_above_threshold():
    rules = make_rules(port_scan_unique_ports_threshold=5)
    det = PortScanDetector(rules)
    alerts = []
    for i, port in enumerate(range(1000, 1006)):  # 6 unique ports
        e = PacketEvent(timestamp=i * 0.1, src_ip="5.5.5.5", dst_ip="10.0.0.1",
                         proto="TCP", dst_port=port)
        alerts += det.process(e)
    assert any(a.rule == "port_scan" for a in alerts)


def test_port_scan_not_triggered_below_threshold():
    rules = make_rules(port_scan_unique_ports_threshold=10)
    det = PortScanDetector(rules)
    alerts = []
    for i, port in enumerate(range(1000, 1003)):  # only 3 unique ports
        e = PacketEvent(timestamp=i * 0.1, src_ip="5.5.5.5", dst_ip="10.0.0.1",
                         proto="TCP", dst_port=port)
        alerts += det.process(e)
    assert alerts == []


def test_port_scan_window_expiry():
    """Ports probed outside the sliding window should not count toward the threshold."""
    rules = make_rules(port_scan_unique_ports_threshold=3, port_scan_window_seconds=1)
    det = PortScanDetector(rules)
    alerts = []
    alerts += det.process(PacketEvent(timestamp=0, src_ip="5.5.5.5", proto="TCP", dst_port=1))
    alerts += det.process(PacketEvent(timestamp=0.1, src_ip="5.5.5.5", proto="TCP", dst_port=2))
    # Big time jump -- earlier events should fall out of the window
    alerts += det.process(PacketEvent(timestamp=10, src_ip="5.5.5.5", proto="TCP", dst_port=3))
    assert alerts == []  # only 1 unique port left in the current window


# ---- SynFloodDetector --------------------------------------------------------

def test_syn_flood_detected():
    rules = make_rules(syn_flood_threshold=5)
    det = SynFloodDetector(rules)
    alerts = []
    for i in range(6):
        e = PacketEvent(timestamp=i * 0.01, src_ip="6.6.6.6", proto="TCP",
                         dst_port=80, tcp_flags={"S"})
        alerts += det.process(e)
    assert any(a.rule == "syn_flood" for a in alerts)


def test_syn_ack_not_counted_as_syn_flood():
    """A full three-way handshake (SYN+ACK present) should never be flagged."""
    rules = make_rules(syn_flood_threshold=3)
    det = SynFloodDetector(rules)
    alerts = []
    for i in range(10):
        e = PacketEvent(timestamp=i * 0.01, src_ip="6.6.6.6", proto="TCP",
                         dst_port=80, tcp_flags={"S", "A"})
        alerts += det.process(e)
    assert alerts == []


# ---- IcmpFloodDetector --------------------------------------------------------

def test_icmp_flood_detected():
    rules = make_rules(icmp_flood_threshold=5)
    det = IcmpFloodDetector(rules)
    alerts = []
    for i in range(6):
        e = PacketEvent(timestamp=i * 0.01, src_ip="7.7.7.7", proto="ICMP", icmp_type=8)
        alerts += det.process(e)
    assert any(a.rule == "icmp_flood" for a in alerts)


def test_icmp_reply_not_counted():
    """ICMP echo *replies* (type 0) are normal traffic and must not trigger the flood rule."""
    rules = make_rules(icmp_flood_threshold=3)
    det = IcmpFloodDetector(rules)
    alerts = []
    for i in range(10):
        e = PacketEvent(timestamp=i * 0.01, src_ip="7.7.7.7", proto="ICMP", icmp_type=0)
        alerts += det.process(e)
    assert alerts == []


# ---- SignatureDetector --------------------------------------------------------

def test_signature_match_detected():
    rules = make_rules()
    det = SignatureDetector(rules)
    e = PacketEvent(timestamp=0, src_ip="8.8.8.8", payload="LOGIN PASSWORD=hunter2")
    alerts = det.process(e)
    assert len(alerts) == 1
    assert "test_sig" in alerts[0].rule


def test_signature_no_match_on_clean_payload():
    rules = make_rules()
    det = SignatureDetector(rules)
    e = PacketEvent(timestamp=0, src_ip="8.8.8.8", payload="GET /index.html HTTP/1.1")
    assert det.process(e) == []
