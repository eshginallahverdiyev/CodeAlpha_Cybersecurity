"""
detectors.py — Stateful detection logic for the NIDS.

Detectors are decoupled from Scapy on purpose: each one consumes a plain
`PacketEvent` dataclass. This keeps the detection logic pure, deterministic,
and easy to unit test (see tests/test_detectors.py) without needing root
privileges or a live network interface.
"""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from .alert import Alert, Severity
from .rules import RuleSet


@dataclass
class PacketEvent:
    """A protocol-agnostic view of a single captured packet."""

    timestamp: float
    src_ip: str
    dst_ip: str | None = None
    proto: str = "OTHER"          # "TCP" | "UDP" | "ICMP" | "OTHER"
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: set[str] = field(default_factory=set)  # e.g. {"S"}, {"S","A"}
    icmp_type: int | None = None  # 8 = echo request
    payload: str = ""
    length: int = 0


class BaseDetector:
    """Shared cooldown logic so a sustained attack doesn't spam duplicate alerts."""

    name = "base"
    cooldown_seconds = 30

    def __init__(self):
        self._last_alert: dict[str, float] = {}

    def _cooled_down(self, key: str, now: float) -> bool:
        last = self._last_alert.get(key)
        if last is None or (now - last) >= self.cooldown_seconds:
            self._last_alert[key] = now
            return True
        return False

    def process(self, event: PacketEvent) -> list[Alert]:  # pragma: no cover
        raise NotImplementedError


class BlacklistDetector(BaseDetector):
    """Flags any traffic whose source IP is on the static blacklist."""

    name = "blacklist_ip"
    cooldown_seconds = 60

    def __init__(self, rules: RuleSet):
        super().__init__()
        self.blacklist = rules.blacklist_ips

    def process(self, event: PacketEvent) -> list[Alert]:
        if event.src_ip in self.blacklist and self._cooled_down(event.src_ip, event.timestamp):
            return [
                Alert(
                    rule=self.name,
                    severity=Severity.HIGH,
                    src_ip=event.src_ip,
                    dst_ip=event.dst_ip,
                    dst_port=event.dst_port,
                    protocol=event.proto,
                    description=f"Traffic from blacklisted IP {event.src_ip}",
                )
            ]
        return []


class PortScanDetector(BaseDetector):
    """
    Flags a source IP that touches an unusually high number of *distinct*
    destination ports within a sliding time window — the classic signature
    of reconnaissance / port scanning (e.g. nmap).
    """

    name = "port_scan"
    cooldown_seconds = 30

    def __init__(self, rules: RuleSet):
        super().__init__()
        self.window = rules.port_scan_window_seconds
        self.threshold = rules.port_scan_unique_ports_threshold
        # src_ip -> deque[(timestamp, port)]
        self._history: dict[str, deque] = defaultdict(deque)

    def process(self, event: PacketEvent) -> list[Alert]:
        if event.proto not in ("TCP", "UDP") or event.dst_port is None:
            return []

        dq = self._history[event.src_ip]
        dq.append((event.timestamp, event.dst_port))

        cutoff = event.timestamp - self.window
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        unique_ports = {p for _, p in dq}
        if len(unique_ports) >= self.threshold and self._cooled_down(event.src_ip, event.timestamp):
            return [
                Alert(
                    rule=self.name,
                    severity=Severity.MEDIUM,
                    src_ip=event.src_ip,
                    dst_ip=event.dst_ip,
                    protocol=event.proto,
                    description=(
                        f"{len(unique_ports)} distinct ports probed by "
                        f"{event.src_ip} in {self.window}s (threshold={self.threshold})"
                    ),
                    meta={"ports": sorted(unique_ports)[:20]},
                )
            ]
        return []


class SynFloodDetector(BaseDetector):
    """
    Flags a source IP sending an unusually high rate of bare SYN packets
    (SYN set, ACK not set) within a short window — indicative of a SYN
    flood / half-open connection DoS attempt.
    """

    name = "syn_flood"
    cooldown_seconds = 15

    def __init__(self, rules: RuleSet):
        super().__init__()
        self.window = rules.syn_flood_window_seconds
        self.threshold = rules.syn_flood_threshold
        self._history: dict[str, deque] = defaultdict(deque)

    def process(self, event: PacketEvent) -> list[Alert]:
        is_bare_syn = (
            event.proto == "TCP" and "S" in event.tcp_flags and "A" not in event.tcp_flags
        )
        if not is_bare_syn:
            return []

        dq = self._history[event.src_ip]
        dq.append(event.timestamp)
        cutoff = event.timestamp - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()

        if len(dq) >= self.threshold and self._cooled_down(event.src_ip, event.timestamp):
            return [
                Alert(
                    rule=self.name,
                    severity=Severity.HIGH,
                    src_ip=event.src_ip,
                    dst_ip=event.dst_ip,
                    dst_port=event.dst_port,
                    protocol="TCP",
                    description=(
                        f"{len(dq)} SYN packets from {event.src_ip} in "
                        f"{self.window}s (threshold={self.threshold}) — possible SYN flood"
                    ),
                )
            ]
        return []


class IcmpFloodDetector(BaseDetector):
    """Flags an abnormally high rate of ICMP echo requests from one source (ping flood)."""

    name = "icmp_flood"
    cooldown_seconds = 15

    def __init__(self, rules: RuleSet):
        super().__init__()
        self.window = rules.icmp_flood_window_seconds
        self.threshold = rules.icmp_flood_threshold
        self._history: dict[str, deque] = defaultdict(deque)

    def process(self, event: PacketEvent) -> list[Alert]:
        if event.proto != "ICMP" or event.icmp_type != 8:
            return []

        dq = self._history[event.src_ip]
        dq.append(event.timestamp)
        cutoff = event.timestamp - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()

        if len(dq) >= self.threshold and self._cooled_down(event.src_ip, event.timestamp):
            return [
                Alert(
                    rule=self.name,
                    severity=Severity.MEDIUM,
                    src_ip=event.src_ip,
                    dst_ip=event.dst_ip,
                    protocol="ICMP",
                    description=(
                        f"{len(dq)} ICMP echo requests from {event.src_ip} in "
                        f"{self.window}s (threshold={self.threshold}) — possible ping flood"
                    ),
                )
            ]
        return []


class SignatureDetector(BaseDetector):
    """
    Flags packets whose (best-effort decoded) payload matches a known
    plaintext signature — e.g. cleartext credentials over an unencrypted
    protocol, or a known malicious string/command pattern.
    """

    name = "signature_match"
    cooldown_seconds = 20

    def __init__(self, rules: RuleSet):
        super().__init__()
        self.signatures = [
            (sig.name, re.compile(sig.pattern, re.IGNORECASE), sig.severity)
            for sig in rules.signatures
        ]

    def process(self, event: PacketEvent) -> list[Alert]:
        if not event.payload or not self.signatures:
            return []

        alerts = []
        for name, pattern, severity in self.signatures:
            if pattern.search(event.payload):
                key = f"{event.src_ip}:{name}"
                if self._cooled_down(key, event.timestamp):
                    alerts.append(
                        Alert(
                            rule=f"signature:{name}",
                            severity=Severity(severity),
                            src_ip=event.src_ip,
                            dst_ip=event.dst_ip,
                            dst_port=event.dst_port,
                            protocol=event.proto,
                            description=f"Payload matched signature '{name}'",
                        )
                    )
        return alerts


def build_default_detectors(rules: RuleSet) -> list[BaseDetector]:
    """Convenience factory used by the sniffer/CLI to build the standard pipeline."""
    return [
        BlacklistDetector(rules),
        PortScanDetector(rules),
        SynFloodDetector(rules),
        IcmpFloodDetector(rules),
        SignatureDetector(rules),
    ]
