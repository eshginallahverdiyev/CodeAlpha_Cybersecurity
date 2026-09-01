"""
sniffer.py — Bridges Scapy packet capture (live interface or offline .pcap
replay) into the detector pipeline.

Live capture requires elevated privileges (root / CAP_NET_RAW) because it
opens a raw socket. Offline replay works with an ordinary user account and
is the recommended way to demo or test this project.
"""

from __future__ import annotations

import time
from typing import Callable, Iterable

from .alert import Alert, AlertManager
from .detectors import BaseDetector, PacketEvent


def _decode_payload(raw: bytes, max_len: int = 512) -> str:
    try:
        return raw[:max_len].decode("utf-8", errors="ignore")
    except Exception:
        return ""


def scapy_packet_to_event(pkt) -> PacketEvent | None:
    """Converts a live/offline Scapy packet into our protocol-agnostic PacketEvent."""
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.packet import Raw

    if IP not in pkt:
        return None

    ip = pkt[IP]
    ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
    event = PacketEvent(
        timestamp=ts,
        src_ip=ip.src,
        dst_ip=ip.dst,
        length=len(pkt),
    )

    if TCP in pkt:
        tcp = pkt[TCP]
        event.proto = "TCP"
        event.src_port = int(tcp.sport)
        event.dst_port = int(tcp.dport)
        flags = str(tcp.flags)
        event.tcp_flags = {c for c in flags if c.isalpha()}
    elif UDP in pkt:
        udp = pkt[UDP]
        event.proto = "UDP"
        event.src_port = int(udp.sport)
        event.dst_port = int(udp.dport)
    elif ICMP in pkt:
        icmp = pkt[ICMP]
        event.proto = "ICMP"
        event.icmp_type = int(icmp.type)
    else:
        event.proto = "OTHER"

    if Raw in pkt:
        event.payload = _decode_payload(bytes(pkt[Raw].load))

    return event


class NIDSEngine:
    """Feeds PacketEvents through every registered detector and raises alerts."""

    def __init__(self, detectors: Iterable[BaseDetector], alert_manager: AlertManager):
        self.detectors = list(detectors)
        self.alert_manager = alert_manager
        self.packet_count = 0

    def handle_event(self, event: PacketEvent) -> list[Alert]:
        self.packet_count += 1
        fired: list[Alert] = []
        for detector in self.detectors:
            alerts = detector.process(event)
            for a in alerts:
                self.alert_manager.raise_alert(a)
                fired.append(a)
        return fired

    # ---- Live capture -----------------------------------------------------
    def sniff_live(self, iface: str | None = None, bpf_filter: str | None = None,
                    packet_count: int = 0, timeout: int | None = None) -> None:
        """
        Starts live capture on `iface` (None = Scapy's default interface).
        Requires root/administrator privileges.
        """
        from scapy.all import sniff

        def _on_packet(pkt):
            event = scapy_packet_to_event(pkt)
            if event:
                self.handle_event(event)

        sniff(
            iface=iface,
            filter=bpf_filter,
            prn=_on_packet,
            store=False,
            count=packet_count,
            timeout=timeout,
        )

    # ---- Offline replay (no root required; great for demos/tests) --------
    def replay_pcap(self, pcap_path: str) -> None:
        from scapy.utils import rdpcap

        packets = rdpcap(pcap_path)
        for pkt in packets:
            event = scapy_packet_to_event(pkt)
            if event:
                self.handle_event(event)
