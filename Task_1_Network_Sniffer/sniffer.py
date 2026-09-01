#!/usr/bin/env python3
"""
NetSniff - A Basic Network Packet Sniffer
===========================================

An educational tool for capturing and analyzing network traffic in real time.
Built with Scapy, it displays source/destination IP addresses, protocols,
ports, and payload data for each captured packet, and keeps a running
summary of traffic statistics.

Author: <your-name-here>
License: MIT

IMPORTANT:
    This tool captures live network traffic and generally requires
    administrator/root privileges (or CAP_NET_RAW on Linux) to run.
    Only use it on networks you own or have explicit permission to monitor.
"""

import argparse
import datetime
import signal
import sys
from collections import Counter

try:
    from scapy.all import sniff, get_if_list, wrpcap
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether
    from scapy.layers.dns import DNS, DNSQR
except ImportError:
    print("[!] Scapy is not installed. Install it with:  pip install scapy")
    sys.exit(1)


# --------------------------------------------------------------------------- #
# ANSI colors for readable terminal output (safe no-ops on unsupported term)
# --------------------------------------------------------------------------- #
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"


PROTOCOL_COLORS = {
    "TCP": Colors.BLUE,
    "UDP": Colors.MAGENTA,
    "ICMP": Colors.YELLOW,
    "DNS": Colors.CYAN,
    "OTHER": Colors.GRAY,
}


class PacketStats:
    """Keeps a running tally of everything captured during the session."""

    def __init__(self):
        self.total_packets = 0
        self.protocol_counter = Counter()
        self.top_talkers = Counter()
        self.total_bytes = 0
        self.start_time = datetime.datetime.now()

    def update(self, protocol, size, src_ip=None):
        self.total_packets += 1
        self.protocol_counter[protocol] += 1
        self.total_bytes += size
        if src_ip:
            self.top_talkers[src_ip] += 1

    def summary(self):
        elapsed = (datetime.datetime.now() - self.start_time).total_seconds()
        lines = [
            f"\n{Colors.BOLD}{'=' * 60}{Colors.RESET}",
            f"{Colors.BOLD}Capture Summary{Colors.RESET}",
            f"{'=' * 60}",
            f"Duration        : {elapsed:.2f} s",
            f"Total packets   : {self.total_packets}",
            f"Total data      : {self.total_bytes / 1024:.2f} KB",
            f"\n{Colors.BOLD}Protocol breakdown:{Colors.RESET}",
        ]
        for proto, count in self.protocol_counter.most_common():
            pct = (count / self.total_packets * 100) if self.total_packets else 0
            lines.append(f"  {proto:<8} {count:>6}  ({pct:5.1f}%)")

        if self.top_talkers:
            lines.append(f"\n{Colors.BOLD}Top source IPs:{Colors.RESET}")
            for ip, count in self.top_talkers.most_common(5):
                lines.append(f"  {ip:<18} {count} packets")

        lines.append(f"{'=' * 60}\n")
        return "\n".join(lines)


class Sniffer:
    def __init__(self, iface=None, bpf_filter=None, count=0, verbose=False,
                 save_file=None, payload_len=64):
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.count = count
        self.verbose = verbose
        self.save_file = save_file
        self.payload_len = payload_len
        self.stats = PacketStats()
        self.captured_packets = []

    # ------------------------------------------------------------------ #
    def _format_payload(self, raw_bytes):
        """Return a printable, truncated preview of the raw payload."""
        if not raw_bytes:
            return None
        snippet = raw_bytes[: self.payload_len]
        try:
            text = snippet.decode("utf-8", errors="replace")
            text = "".join(ch if ch.isprintable() else "." for ch in text)
        except Exception:
            text = snippet.hex()
        suffix = "..." if len(raw_bytes) > self.payload_len else ""
        return text + suffix

    # ------------------------------------------------------------------ #
    def _process_packet(self, packet):
        """Callback invoked by Scapy for every captured packet."""
        self.captured_packets.append(packet)
        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

        if IP not in packet:
            # Non-IP traffic (e.g. ARP) — log briefly and move on.
            self.stats.update("OTHER", len(packet))
            if self.verbose:
                print(f"{Colors.GRAY}[{timestamp}] Non-IP packet: {packet.summary()}{Colors.RESET}")
            return

        ip_layer = packet[IP]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        size = len(packet)
        protocol = "OTHER"
        detail = ""
        payload = None

        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            protocol = "DNS"
            try:
                qname = packet[DNSQR].qname.decode(errors="replace")
            except Exception:
                qname = str(packet[DNSQR].qname)
            detail = f"query={qname}"
        elif TCP in packet:
            protocol = "TCP"
            tcp_layer = packet[TCP]
            detail = f"{src_ip}:{tcp_layer.sport} -> {dst_ip}:{tcp_layer.dport} [flags={tcp_layer.flags}]"
            if packet.haslayer("Raw"):
                payload = bytes(packet["Raw"].load)
        elif UDP in packet:
            protocol = "UDP"
            udp_layer = packet[UDP]
            detail = f"{src_ip}:{udp_layer.sport} -> {dst_ip}:{udp_layer.dport}"
            if packet.haslayer("Raw"):
                payload = bytes(packet["Raw"].load)
        elif ICMP in packet:
            protocol = "ICMP"
            icmp_layer = packet[ICMP]
            detail = f"type={icmp_layer.type} code={icmp_layer.code}"
        else:
            detail = f"proto_num={ip_layer.proto}"

        self.stats.update(protocol, size, src_ip)

        color = PROTOCOL_COLORS.get(protocol, Colors.GRAY)
        header = (
            f"{Colors.GRAY}[{timestamp}]{Colors.RESET} "
            f"{color}{Colors.BOLD}{protocol:<5}{Colors.RESET} "
            f"{Colors.GREEN}{src_ip:<15}{Colors.RESET} -> "
            f"{Colors.RED}{dst_ip:<15}{Colors.RESET} "
            f"({size} bytes)"
        )
        print(header)
        if detail:
            print(f"    {Colors.GRAY}{detail}{Colors.RESET}")

        if payload:
            preview = self._format_payload(payload)
            if preview:
                print(f"    {Colors.YELLOW}Payload:{Colors.RESET} {preview}")

        if self.verbose:
            print(f"    {Colors.GRAY}{packet.summary()}{Colors.RESET}")

        print()

    # ------------------------------------------------------------------ #
    def start(self):
        print(f"{Colors.BOLD}{Colors.CYAN}NetSniff — Basic Network Packet Sniffer{Colors.RESET}")
        print(f"Interface : {self.iface or 'default'}")
        print(f"Filter    : {self.bpf_filter or 'none (all traffic)'}")
        print(f"Count     : {'unlimited' if self.count == 0 else self.count}")
        print(f"{Colors.GRAY}Press Ctrl+C to stop capturing.{Colors.RESET}\n")

        try:
            sniff(
                iface=self.iface,
                filter=self.bpf_filter,
                prn=self._process_packet,
                count=self.count,
                store=False,
            )
        except PermissionError:
            print(f"{Colors.RED}[!] Permission denied. Try running with sudo/administrator rights.{Colors.RESET}")
            sys.exit(1)
        except OSError as exc:
            print(f"{Colors.RED}[!] Network error: {exc}{Colors.RESET}")
            sys.exit(1)
        finally:
            self._finish()

    def _finish(self):
        print(self.stats.summary())
        if self.save_file and self.captured_packets:
            wrpcap(self.save_file, self.captured_packets)
            print(f"{Colors.GREEN}[+] Saved {len(self.captured_packets)} packets to {self.save_file}{Colors.RESET}")


def handle_sigint(sig, frame):
    print(f"\n{Colors.YELLOW}[!] Capture interrupted by user.{Colors.RESET}")
    raise KeyboardInterrupt


def parse_args():
    parser = argparse.ArgumentParser(
        description="NetSniff — a basic educational network packet sniffer.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-i", "--interface", default=None,
                         help="Network interface to sniff on (default: Scapy's default)")
    parser.add_argument("-f", "--filter", default=None,
                         help="BPF filter string, e.g. 'tcp port 80' or 'udp'")
    parser.add_argument("-c", "--count", type=int, default=0,
                         help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-v", "--verbose", action="store_true",
                         help="Show extra packet detail (Scapy summary line)")
    parser.add_argument("-o", "--output", default=None,
                         help="Save captured packets to a .pcap file")
    parser.add_argument("--payload-len", type=int, default=64,
                         help="Max number of payload bytes/characters to preview")
    parser.add_argument("--list-interfaces", action="store_true",
                         help="List available network interfaces and exit")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.list_interfaces:
        print(f"{Colors.BOLD}Available interfaces:{Colors.RESET}")
        for iface in get_if_list():
            print(f"  - {iface}")
        return

    signal.signal(signal.SIGINT, handle_sigint)

    sniffer = Sniffer(
        iface=args.interface,
        bpf_filter=args.filter,
        count=args.count,
        verbose=args.verbose,
        save_file=args.output,
        payload_len=args.payload_len,
    )

    try:
        sniffer.start()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
