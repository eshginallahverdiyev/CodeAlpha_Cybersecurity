# 🕵️ NetSniff — Basic Network Packet Sniffer

A lightweight, educational network packet sniffer built in Python with [Scapy](https://scapy.net/). NetSniff captures live traffic on a chosen network interface and displays useful, human-readable details for every packet: source/destination IP addresses, protocol, ports, and a preview of the payload — plus a live-updating statistics summary when the capture ends.

This project was built as part of a hands-on exercise in understanding **how data flows through a network** and the fundamentals of protocol analysis.

---

## ✨ Features

- 📡 **Live packet capture** on any available network interface
- 🔍 **Protocol detection** — TCP, UDP, ICMP, and DNS are parsed and labeled
- 🎯 **BPF filtering** — capture only the traffic you care about (e.g. `tcp port 443`)
- 📦 **Payload preview** — see a readable snippet of each packet's raw data
- 📊 **Session statistics** — protocol breakdown, top talkers, total data captured
- 💾 **PCAP export** — save your capture to a `.pcap` file for Wireshark or later analysis
- 🎨 **Color-coded terminal output** for fast visual scanning
- 🧩 Clean, single-file, well-commented codebase — easy to read and extend

---

## 📸 Example Output

```
NetSniff — Basic Network Packet Sniffer
Interface : eth0
Filter    : tcp port 80
Count     : unlimited
Press Ctrl+C to stop capturing.

[14:32:10.421] TCP   192.168.1.15    -> 93.184.216.34  (74 bytes)
    192.168.1.15:52344 -> 93.184.216.34:80 [flags=S]

[14:32:10.512] TCP   93.184.216.34   -> 192.168.1.15   (60 bytes)
    93.184.216.34:80 -> 192.168.1.15:52344 [flags=SA]

============================================================
Capture Summary
============================================================
Duration        : 12.84 s
Total packets   : 48
Total data      : 6.21 KB

Protocol breakdown:
  TCP           40  ( 83.3%)
  DNS            5  ( 10.4%)
  UDP            3  (  6.3%)

Top source IPs:
  192.168.1.15       24 packets
  93.184.216.34      20 packets
============================================================
```

---

## 🛠️ Requirements

- Python **3.8+**
- [Scapy](https://scapy.net/) (installed via `requirements.txt`)
- **Administrator / root privileges** — raw packet capture requires elevated permissions
- On Windows: [Npcap](https://npcap.com/) must be installed (Scapy uses it under the hood)

---

## 📥 Installation

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/netsniff.git
cd netsniff

# 2. (Recommended) create a virtual environment
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Usage

> ⚠️ Packet capture requires elevated privileges. Run with `sudo` on Linux/macOS, or an Administrator terminal on Windows.

**Basic capture on the default interface:**
```bash
sudo python3 sniffer.py
```

**Capture on a specific interface:**
```bash
sudo python3 sniffer.py -i eth0
```

**List available interfaces:**
```bash
python3 sniffer.py --list-interfaces
```

**Apply a BPF filter (only HTTP traffic):**
```bash
sudo python3 sniffer.py -f "tcp port 80"
```

**Capture exactly 100 packets and save them to a pcap file:**
```bash
sudo python3 sniffer.py -c 100 -o capture.pcap
```

**Verbose mode (extra Scapy detail per packet):**
```bash
sudo python3 sniffer.py -v
```

### CLI Options

| Flag | Description | Default |
|---|---|---|
| `-i`, `--interface` | Network interface to sniff on | system default |
| `-f`, `--filter` | BPF filter string (e.g. `udp`, `tcp port 443`) | none (all traffic) |
| `-c`, `--count` | Number of packets to capture (`0` = unlimited) | `0` |
| `-v`, `--verbose` | Show extra packet detail | off |
| `-o`, `--output` | Save capture to a `.pcap` file | none |
| `--payload-len` | Max payload bytes/characters shown per packet | `64` |
| `--list-interfaces` | List interfaces and exit | — |

Press **Ctrl+C** at any time to stop the capture and print the session summary.

---

## 🧠 How It Works

1. **Capture** — Scapy's `sniff()` function hooks into the OS's raw socket / libpcap layer to receive packets as they arrive on the network interface.
2. **Parse** — Each packet is inspected layer by layer (`Ether` → `IP` → `TCP`/`UDP`/`ICMP` → `Raw`) to extract addressing, protocol, and payload information.
3. **Classify** — Packets are labeled by protocol (TCP, UDP, ICMP, DNS) so traffic patterns are easy to spot at a glance.
4. **Report** — Every packet is printed in real time, and running statistics are tallied and displayed when the capture stops.

---

## ⚖️ Legal & Ethical Notice

This tool is intended **strictly for educational purposes** — to learn how packets are structured and how data moves across a network.

- Only capture traffic on networks you **own** or have **explicit, written permission** to monitor.
- Unauthorized packet interception may violate local, national, or international law (e.g. wiretapping / computer misuse statutes).
- The author(s) of this project accept no liability for misuse of this software.

---

## 🗺️ Roadmap / Ideas for Contribution

- [ ] Add HTTP request/response parsing (method, host, headers)
- [ ] Export capture summary as JSON/CSV
- [ ] Add a simple TUI dashboard (e.g. with `rich` or `textual`)
- [ ] IPv6 support
- [ ] Alerting rules (e.g. flag unusual port scans)

Contributions are welcome — feel free to open an issue or submit a pull request!

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 🙏 Acknowledgements

Built with [Scapy](https://scapy.net/), a powerful Python library for packet manipulation and network analysis.
