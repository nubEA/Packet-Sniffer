# 🐍 Packet Sniffer CLI (C++)

A multithreaded packet sniffer written in C++ that captures and parses live network traffic from a specified interface. Supports Ethernet, IPv4/IPv6, TCP, UDP, ICMP, and HTTP protocols with clean, color-coded CLI output.

## ✨ Features

- 🔎 **Live Packet Capture** — Monitor traffic in real-time from a given network interface.
- 🧠 **Protocol Parsing** — Parses Ethernet, IP, TCP, UDP, ICMP (v4 & v6), and basic HTTP headers.
- 🎨 **Colored CLI Output** — Highlights different protocols for better readability using ANSI colors.
- ⚙️ **Multithreaded** — Separate threads for capturing and processing packets to improve performance.
- 🎯 **Basic Filtering** — Filter packets by protocol or port (coming soon).

---

## 🚀 Getting Started

### 🧱 Prerequisites

- A Linux-based OS (recommended)
- g++ (with C++17 support or higher)
- Root privileges (to open raw sockets)

### 🔧 Build Instructions

```bash
git clone https://github.com/nubea/packet-sniffer.git
cd packet-sniffer
make
./sniffer <interface>
./sniffer --help
```
