# NetScope Network Toolkit

NetScope Network Toolkit is a Python-based, multi-purpose network diagnostics and reconnaissance CLI tool.
It bundles several commonly used utilities into a single interactive menu, making it ideal for students,
sysadmins, and cybersecurity enthusiasts who want a quick way to test and inspect networks.

## Features

- Ping Tool
- Traceroute Tool
- Network Scanner (using `nmap`)
- Port Scanner (TCP)
- Bandwidth Monitor
- DNS Lookup Tool
- Packet Sniffer (using `scapy`)
- HTTP Request Simulator
- IP Geolocation Tool
- SSH Client (using `paramiko`)
- Network Performance Tester
- SSL/TLS Certificate Checker

> ⚠️ Use this toolkit only on networks and systems you own or are explicitly authorized to test.

---

## Installation

1. Clone or download this repository.
2. Install Python 3.8+.
3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Ensure required system tools are installed (on Linux-based systems):

```bash
sudo apt install nmap traceroute
```

---

## Usage

Run the main script:

```bash
python netscope.py
```

You will see an interactive menu:

```text
Network Tool Menu:
1. Ping Tool
2. Traceroute Tool
3. Network Scanner
4. Port Scanner
5. Bandwidth Monitor
6. DNS Lookup Tool
7. Packet Sniffer
8. HTTP Request Simulator
9. IP Geolocation Tool
10. SSH Client
11. Network Performance Tester
12. SSL/TLS Certificate Checker
13. Exit
```

Select an option and follow the prompts.

---

## Requirements

Python packages (see `requirements.txt`):
- ping3
- psutil
- requests
- dnspython
- paramiko
- scapy

System tools:
- `nmap` (for network scanning)
- `traceroute` (for route tracing)

---

## Legal & Ethical Notice

This toolkit is intended **only** for educational purposes and authorized security testing.
Do **not** use it against networks or systems without explicit permission. The author assumes
no responsibility for misuse or damages resulting from use of this tool.

---

## Roadmap (Ideas)

- Add Wi‑Fi signal strength analyzer
- Add proxy server helper
- Add automated report generation
- Add parallel/asynchronous scanning

---

## License

MIT License.
