# MayOne Security Framework

**AI‑powered Intrusion Detection & Response for Windows**

![Dashboard Preview](docs/dashboard.png) 

## Features

- Real‑time packet capture (Scapy)
- Rule‑based threat detection (port scan, brute force, DDoS, bursts)
- AI anomaly detection (Isolation Forest) – learns normal traffic
- Risk scoring (0–100) with threat levels: LOW, MEDIUM, HIGH, CRITICAL
- Automatic IP blocking via Windows Firewall (inbound+outbound)
- SQLite database for events, threats, blocked IPs, reports
- Live Flask dashboard with:
  - Traffic statistics
  - Protocol distribution & top ports charts
  - Recent threats table
  - Manual IP block/unblock
- Geo‑IP blocking (optional, MaxMind GeoLite2)
- Scheduled & emergency PDF reports (with logo watermark)
- PCAP export (full buffer)
- Multithreaded, thread‑safe, low CPU usage

## Requirements

- Windows 10/11 (or Windows Server)
- Python 3.10 or higher
- Npcap (with WinPcap API compatibility) – [Download](https://npcap.com)
- Administrator privileges (for sniffing and firewall changes)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/MayOne-Security-Framework.git
   cd MayOne-Security-Framework
   pip install -r requirements.txt
   python main.py