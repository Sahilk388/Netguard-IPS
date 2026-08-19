# NetGuard IPS
<img width="509" height="517" alt="image" src="https://github.com/user-attachments/assets/89ca2a92-a0cc-497e-96d0-b1a1062a4b10" />

A lightweight, real-time Network Intrusion Prevention System built for Kali Linux, developed during my Cybersecurity Summer Internship at SecuredXWave.

NetGuard actively monitors network traffic for **ARP spoofing** and **DNS spoofing** attacks, automatically mitigates threats, and logs every event to a live web dashboard.

## Features

- **ARP Spoofing Detection** — Detects fake routers claiming a trusted IP and automatically restores the correct static ARP entry
- **DNS Spoofing Detection** — Flags untrusted DNS responses and flushes the local DNS cache
- **Automated Mitigation** — Blocks attacker IPs in real time using `iptables`
- **Evasion Defense**
  - MAC-address history tracking to catch spoofing/cloning attempts
  - IP fragmentation inspection to catch IDS-evasion attempts
- **CSV Alert Logging** — Every detection is logged with timestamp, attack type, source IP/MAC, and action taken
- **Live Web Dashboard** — A Flask-based dashboard (auto-refreshing) that shows alerts in plain, non-technical language

## Tech Stack

| Component        | Technology         |
|-------------------|--------------------|
| Packet Sniffing   | Scapy              |
| Detection Engine  | Python 3           |
| Mitigation        | iptables, arp      |
| Dashboard         | Flask              |
| Logging           | CSV                |
| Platform          | Kali Linux         |
<img width="541" height="383" alt="image" src="https://github.com/user-attachments/assets/5e011d4f-391c-4fed-aca5-7580fd2fe1d5" />


## How It Works

1. `netguard_ips.py` sniffs live network traffic on a chosen interface
2. It compares ARP replies against a trusted router MAC and flags mismatches
3. It inspects DNS responses for spoofed/untrusted sources
4. On detection, it automatically applies a static ARP entry and/or blocks the attacker IP via `iptables`
5. All alerts are written to `alerts.csv`
6. `dashboard.py` reads that CSV and displays it as a live-updating web page at `http://127.0.0.1:5000`

## Requirements

- Kali Linux (or any Linux distro with root access)
- Python 3
- Scapy (`pip install scapy`)
- Flask (`pip install flask`)

## How to Run

### 1. Clone the repo
```bash
git clone https://github.com/Sahilk388/Netguard-IPS.git
cd Netguard-IPS
```

### 2. Install dependencies
```bash
pip install scapy flask
```

### 3. Run the detection engine (Terminal 1 — requires root)
```bash
sudo python3 netguard_ips.py
```
You'll be prompted for:
- Network interface (default: `wlan0`)
- Router IP (default: `192.168.1.1`)
- Router MAC address (required)

### 4. Run the dashboard (Terminal 2 — no root needed)
```bash
python3 dashboard.py
```

### 5. Open the dashboard
In your browser, go to:

http://127.0.0.1:5000
<img width="916" height="408" alt="image" src="https://github.com/user-attachments/assets/e85bb6a5-e3ec-4f5f-ac31-b56b4273b55b" />



## Project Context

Built as part of the **SecuredXWave Summer Internship Program 2026** (June 22 – August 8, 2026), focused on practical network security and intrusion prevention concepts.

## Author

**Sahil Khan**
Cybersecurity Intern @ SecuredXWave
