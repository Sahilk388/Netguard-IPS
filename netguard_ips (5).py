#!/usr/bin/env python3
"""
====================================================================
  NetGuard IPS - Active Network Defense Engine (v2.0)
  Description: Real-time ARP & DNS Spoofing Detection & Auto-Mitigation
               + CSV logging for GUI dashboard
  Platform   : Linux / Kali Linux
====================================================================
"""

import os
import sys
import csv
import time
from datetime import datetime
from scapy.all import sniff, ARP, IP, UDP, DNS, DNSRR

# ------------------------------------------------------------------
# DYNAMIC CONFIGURATION GLOBALS
# ------------------------------------------------------------------
INTERFACE = "wlan0"
ROUTER_IP = "192.168.1.1"
REAL_ROUTER_MAC = ""
BLOCKED_IPS = set()

# MAC change history: {ip: [(timestamp, mac), ...]}  -> catches MAC-spoof evasion
MAC_HISTORY = {}
MAC_CHANGE_WINDOW_SECONDS = 300  # flag if MAC for same IP changes within 5 minutes

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alerts.csv")


# ------------------------------------------------------------------
# LOGGING
# ------------------------------------------------------------------
def init_log_file():
    """Agar log file nahi hai to header ke saath create karta hai."""
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "attack_type", "source_ip", "source_mac", "detail", "action_taken"])


def log_alert(attack_type, source_ip, source_mac, detail, action_taken):
    """Har detection ko CSV file mein append karta hai (GUI isi ko padhta hai)."""
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            attack_type,
            source_ip,
            source_mac,
            detail,
            action_taken,
        ])


# ------------------------------------------------------------------
# BANNER & DYNAMIC INPUTS
# ------------------------------------------------------------------
def show_banner():
    os.system("clear")
    banner = """
\033[1;36m
 ███╗   ██╗███████╗████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
 ██╔██╗ ██║█████╗     ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
 ██║╚██╗██║██╔══╝     ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
 ██║ ╚████║███████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
 ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
\033[0m
\033[1;33m════════════════════════════════════════════════════════════════════\033[0m
\033[1;35m   Intrusion Prevention System  |  v2.0  |  Developed by MrSteve\033[0m
\033[1;33m════════════════════════════════════════════════════════════════════\033[0m
\033[1;30m [*] Active shields   : ARP spoofing, DNS spoofing, fragmentation
 [*] Mode             : Auto-detection & auto-mitigation
 [*] Evasion defense  : MAC history tracking + fragment inspection
 [*] Logging          : alerts.csv (feeds the live dashboard)\033[0m
"""
    print(banner)


def get_user_inputs():
    global INTERFACE, ROUTER_IP, REAL_ROUTER_MAC

    print("\033[1;34m[+] Network Setup (Enter Details Below):\033[0m")

    iface_in = input(" -> Interface (Press Enter for 'wlan0'): ").strip()
    INTERFACE = iface_in if iface_in else "wlan0"

    ip_in = input(" -> Router IP (Press Enter for '192.168.1.1'): ").strip()
    ROUTER_IP = ip_in if ip_in else "192.168.1.1"

    mac_in = input(" -> Router MAC (e.g. aa:bb:cc:dd:ee:ff): ").strip()
    while not mac_in:
        print("\033[1;31m[!] Router MAC address is required for spoof detection!\033[0m")
        mac_in = input(" -> Router MAC: ").strip()

    REAL_ROUTER_MAC = mac_in.lower()

    print("\n\033[1;32m[*] Initializing NetGuard Engine", end="")
    for _ in range(4):
        time.sleep(0.3)
        print(".", end="", flush=True)
    print(" [READY]\033[0m\n")


# ------------------------------------------------------------------
# PREVENTION / MITIGATION FUNCTIONS
# ------------------------------------------------------------------
def apply_static_arp(router_ip, router_mac):
    print(f"\033[1;33m[DEFENSE] Applying Static ARP: {router_ip} -> {router_mac}\033[0m")
    os.system(f"sudo arp -s {router_ip} {router_mac} > /dev/null 2>&1")


def block_attacker_ip(attacker_ip):
    if attacker_ip not in BLOCKED_IPS and attacker_ip not in ("0.0.0.0", ROUTER_IP):
        print(f"\033[1;31m[DEFENSE] Blocking Attacker IP ({attacker_ip}) via iptables...\033[0m")
        os.system(f"sudo iptables -A INPUT -s {attacker_ip} -j DROP")
        BLOCKED_IPS.add(attacker_ip)
        print(f"\033[1;32m[STATUS] Attacker {attacker_ip} ISOLATED.\033[0m")


def flush_dns_cache():
    print("\033[1;33m[DEFENSE] Flushing local DNS cache...\033[0m")
    os.system("sudo systemd-resolve --flush-caches > /dev/null 2>&1")


# ------------------------------------------------------------------
# EVASION DEFENSE HELPERS
# ------------------------------------------------------------------
def check_fragmentation(packet):
    """
    Attacker packets ko chhote fragments mein tod kar IDS ko bypass karne
    ki koshish kar sakta hai. Ye function har IP packet ke fragment flags
    check karta hai aur suspicious fragmentation flag kar deta hai.
    """
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        more_fragments = (ip_layer.flags == 1) or (int(ip_layer.frag) > 0)
        if more_fragments:
            print("\n\033[1;33m[WARNING] Fragmented packet detected - possible IDS evasion attempt\033[0m")
            print(f"   Source IP : {ip_layer.src}")
            log_alert(
                attack_type="Fragmentation Evasion Attempt",
                source_ip=ip_layer.src,
                source_mac="-",
                detail="Fragmented packet seen; possible attempt to hide payload from IDS",
                action_taken="Flagged for review",
            )
            return True
    return False


def check_mac_consistency(ip, mac):
    """
    Attacker apna MAC address 'macchanger' jaisay tool se router ke asal
    MAC jaisa bana sakta hai. Ye function track karta hai ke kisi IP ka
    MAC achanak (thodi der mein) badal to nahi gaya - jo cloning ka signal hai.
    """
    now = time.time()
    history = MAC_HISTORY.setdefault(ip, [])

    if history:
        last_time, last_mac = history[-1]
        if last_mac != mac and (now - last_time) < MAC_CHANGE_WINDOW_SECONDS:
            print("\n\033[1;33m[WARNING] Sudden MAC change detected for same IP - possible spoofing/cloning\033[0m")
            print(f"   IP        : {ip}")
            print(f"   Old MAC   : {last_mac}")
            print(f"   New MAC   : {mac}")
            log_alert(
                attack_type="MAC Change Anomaly",
                source_ip=ip,
                source_mac=mac,
                detail=f"MAC changed from {last_mac} within {MAC_CHANGE_WINDOW_SECONDS}s",
                action_taken="Flagged for review",
            )

    history.append((now, mac))
    if len(history) > 20:
        history.pop(0)


# ------------------------------------------------------------------
# DETECTION ENGINE
# ------------------------------------------------------------------
def process_packet(packet):
    # 0. FRAGMENTATION EVASION CHECK (runs on every IP packet)
    check_fragmentation(packet)

    # 1. ARP SPOOFING DETECTION
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc.lower()

        check_mac_consistency(src_ip, src_mac)

        if src_ip == ROUTER_IP and src_mac != REAL_ROUTER_MAC.lower():
            print("\n" + "\033[1;31m=" * 55)
            print("[CRITICAL ALERT] ARP SPOOFING ATTACK DETECTED!")
            print(f"   Spoofed Target IP : {src_ip}")
            print(f"   Attacker Fake MAC : {src_mac}")
            print(f"   Trusted Router MAC: {REAL_ROUTER_MAC}")
            print("=" * 55 + "\033[0m")

            apply_static_arp(ROUTER_IP, REAL_ROUTER_MAC)
            block_attacker_ip(src_ip)

            log_alert(
                attack_type="ARP Spoofing",
                source_ip=src_ip,
                source_mac=src_mac,
                detail=f"Fake MAC claimed router IP {ROUTER_IP}",
                action_taken="Static ARP restored + IP blocked",
            )

    # 2. DNS SPOOFING DETECTION
    if packet.haslayer(DNS) and packet.haslayer(DNSRR):
        dns_layer = packet[DNS]
        if packet.haslayer(IP):
            sender_ip = packet[IP].src
            query_name = dns_layer.qd.qname.decode("utf-8") if dns_layer.qd else "Unknown"

            if sender_ip != ROUTER_IP and sender_ip not in ("8.8.8.8", "1.1.1.1"):
                print("\n" + "\033[1;31m=" * 55)
                print("[CRITICAL ALERT] SUSPICIOUS DNS RESPONSE DETECTED!")
                print(f"   Domain Name    : {query_name}")
                print(f"   Untrusted Source: {sender_ip}")
                print("=" * 55 + "\033[0m")

                flush_dns_cache()
                block_attacker_ip(sender_ip)

                log_alert(
                    attack_type="DNS Spoofing",
                    source_ip=sender_ip,
                    source_mac="-",
                    detail=f"Untrusted DNS response for {query_name}",
                    action_taken="DNS cache flushed + IP blocked",
                )


# ------------------------------------------------------------------
# MAIN EXECUTION
# ------------------------------------------------------------------
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("\033[1;31m[ERROR] NetGuard requires root privileges! Run with 'sudo'.\033[0m")
        sys.exit(1)

    init_log_file()
    show_banner()
    get_user_inputs()

    print(f"\033[1;34m[*] Monitoring active on interface '{INTERFACE}'...\033[0m")
    print(f"\033[1;30m[*] Logging alerts to: {LOG_FILE}\033[0m")
    print("\033[1;30m[*] Press Ctrl+C to exit safely.\033[0m\n")

    try:
        sniff(iface=INTERFACE, filter="arp or udp port 53", prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\n\033[1;31m[*] NetGuard IPS stopped. Exiting safely.\033[0m")
        sys.exit(0)
    except Exception as err:
        print(f"\n\033[1;31m[ERROR] Sniffer error: {err}\033[0m")
        sys.exit(1)
