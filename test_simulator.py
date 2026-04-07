#!/usr/bin/env python3
import time
import random
from scapy.all import IP, TCP, UDP, send

def port_scan(target_ip="127.0.0.1", ports=range(1, 100)):
    print(f"[SIM] Port scanning {target_ip}...")
    for port in ports:
        pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.01)

def brute_force(target_ip="127.0.0.1", port=22, attempts=50):
    print(f"[SIM] Brute force simulation on {target_ip}:{port}")
    for i in range(attempts):
        pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.05)

def ddos_flood(target_ip="127.0.0.1", duration=5, rate=200):
    print(f"[SIM] DDoS flood on {target_ip} for {duration}s at {rate} pps")
    end = time.time() + duration
    while time.time() < end:
        for _ in range(rate):
            pkt = IP(dst=target_ip)/UDP(dport=random.randint(1, 65535))
            send(pkt, verbose=False)
        time.sleep(1)

if __name__ == "__main__":
    print("Choose attack: 1=Port Scan, 2=Brute Force, 3=DDoS Flood")
    choice = input("> ")
    if choice == "1":
        port_scan()
    elif choice == "2":
        brute_force()
    elif choice == "3":
        ddos_flood()
    else:
        print("Invalid")