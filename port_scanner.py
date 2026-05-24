# -*- coding: utf-8 -*-
"""
Created on Sat May 23 21:00:40 2026

@author: Renuka
"""

#!/usr/bin/env python3
"""
PORT SCANNER - Cybersecurity Project
Scans a target host for open ports with service detection.
Usage: python port_scanner.py
"""

import socket
import threading
import sys
from datetime import datetime

# ─────────────────────────────────────────
#  COMMON PORTS & SERVICES
# ─────────────────────────────────────────
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB", 5900: "VNC",
    161: "SNMP", 389: "LDAP", 636: "LDAPS",
}

open_ports = []
lock = threading.Lock()


def print_banner():
    print("=" * 55)
    print("        PYTHON PORT SCANNER - Security Tool")
    print("=" * 55)


def resolve_host(target):
    """Resolve hostname to IP."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print(f"[ERROR] Cannot resolve host: {target}")
        sys.exit(1)


def scan_port(ip, port, timeout=1.0):
    """Attempt to connect to a single port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            service = COMMON_SERVICES.get(port, "Unknown")
            with lock:
                open_ports.append((port, service))
            print(f"  [OPEN]  Port {port:5d}  →  {service}")
    except Exception:
        pass


def grab_banner(ip, port):
    """Try to grab a service banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner[:80] if banner else None
    except Exception:
        return None


def scan_range(ip, start_port, end_port, max_threads=100):
    """Scan a range of ports using threading."""
    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(ip, port))
        threads.append(t)
        t.start()

        # Limit concurrent threads
        if len(threads) >= max_threads:
            for t in threads:
                t.join()
            threads = []

    # Wait for remaining threads
    for t in threads:
        t.join()


def print_summary(ip, start_port, end_port, start_time):
    elapsed = datetime.now() - start_time
    print("\n" + "=" * 55)
    print(f"  SCAN COMPLETE")
    print(f"  Target  : {ip}")
    print(f"  Range   : {start_port} - {end_port}")
    print(f"  Time    : {elapsed.seconds}s")
    print(f"  Open    : {len(open_ports)} port(s)")
    print("=" * 55)

    if open_ports:
        print("\n  OPEN PORTS SUMMARY:")
        open_ports.sort()
        for port, service in open_ports:
            print(f"    {port:5d}/tcp   {service}")
    else:
        print("\n  No open ports found.")


def main():
    print_banner()

    target = input("\n  Enter target (IP or hostname): ").strip()
    if not target:
        print("[ERROR] No target provided.")
        sys.exit(1)

    print(f"\n  Scan type:")
    print(f"  1. Quick Scan  (top 1000 ports)")
    print(f"  2. Full Scan   (1 - 65535)")
    print(f"  3. Custom Range")
    choice = input("\n  Choose [1/2/3]: ").strip()

    if choice == "1":
        start_port, end_port = 1, 1000
    elif choice == "2":
        start_port, end_port = 1, 65535
    elif choice == "3":
        try:
            start_port = int(input("  Start port: "))
            end_port = int(input("  End port  : "))
        except ValueError:
            print("[ERROR] Invalid port numbers.")
            sys.exit(1)
    else:
        print("[ERROR] Invalid choice.")
        sys.exit(1)

    ip = resolve_host(target)
    print(f"\n  Target IP : {ip}")
    print(f"  Scanning ports {start_port} to {end_port}...")
    print(f"  Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 55)

    start_time = datetime.now()
    scan_range(ip, start_port, end_port)
    print_summary(ip, start_port, end_port, start_time)

    # Optional banner grabbing
    if open_ports:
        grab = input("\n  Grab banners from open ports? [y/n]: ").strip().lower()
        if grab == "y":
            print("\n  BANNER GRAB:")
            for port, service in sorted(open_ports):
                banner = grab_banner(ip, port)
                if banner:
                    print(f"    Port {port}: {banner}")
                else:
                    print(f"    Port {port}: No banner")
if __name__ == "__main__":
    main()

