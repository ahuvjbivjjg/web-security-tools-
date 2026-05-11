#!/usr/bin/env python3
"""
basic_port_scanner.py
─────────────────────
A simple TCP port scanner for learning and authorized testing.

Usage:
  python basic_port_scanner.py -t 192.168.1.1
  python basic_port_scanner.py -t example.com -p 1-1000
  python basic_port_scanner.py -t example.com -p 80,443,8080
  python basic_port_scanner.py -t example.com -p 1-65535 --threads 200

Author : Ahmed Ashraf Mohamed
Purpose: Cybersecurity portfolio — authorized testing only
"""

import socket
import argparse
import threading
from datetime import datetime


# ── Common ports with service names ─────────────────────────────────────────

COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    135:  "MS-RPC",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    993:  "IMAPS",
    995:  "POP3S",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017:"MongoDB",
}


# ── Results store ────────────────────────────────────────────────────────────

open_ports   = []
results_lock = threading.Lock()


# ── Core scanner ─────────────────────────────────────────────────────────────

def scan_port(host: str, port: int, timeout: float) -> None:
    """Try to connect to host:port. Record if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "unknown")
                with results_lock:
                    open_ports.append((port, service))
    except (socket.error, OSError):
        pass


def resolve_host(host: str) -> str:
    """Resolve hostname to IP address."""
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror:
        print(f"[ERROR] Cannot resolve host: {host}")
        raise SystemExit(1)


def parse_ports(port_arg: str) -> list[int]:
    """
    Parse port argument into a list of integers.
    Accepts: '80', '80,443,8080', '1-1000'
    """
    ports = []
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Basic TCP Port Scanner — for authorized use only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python basic_port_scanner.py -t 192.168.1.1
  python basic_port_scanner.py -t example.com -p 1-1000
  python basic_port_scanner.py -t example.com -p 80,443,8080
        """
    )
    parser.add_argument("-t", "--target",  required=True,  help="Target host or IP")
    parser.add_argument("-p", "--ports",   default="1-1024", help="Ports: '80', '1-1000', '80,443' (default: 1-1024)")
    parser.add_argument("--threads",       type=int, default=100, help="Number of threads (default: 100)")
    parser.add_argument("--timeout",       type=float, default=1.0, help="Connection timeout in seconds (default: 1.0)")
    args = parser.parse_args()

    # Resolve target
    target_ip = resolve_host(args.target)
    ports     = parse_ports(args.ports)

    print("=" * 55)
    print(f"  Basic Port Scanner")
    print(f"  Target : {args.target} ({target_ip})")
    print(f"  Ports  : {len(ports)} ports")
    print(f"  Threads: {args.threads}  |  Timeout: {args.timeout}s")
    print(f"  Start  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 55)
    print("[*] Scanning — please wait...\n")

    # Thread pool scan
    semaphore = threading.Semaphore(args.threads)
    threads   = []

    def worker(port):
        with semaphore:
            scan_port(target_ip, port, args.timeout)

    for port in ports:
        t = threading.Thread(target=worker, args=(port,), daemon=True)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # Results
    print(f"\n{'PORT':<10} {'SERVICE':<20} {'STATE'}")
    print("-" * 40)

    if open_ports:
        for port, service in sorted(open_ports):
            print(f"{port:<10} {service:<20} OPEN")
    else:
        print("  No open ports found.")

    print("-" * 40)
    print(f"\n[+] Scan complete — {len(open_ports)} open port(s) found")
    print(f"[+] Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("\n[!] Only use on systems you own or have written permission to test.")


if __name__ == "__main__":
    main()
