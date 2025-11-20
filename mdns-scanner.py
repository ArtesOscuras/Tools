#!/usr/bin/env python3
import subprocess
import threading
import re
import signal
import sys
import os
import time
import socket
import netifaces
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import shutil



if len(sys.argv) < 2:
    print(f"Usage: sudo {sys.argv[0]} <interface>")
    sys.exit(1)

INTERFACE = sys.argv[1]

try:
    addrs = netifaces.ifaddresses(INTERFACE)
    ipv4 = addrs.get(netifaces.AF_INET)
    if not ipv4:
        print(f"[!] Interface {INTERFACE} has no IPv4 address")
        sys.exit(1)
    ip = ipv4[0]['addr']
    BASE_IP = '.'.join(ip.split('.')[:3]) + '.'
except Exception as e:
    print(f"[!] Could not obtain IP from interface '{INTERFACE}': {e}")
    sys.exit(1)

print(f"[*] Using interface {INTERFACE} (base IP: {BASE_IP})")


def require_root():
    if os.geteuid() != 0:
        print("[ERROR] This script must be run as root.")
        print("        Root privileges are required to run tcpdump and raw packet operations.")
        print("\n        Try again using:\n            sudo python3 scanner.py <interface>\n")
        sys.exit(1)




HAS_NMAP = shutil.which("nmap") is not None
HAS_TCPDUMP = shutil.which("tcpdump") is not None



if HAS_NMAP:
    pass
else:
    print("[WARNING] nmap NOT found. Active scanner disabled.")

if HAS_TCPDUMP:
    pass
else:
    print("[WARNING] tcpdump NOT found. Passive scanner disabled.")



START = 1
END = 255
PORT = "5353"
MAX_THREADS = 20
ACTIVE_INTERVAL = 3

RESET = "\033[0m"
GREEN = "\033[92m"
YELLOW = "\033[93m"


OUI = {
    "28:CF:E9": "Apple, Inc.",
    "DC:A6:32": "Apple, Inc.",
    "40:CB:C0": "Apple, Inc.",
    "F4:F5:D8": "Google, Inc.",
    "3C:5A:B4": "Google Nest",
    "F0:9F:C2": "Amazon",
    "50:02:91": "Espressif",
    "7C:DF:A1": "Espressif",
    "84:CC:A8": "Samsung",
    "00:1A:79": "Sony",
}

hosts = []
lock = threading.Lock()


def oui_lookup(mac):
    if not mac or ":" not in mac:
        return "Unknown"
    prefix = ":".join(mac.upper().split(":")[0:3])
    return OUI.get(prefix, "Unknown")


def get_mac(ip):
    try:
        out = subprocess.check_output(["ip", "neigh"], text=True)
        for line in out.splitlines():
            if ip in line and "lladdr" in line:
                m = re.search(r"lladdr ([0-9a-f:]+)", line)
                if m:
                    return m.group(1)
    except:
        pass
    return None


def update_table():
    os.system("clear")

    if not hosts:
        print("No hosts discovered yet...\n")
        return

    ordered = sorted(hosts, key=lambda h: list(map(int, h["ip"].split("."))))

    print("+----------------+-------------------+----------------------+---------------------+-----------+")
    print("| IP             | MAC               | Vendor               | Last Seen           | Method    |")
    print("+----------------+-------------------+----------------------+---------------------+-----------+")

    for h in ordered:
        method_color = GREEN if h["method"] == "Active" else YELLOW
        vendor = h["vendor"][:20]
        print(f"| {h['ip']:<14} | {h['mac']:<17} | {vendor:<20} | {h['last_seen']:<19} | "
              f"{method_color}{h['method']:<9}{RESET} |")

    print("+----------------+-------------------+----------------------+---------------------+-----------+\n")



def add_host(ip, mac, method, vendor_override=None):
    with lock:
        for h in hosts:
            if h["ip"] == ip:

                h["last_seen"] = datetime.now().strftime("%H:%M:%S")

                if method == "Active":
                    h["method"] = "Active"

                if mac:
                    h["mac"] = mac

                curr = h["vendor"]

                if vendor_override and vendor_override not in ["Unknown", "(Unknown)"]:
                    if curr in ["Unknown", "(Unknown)"]:
                        h["vendor"] = vendor_override
                    elif "." in curr:
                        h["vendor"] = vendor_override

                update_table()
                return

        hosts.append({
            "ip": ip,
            "mac": mac if mac else "(unknown)",
            "vendor": vendor_override if vendor_override else "(Unknown)",
            "method": method,
            "last_seen": datetime.now().strftime("%H:%M:%S")
        })
        update_table()


def passive_sniffer(interface):
    print("[*] Passive mDNS listener started...")

    cmd = ["tcpdump", "-l", "-n", "-i", interface, "udp port 5353"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True)

    for line in proc.stdout:
        m = re.search(r"IP (\d+\.\d+\.\d+\.\d+)", line)
        if not m:
            continue

        ip = m.group(1)
        mac = get_mac(ip)

        vendor_override = None
        mname = re.search(r'PTR\s+"?([^"\s{},]+)', line)
        if mname:
            name = mname.group(1)
            if not name.startswith(("(", "{")):
                vendor_override = name.capitalize()

        add_host(ip, mac, "Passive", vendor_override)


def scan_ip(ip):
    if not HAS_NMAP:
        return

    try:
        result = subprocess.run(
            ["nmap", "-n", "-Pn", "-sU", "-T4", "-p", PORT, ip],
            capture_output=True,
            text=True,
            timeout=10
        )
    except:
        return

    if "zeroconf" not in result.stdout.lower():
        return

    mac = None
    vendor_from_nmap = None

    for line in result.stdout.splitlines():
        if "MAC Address" in line:
            m_mac = re.search(r"MAC Address: ([0-9a-f:]+)", line, re.I)
            if m_mac:
                mac = m_mac.group(1)

            m_vendor = re.search(r"\((.*?)\)", line)
            if m_vendor:
                vendor_from_nmap = m_vendor.group(1).strip()

    add_host(ip, mac, "Active", vendor_override=vendor_from_nmap)


def active_scanner_loop():
    if not HAS_NMAP:
        print("[!] Active scanner disabled (nmap missing).")
        return

    ips = [f"{BASE_IP}{i}" for i in range(START, END + 1)]
    while True:
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            for ip in ips:
                executor.submit(scan_ip, ip)
        time.sleep(ACTIVE_INTERVAL)



if __name__ == "__main__":
    require_root()
    update_table()

    t = threading.Thread(target=passive_sniffer, args=(INTERFACE,), daemon=True)
    t.start()


    if HAS_NMAP:
        try:
            active_scanner_loop()
        except KeyboardInterrupt:
            print("\n[!] Ctrl+C detected. Exiting...")
            sys.exit(0)
    else:
        print("[INFO] Active scanner disabled (nmap missing).")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[!] Ctrl+C detected. Exiting...")
            sys.exit(0)
