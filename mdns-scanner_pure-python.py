#!/usr/bin/env python3
import os
import sys
import time
import socket
import threading
import shutil
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

import netifaces
from scapy.all import ARP, Ether, srp
from zeroconf import Zeroconf, ServiceBrowser, BadTypeInNameException

# =========================
# Optional Nmap support
# =========================
try:
    import nmap
    HAS_PYTHON_NMAP = True
except ImportError:
    HAS_PYTHON_NMAP = False

HAS_NMAP_BIN = shutil.which("nmap") is not None
HAS_NMAP = HAS_PYTHON_NMAP and HAS_NMAP_BIN

# =========================
# Configuration
# =========================
SERVICE_ENUM_TIME = 3
ACTIVE_INTERVAL = 5
THREADS = 20

# =========================
# Shared state
# =========================
hosts = []
lock = threading.Lock()

# =========================
# Utility
# =========================
def now():
    return datetime.now().strftime("%H:%M:%S")

def is_loopback(ip):
    return ip.startswith("127.") or ip == "::1"

def is_vendor_placeholder(name):
    return name.endswith(" (vendor)")

def find_host_by_mac(mac):
    if not mac:
        return None
    for h in hosts:
        if h["mac"] == mac:
            return h
    return None

def find_host_by_ipv4(ip):
    for h in hosts:
        if h["ipv4"] == ip:
            return h
    return None

def update_host(ipv4=None, ipv6=None, mac=None, hostname=None, method=None):
    if ipv4 and is_loopback(ipv4):
        return
    if ipv6 and is_loopback(ipv6):
        return

    with lock:
        host = None

        if mac:
            host = find_host_by_mac(mac)

        if not host and ipv4:
            host = find_host_by_ipv4(ipv4)

        if not host:
            host = {
                "ipv4": None,
                "ipv6": None,
                "mac": mac or "(unknown)",
                "hostname": "",
                "methods": set(),
                "last_seen": now()
            }
            hosts.append(host)

        # IP handling
        if ipv4:
            host["ipv4"] = ipv4
        if ipv6 and not host["ipv4"]:
            host["ipv6"] = ipv6

        # MAC handling
        if mac:
            host["mac"] = mac
        elif not host["mac"]:
            host["mac"] = "(unknown)"

        # =========================
        # Hostname precedence logic
        # =========================
        if hostname:
            if is_vendor_placeholder(hostname):
                # Vendor only if no hostname yet
                if not host["hostname"]:
                    host["hostname"] = hostname
            else:
                # Real hostname always wins
                host["hostname"] = hostname

        if method:
            host["methods"].add(method)

        host["last_seen"] = now()
        print_table()


def print_table():
    os.system("clear")
    print("+--------------------------+-------------------+----------------------+----------------------+")
    print("| IPs                      | MAC               | Hostname             | Methods              |")
    print("+--------------------------+-------------------+----------------------+----------------------+")
    for h in hosts:
        ip_col = h["ipv4"] if h["ipv4"] else (h["ipv6"] or "")
        methods = ", ".join(sorted(h["methods"]))
        print(f"| {ip_col:<24} | {h['mac']:<17} | {h['hostname']:<20} | {methods:<20} |")
    print("+--------------------------+-------------------+----------------------+----------------------+")

# =========================
# ARP Scanner (IPv4)
# =========================
def arp_scanner(interface, cidr):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    ans, _ = srp(pkt, iface=interface, timeout=2, verbose=0)
    for _, r in ans:
        update_host(ipv4=r.psrc, mac=r.hwsrc, method="ARP")

# =========================
# mDNS Passive / Active
# =========================
class PassiveListener:
    def add_service(self, zc, type_, name):
        try:
            info = zc.get_service_info(type_, name, timeout=1000)
            if not info:
                return

            hostname = info.server.rstrip(".")
            for addr in info.addresses:
                if len(addr) == 4:
                    update_host(
                        ipv4=socket.inet_ntoa(addr),
                        hostname=hostname,
                        method="mDNS-Passive"
                    )
                elif len(addr) == 16:
                    update_host(
                        ipv6=socket.inet_ntop(socket.AF_INET6, addr),
                        hostname=hostname,
                        method="mDNSv6-Passive"
                    )
        except BadTypeInNameException:
            pass

    def remove_service(self, *args): pass
    def update_service(self, *args): pass

class ServiceTypeListener:
    def __init__(self):
        self.types = set()
    def add_service(self, zc, type_, name):
        self.types.add(name)
    def remove_service(self, *args): pass
    def update_service(self, *args): pass

class ActiveServiceListener:
    def add_service(self, zc, type_, name):
        info = zc.get_service_info(type_, name, timeout=2000)
        if not info:
            return

        hostname = info.server.rstrip(".")
        for addr in info.addresses:
            if len(addr) == 4:
                update_host(
                    ipv4=socket.inet_ntoa(addr),
                    hostname=hostname,
                    method="mDNS-Active"
                )
            elif len(addr) == 16:
                update_host(
                    ipv6=socket.inet_ntop(socket.AF_INET6, addr),
                    hostname=hostname,
                    method="mDNSv6-Active"
                )

    def remove_service(self, *args): pass
    def update_service(self, *args): pass

def mdns_active_loop(zc):
    while True:
        tl = ServiceTypeListener()
        ServiceBrowser(zc, "_services._dns-sd._udp.local.", tl)
        time.sleep(SERVICE_ENUM_TIME)

        for t in tl.types:
            ServiceBrowser(zc, t, ActiveServiceListener())

        time.sleep(ACTIVE_INTERVAL)

# =========================
# Nmap Active Scanner (UDP 5353)
# =========================
def nmap_udp_scan(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip, arguments="-sU -Pn -p 5353 --open")
    except:
        return

    if ip not in nm.all_hosts():
        return

    if 5353 not in nm[ip].get("udp", {}):
        return

    mac = nm[ip]["addresses"].get("mac")
    hostname = ""

    # Hostname real reportado por Nmap
    if nm[ip]["hostnames"]:
        hostname = nm[ip]["hostnames"][0].get("name", "")

    # Vendor solo si no hay hostname
    if not hostname and mac:
        vendor = nm[ip].get("ven", {}).get(mac)
        if vendor:
            hostname = f"{vendor} (ven)"  # <-- importante el sufijo

    update_host(
        ipv4=ip,
        mac=mac,
        hostname=hostname,
        method="Nmap-Active"
    )

def nmap_active_loop(cidr):
    if not HAS_NMAP:
        return

    net = ipaddress.ip_network(cidr, strict=False)
    targets = [str(ip) for ip in net.hosts()]

    while True:
        with ThreadPoolExecutor(max_workers=THREADS) as exe:
            for ip in targets:
                exe.submit(nmap_udp_scan, ip)
        time.sleep(ACTIVE_INTERVAL)

# =========================
# Main
# =========================
def main():
    if os.geteuid() != 0:
        print("[!] Must be run as root")
        sys.exit(1)

    if len(sys.argv) != 2:
        print(f"Usage: sudo {sys.argv[0]} <interface>")
        sys.exit(1)

    iface = sys.argv[1]
    iface_info = netifaces.ifaddresses(iface).get(netifaces.AF_INET)
    if not iface_info:
        print("[!] No IPv4 on interface")
        sys.exit(1)

    ip = iface_info[0]["addr"]
    netmask = iface_info[0]["netmask"]

    cidr_len = sum(bin(int(o)).count("1") for o in netmask.split("."))
    network = ipaddress.ip_network(f"{ip}/{cidr_len}", strict=False)

    print(f"[*] Interface : {iface}")
    print(f"[*] Local IP  : {ip}")
    print(f"[*] Netmask   : {netmask}")
    print(f"[*] Network   : {network}")
    print(f"[*] Max hosts : {network.num_addresses - 2}")
    print(f"[*] Nmap scan : {'enabled' if HAS_NMAP else 'disabled'}")
    time.sleep(2)

    arp_scanner(iface, str(network))

    zc = Zeroconf()
    ServiceBrowser(zc, "_services._dns-sd._udp.local.", PassiveListener())

    threading.Thread(target=mdns_active_loop, args=(zc,), daemon=True).start()

    if HAS_NMAP:
        threading.Thread(
            target=nmap_active_loop,
            args=(str(network),),
            daemon=True
        ).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        zc.close()
        print("\n[!] Exiting")

if __name__ == "__main__":
    main()

