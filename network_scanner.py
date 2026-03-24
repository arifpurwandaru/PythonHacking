#!/usr/bin/env python

import argparse
import itertools
import scapy.all as scapy
import socket
import sys
import threading
import time

# in kali linux just type netdiscover -r 192.168.1.1/24


def get_arguments():
    parser = argparse.ArgumentParser(description="Network Scanner - Discover active hosts on a network")
    parser.add_argument("-t", "--target", dest="target", required=True,
                        help="Target IP address or IP range (e.g. 192.168.1.0/24)")
    parser.add_argument("-i", "--iface", dest="iface", default=None,
                        help="Network interface to use (e.g. Wi-Fi, eth0). Uses Scapy default if not specified.")
    return parser.parse_args()


def _spinner(message, stop_event):
    """Animated spinner that runs in a background thread."""
    for char in itertools.cycle(["|  ", "/  ", "-  ", "\\  "]):
        if stop_event.is_set():
            break
        sys.stdout.write(f"\r[*] {message} {char}")
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write("\r" + " " * (len(message) + 10) + "\r")
    sys.stdout.flush()


def get_hostname(ip):
    """Attempt to resolve hostname from IP address"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror):
        return "N/A"


def get_vendor(mac):
    """Get vendor/manufacturer from MAC address using Scapy's OUI database"""
    try:
        # Scapy's conf.manufdb can resolve MAC to vendor
        vendor = scapy.conf.manufdb._get_manuf(mac)
        return vendor if vendor else "Unknown"
    except:
        return "Unknown"


def scan(ip, iface=None):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # ini artinya dicombine antara broadcast vs arp_request
    arp_request_broadcast = broadcast / arp_request
    srp_kwargs = {"timeout": 1, "verbose": False}
    if iface:
        srp_kwargs["iface"] = iface

    # Spinner while sending ARP broadcast and waiting for replies
    stop_event = threading.Event()
    spinner_thread = threading.Thread(target=_spinner, args=(f"Scanning {ip} ...", stop_event))
    spinner_thread.start()
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, **srp_kwargs)
    stop_event.set()
    spinner_thread.join()

    total = len(answered_list)
    print(f"[+] Found {total} host(s). Resolving details...")

    clients_list = []
    for i, elem in enumerate(answered_list, 1):
        ip_addr = elem[1].psrc
        mac_addr = elem[1].hwsrc
        sys.stdout.write(f"\r    [{i}/{total}] Resolving {ip_addr} ...")
        sys.stdout.flush()
        client_dict = {
            "ip": ip_addr,
            "mac": mac_addr,
            "hostname": get_hostname(ip_addr),
            "vendor": get_vendor(mac_addr)
        }
        clients_list.append(client_dict)

    if total > 0:
        sys.stdout.write("\r" + " " * 50 + "\r")
        sys.stdout.flush()

    return clients_list


def print_result(results_list):
    print("IP\t\t\tMAC Address\t\t   Hostname\t\t\tVendor")
    print("=" * 100)
    for client in results_list:
        # Format output with proper spacing
        print("{:16}\t{:18} {:25}\t{}".format(
            client["ip"],
            client["mac"],
            client["hostname"][:25],  # Truncate long hostnames
            client["vendor"]
        ))


args = get_arguments()
scan_result = scan(args.target, iface=args.iface)
print_result(scan_result)


    
