#!/usr/bin/env python

import argparse
import scapy.all as scapy
import socket

# in kali linux just type netdiscover -r 192.168.1.1/24


def get_arguments():
    parser = argparse.ArgumentParser(description="Network Scanner - Discover active hosts on a network")
    parser.add_argument("-t", "--target", dest="target", required=True,
                        help="Target IP address or IP range (e.g. 192.168.1.0/24)")
    return parser.parse_args()


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


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # ini artinya dicombine antara broadcast vs arp_request
    arp_request_broadcast = broadcast / arp_request
    # send the package, this function return 2 list of answered and unanswered
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)

    clients_list = []
    for elem in answered_list:
        ip_addr = elem[1].psrc
        mac_addr = elem[1].hwsrc
        client_dict = {
            "ip": ip_addr,
            "mac": mac_addr,
            "hostname": get_hostname(ip_addr),
            "vendor": get_vendor(mac_addr)
        }
        clients_list.append(client_dict)
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
scan_result = scan(args.target)
print_result(scan_result)


    
