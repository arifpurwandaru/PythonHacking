#!/usr/bin/env python

import argparse
import scapy.all as scapy

# in kali linux just type netdiscover -r 192.168.1.1/24


def get_arguments():
    parser = argparse.ArgumentParser(description="Network Scanner - Discover active hosts on a network")
    parser.add_argument("-t", "--target", dest="target", required=True,
                        help="Target IP address or IP range (e.g. 192.168.1.0/24)")
    return parser.parse_args()


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # ini artinya dicombine antara broadcast vs arp_request
    arp_request_broadcast = broadcast / arp_request
    # send the package, this function return 2 list of answered and unanswered
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)

    clients_list = []
    for elem in answered_list:
        client_dict = {"ip": elem[1].psrc, "mac": elem[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


def print_result(results_list):
    print("IP\t\t\tMAC Address\n===========================================================")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


args = get_arguments()
scan_result = scan(args.target)
print_result(scan_result)


    
