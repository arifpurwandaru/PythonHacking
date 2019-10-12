#!/usr/bin/env python

import scapy.all as scapy


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # ini artinya dicombine antara broadcast vs arp_request
    arp_request_broadcast = broadcast / arp_request
    # send the package, this function return 2 list of answered and unanswered
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)
    print("IP\t\t\tMAC Address\n===========================================================")
    for elem in answered_list:
        print(elem[1].psrc+"\t\t"+elem[1].hwsrc)   # supaya tau nama fieldnya dishow dulu ==> elem[1].show()


scan("192.168.1.1/24")
