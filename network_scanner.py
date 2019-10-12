#!/usr/bin/env python

import scapy.all as scapy


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # ini artinya dicombine antara broadcast vs arp_request
    arp_request_broadcast = broadcast/arp_request
    # send the package, this function return 2 list of answered and unanswered
    answered, unanswered = scapy.srp(arp_request_broadcast, timeout=1)

    print(answered.summary())

scan("192.168.1.1/24")