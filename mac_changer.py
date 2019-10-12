#!/usr/bin/env python

# so basically to change the mac you have to shutdown first, contone: ifconfig eth0 down
# terus diganti, contoh: ifconfig eth0 hw ether 00:11:22:33:44:55
# up lagi: if config eth0 up


# usage==> python mac_changer --interface [wlan0] --mac [00:11:22:33:44:55]

import subprocess
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to Change its MAC address")
    parser.add_option("-m", "--mac", dest="new_mac", help="New MAC address")
    (ops, arguments) = parser.parse_args()
    if not ops.interface:
        parser.error("[-] Please specify an interface, use --help for more info.")
    elif not ops.new_mac:
        parser.error("[-] Please specify a new mac, use --help for more info.")
    return ops


def change_mac(interface, new_mac):
    print("[+] Changing MAC address for " + interface + " to " + new_mac)
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])


options = get_arguments()
change_mac(options.interface, options.new_mac)
