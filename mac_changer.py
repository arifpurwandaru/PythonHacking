#!/usr/bin/env python

# so basically to change the mac you have to shutdown first, contone: ifconfig eth0 down
# terus diganti, contoh: ifconfig eth0 hw ether 00:11:22:33:44:55
# up lagi: if config eth0 up


# usage==> python mac_changer --interface [wlan0] --mac [00:11:22:33:44:55]

import subprocess
import optparse
import re


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


def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(["ifconfig", options.interface])
    # buat njajal2 regex pake ini: https://pythex.org/
    mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)
    if mac_address_search_result:
        return mac_address_search_result.group(0)
    else:
        print("[-] Could not read MAC address from " + options.interface)


options = get_arguments()
current_mac = get_current_mac(options.interface)
print("Current MAC = " + str(current_mac))
change_mac(options.interface, options.new_mac)


current_mac = get_current_mac(options.interface)
if(current_mac == options.new_mac):
    print("[+] MAC address was successfully changed to "+ str(options.new_mac))
else:
    print("[-] MAC address DO NOT CHANGED")
