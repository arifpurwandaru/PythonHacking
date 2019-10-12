#!/usr/bin/env python

# so basically to change the mac you have to shutdown first, contone: ifconfig eth0 down
# terus diganti, contoh: ifconfig eth0 hw ether 00:11:22:33:44:55
# up lagi: if config eth0 up


# usage==> python mac_changer --interface [wlan0] --mac [00:11:22:33:44:55]

import subprocess
import optparse

parser = optparse.OptionParser()

parser.add_option("-i", "--interface", dest="interface", help="Interface to Change its MAC address")
parser.add_option("-m", "--mac", dest="new_mac", help="New MAC address")

(options, arguments) = parser.parse_args()
print(arguments)

interface = options.interface
new_mac = options.new_mac

print("[+] Changing MAC address for "+interface+" to "+new_mac)

subprocess.call(["ifconfig", interface, "down"])
subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
subprocess.call(["ifconfig", interface, "up"])
