#!/usr/bin/env python

import argparse
import scapy.all as scapy
from scapy.layers import http


def get_arguments():
    parser = argparse.ArgumentParser(description="Packet Sniffer - Capture and analyze network traffic")
    parser.add_argument("-i", "--interface", dest="interface", 
                        help="Network interface to sniff on (e.g., eth0, wlan0)")
    parser.add_argument("-c", "--count", dest="count", type=int, default=0,
                        help="Number of packets to capture (0 = infinite, default: 0)")
    parser.add_argument("-f", "--filter", dest="filter", default="",
                        help="BPF filter (e.g., 'tcp port 80', 'host 192.168.1.1')")
    return parser.parse_args()


def get_url(packet):
    """Extract URL from HTTP request"""
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        return url.decode() if isinstance(url, bytes) else url
    return None


def get_credentials(packet):
    """Extract potential credentials from HTTP packets"""
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        # Convert bytes to string for searching
        load_str = load.decode('utf-8', errors='ignore')
        
        # Keywords that might indicate credentials
        keywords = ["username", "user", "login", "password", "pass", "email"]
        for keyword in keywords:
            if keyword in load_str.lower():
                return load_str
    return None


def process_packet(packet):
    """Process and extract information from captured packets"""
    
    # Print separator for readability
    print("\n" + "=" * 80)
    
    # Basic packet info
    print(f"[+] Packet captured at: {packet.time}")
    
    # Check if packet has IP layer
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        
        print(f"[*] Source IP: {ip_src}")
        print(f"[*] Destination IP: {ip_dst}")
        print(f"[*] Protocol: {protocol}")
        
        # TCP layer information
        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            flags = packet[scapy.TCP].flags
            
            print(f"[*] Protocol Type: TCP")
            print(f"[*] Source Port: {src_port}")
            print(f"[*] Destination Port: {dst_port}")
            print(f"[*] TCP Flags: {flags}")
            
            # HTTP traffic analysis
            if packet.haslayer(http.HTTPRequest):
                print("[!] HTTP Request Detected!")
                
                # Extract HTTP method
                method = packet[http.HTTPRequest].Method.decode()
                print(f"    Method: {method}")
                
                # Extract URL
                url = get_url(packet)
                if url:
                    print(f"    URL: {url}")
                
                # Extract User-Agent if present
                if packet[http.HTTPRequest].User_Agent:
                    user_agent = packet[http.HTTPRequest].User_Agent.decode()
                    print(f"    User-Agent: {user_agent}")
            
            if packet.haslayer(http.HTTPResponse):
                print("[!] HTTP Response Detected!")
                status_code = packet[http.HTTPResponse].Status_Code.decode()
                print(f"    Status Code: {status_code}")
            
            # Check for credentials
            credentials = get_credentials(packet)
            if credentials:
                print("[!] Possible Credentials/Login Data Found:")
                print(f"    {credentials[:200]}...")  # Print first 200 chars
        
        # UDP layer information
        elif packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            
            print(f"[*] Protocol Type: UDP")
            print(f"[*] Source Port: {src_port}")
            print(f"[*] Destination Port: {dst_port}")
            
            # DNS queries
            if packet.haslayer(scapy.DNSQR):
                dns_query = packet[scapy.DNSQR].qname.decode()
                print(f"[!] DNS Query: {dns_query}")
            
            # DNS responses
            if packet.haslayer(scapy.DNSRR):
                dns_response = packet[scapy.DNSRR].rrname.decode()
                dns_ip = packet[scapy.DNSRR].rdata
                print(f"[!] DNS Response: {dns_response} -> {dns_ip}")
        
        # ICMP layer information
        elif packet.haslayer(scapy.ICMP):
            icmp_type = packet[scapy.ICMP].type
            icmp_code = packet[scapy.ICMP].code
            
            print(f"[*] Protocol Type: ICMP")
            print(f"[*] ICMP Type: {icmp_type}")
            print(f"[*] ICMP Code: {icmp_code}")
    
    # ARP packets
    elif packet.haslayer(scapy.ARP):
        arp_op = packet[scapy.ARP].op
        arp_src_ip = packet[scapy.ARP].psrc
        arp_dst_ip = packet[scapy.ARP].pdst
        arp_src_mac = packet[scapy.ARP].hwsrc
        
        print(f"[*] Protocol Type: ARP")
        print(f"[*] Operation: {'Request' if arp_op == 1 else 'Reply'}")
        print(f"[*] Source IP: {arp_src_ip}")
        print(f"[*] Source MAC: {arp_src_mac}")
        print(f"[*] Destination IP: {arp_dst_ip}")
    
    # Raw data preview (if available)
    if packet.haslayer(scapy.Raw):
        raw_load = packet[scapy.Raw].load
        # Show first 100 bytes of raw data
        print(f"[*] Raw Data (first 100 bytes): {raw_load[:100]}")


def sniff_packets(interface, count, bpf_filter):
    """Start packet sniffing"""
    if interface:
        print(f"[*] Starting packet sniffer on interface: {interface}")
    else:
        print(f"[*] Starting packet sniffer on default interface")
    
    if bpf_filter:
        print(f"[*] Using BPF filter: {bpf_filter}")
    
    if count > 0:
        print(f"[*] Capturing {count} packets...")
    else:
        print(f"[*] Capturing packets (Press Ctrl+C to stop)...")
    
    print("=" * 80)
    
    try:
        # Start sniffing
        if interface:
            scapy.sniff(iface=interface, store=False, prn=process_packet, 
                       count=count, filter=bpf_filter)
        else:
            scapy.sniff(store=False, prn=process_packet, 
                       count=count, filter=bpf_filter)
    except KeyboardInterrupt:
        print("\n\n[!] Sniffing stopped by user.")
        print("[*] Exiting...")


def main():
    args = get_arguments()
    sniff_packets(args.interface, args.count, args.filter)


if __name__ == "__main__":
    main()
