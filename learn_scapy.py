import scapy.all as scapy
import socket

def check_open_port(ip, port):
    # Create a TCP SYN packet
    packet = scapy.IP(dst=ip)/scapy.TCP(dport=port, flags='S')
    
    # Send the packet and wait for a response
    response = scapy.sr1(packet, timeout=1, verbose=0)

    print(response)
    

    # Check if we received a response
    if response is None:
        print(f"Port {port} on {ip} is closed (no response).")
    elif response.haslayer(scapy.TCP):
        if response[scapy.TCP].flags == 'SA':
            print(f"Port {port} on {ip} is open.")
        else:
            print(f"Port {port} on {ip} is closed (received RST).")
    else:
        print(f"Port {port} on {ip} is closed (unexpected response).")



def get_service_name(port):
    try:
        rsl = socket.getservbyport(port, "tcp")
        print(rsl)
        return rsl
    except OSError:
        return "Unknown"

get_service_name(22)