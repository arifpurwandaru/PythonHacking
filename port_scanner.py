import scapy.all as scapy
import argparse
import socket
from datetime import datetime

# Common port-to-service mapping for service prediction
WELL_KNOWN_SERVICES = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    119: "NNTP",
    123: "NTP",
    135: "MS RPC",
    137: "NetBIOS Name",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    179: "BGP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "Microsoft-DS (SMB)",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD/LPR",
    520: "RIP",
    523: "IBM DB2",
    554: "RTSP",
    587: "SMTP (Submission)",
    631: "IPP (CUPS)",
    636: "LDAPS",
    873: "Rsync",
    902: "VMware",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS Proxy",
    1099: "Java RMI",
    1433: "Microsoft SQL Server",
    1434: "MS SQL Monitor",
    1521: "Oracle DB",
    1723: "PPTP VPN",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel SSL",
    2181: "ZooKeeper",
    2222: "SSH (Alt)",
    3306: "MySQL",
    3389: "RDP",
    3690: "SVN",
    4443: "HTTPS (Alt)",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    6379: "Redis",
    6667: "IRC",
    8000: "HTTP (Alt)",
    8080: "HTTP Proxy",
    8443: "HTTPS (Alt)",
    8888: "HTTP (Alt)",
    9090: "Web Management",
    9200: "Elasticsearch",
    9418: "Git",
    11211: "Memcached",
    27017: "MongoDB",
}


def get_service_name(port):
    """Predict the service running on a given port.
    
    First checks the well-known services dict, then falls back
    to the system's /etc/services via socket.getservbyport().
    """
    if port in WELL_KNOWN_SERVICES:
        return WELL_KNOWN_SERVICES[port]

    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "Unknown"


def grab_banner(ip, port, timeout=2):
    """Attempt to grab a service banner from an open port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.sendall(b"HEAD / HTTP/1.1\r\nHost: %b\r\n\r\n" % ip.encode())
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner.split("\n")[0] if banner else None
    except Exception:
        return None


def scan_port(ip, port, timeout=1):
    """Send a TCP SYN packet to a single port and return its state.
    
    Returns:
        "open"     – received SYN-ACK
        "closed"   – received RST or unexpected TCP response
        "filtered" – no response (firewall likely dropping packets)
    """
    packet = scapy.IP(dst=ip) / scapy.TCP(dport=port, flags="S")
    response = scapy.sr1(packet, timeout=timeout, verbose=0)

    if response is None:
        return "filtered"
    elif response.haslayer(scapy.TCP):
        tcp_flags = response[scapy.TCP].flags
        if tcp_flags == "SA":
            # Send RST to gracefully close the half-open connection
            scapy.sr(
                scapy.IP(dst=ip) / scapy.TCP(dport=port, flags="R"),
                timeout=0.5,
                verbose=0,
            )
            return "open"
        elif tcp_flags == "RA" or tcp_flags == "R":
            return "closed"
    return "closed"


def scan_port_range(ip, start_port=1, end_port=1024, timeout=1, verbose=False):
    """Scan a range of ports on a target IP address using TCP SYN scan.

    Args:
        ip:         Target IP address (e.g. "192.168.1.1").
        start_port: First port in the range (inclusive, default 1).
        end_port:   Last port in the range (inclusive, default 1024).
        timeout:    Seconds to wait for each probe (default 1).
        verbose:    If True, also print closed/filtered ports.

    Returns:
        A list of dicts with keys: port, state, service, banner.
    """
    print("=" * 60)
    print(f"  Port Scanner – Target: {ip}")
    print(f"  Port Range : {start_port} – {end_port}")
    print(f"  Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    results = []
    open_count = 0

    for port in range(start_port, end_port + 1):
        state = scan_port(ip, port, timeout)
        service = get_service_name(port)
        banner = None

        if state == "open":
            banner = grab_banner(ip, port)
            open_count += 1
            banner_info = f"  [{banner}]" if banner else ""
            print(f"  [OPEN]     Port {port:>5}/tcp  –  {service}{banner_info}")
            results.append({
                "port": port,
                "state": state,
                "service": service,
                "banner": banner,
            })
        elif verbose:
            tag = "CLOSED" if state == "closed" else "FILTERED"
            print(f"  [{tag:8s}] Port {port:>5}/tcp  –  {service}")
            results.append({
                "port": port,
                "state": state,
                "service": service,
                "banner": None,
            })

    print("=" * 60)
    print(f"  Scan complete – {open_count} open port(s) found.")
    print(f"  Finished at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    return results


def get_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="TCP SYN Port Scanner with Service Detection"
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target IP address to scan (e.g. 192.168.1.1)",
    )
    parser.add_argument(
        "-s", "--start-port",
        type=int,
        default=1,
        help="Start of port range (default: 1)",
    )
    parser.add_argument(
        "-e", "--end-port",
        type=int,
        default=1024,
        help="End of port range (default: 1024)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1,
        help="Timeout per port probe in seconds (default: 1)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show closed and filtered ports as well",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = get_arguments()
    scan_port_range(
        ip=args.target,
        start_port=args.start_port,
        end_port=args.end_port,
        timeout=args.timeout,
        verbose=args.verbose,
    )
