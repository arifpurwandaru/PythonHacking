# Learn Python and Ethical Hacking
This just for learning python and Basic hacking
Please bare in mind that this programs only work well in **Kali Linux** operating system. Not Recommended to run this on Windows, some script behave differently, specially the one with scapy libraries

## INSTALLATION
1. Create and Activate virtual environment. Windows: <code>python -m venv venv && venv\Scripts\activate</code>, Linux: <code>python -m venv venv && source venv/bin/activate</code> 
2. Install dependency <code>pip install -r requirements.txt</code>
3. For non Kali linux OS, it is required to install additional app/lib, you can read the details in here:
- scapy : https://scapy.readthedocs.io/en/latest/installation.html
- e.g., For Ubuntu: <code>sudo apt-get install libcap-dev</code> 

## List of Programs and Usage
## 1. mac_changer.py Usage
This is a simple program to change your mac address, this is the example of usage:
```bash
python mac_changer --interface eth0 --mac 00:11:22:33:44:55
```

## 2. network_scanner.py Usage
To run this, you neet to use root/sudo. But make sure you use the right python from venv
e.g., sudo su first and then reactivate venv and run the script
```bash
python network_scanner.py -t 192.168.18.0/24
```

## 3. Packet sniffer
```bash
# Capture all traffic on default interface (requires sudo)
sudo python packet_sniffer.py

# Capture on specific interface
sudo python packet_sniffer.py -i eth0

# Capture only 50 packets
sudo python packet_sniffer.py -c 50

# Capture only HTTP traffic (port 80)
sudo python packet_sniffer.py -f "tcp port 80"

# Capture traffic to/from specific host
sudo python packet_sniffer.py -f "host 192.168.1.1"

# Capture DNS traffic
sudo python packet_sniffer.py -f "udp port 53"

# Capture on wlan0 interface with filter
sudo python packet_sniffer.py -i wlan0 -f "tcp port 443"
```

#### BPF Filter Examples:
- "tcp port 80" - HTTP traffic
- "tcp port 443" - HTTPS traffic
- "udp port 53" - DNS traffic
- "host 192.168.1.1" - Traffic to/from specific IP
- "net 192.168.1.0/24" - Traffic in subnet
- "port 22" - SSH traffic
- "icmp" - ICMP/ping traffic

## 4. Reconnaissance CLI (recon_cli.py)
```bash
# simple dns scan
python recon_cli.py dnsscan google.com --art CAA

# shodan scan (this will need shodan paid API KEY) add .env file in project folder and add SHODAN_API_KEY
python recon_cli.py shodan < IP Address >

# whois lookup
python recon_cli.py whois-lookup <domain/Ip > 

# Subdomain enumeration
# All methods (Certificate Transparency + Zone Transfer + Brute Force)
python recon_cli.py subdomain example.com

# Only Certificate Transparency (fast, public records)
python recon_cli.py subdomain example.com --method crt

# Only brute force (slower, tests 200+ subdomains)
python recon_cli.py subdomain example.com --method brute

# Only zone transfer attempt (rarely works)
python recon_cli.py subdomain example.com --method axfr
```

## 5. Compromised Password Check
```bash
# Activate virtual environment first
source venv/bin/activate

# Check a single password (interactive prompt)
python compromised_password_check.py check

# Check a password directly (insecure - visible in history)
python compromised_password_check.py check --password "MyPassword123"

# Check with verbose output
python compromised_password_check.py check -v

# Check multiple passwords from a file
echo -e "password123\nadmin\nqwerty" > test_passwords.txt
python compromised_password_check.py check-file test_passwords.txt

# Check file and show passwords in output
python compromised_password_check.py check-file test_passwords.txt --show-passwords

# Show information about the service
python compromised_password_check.py info

# Get help
python compromised_password_check.py --help
```