# Learn Python and Ethical Hacking
This just for learning python and Basic hacking
Please bare in mind that this programs only work well in **Kali Linux 2019** operating system

## INSTALLATION
1. Create and Activate virtual environment. Windows: <code>python -m venv venv && venv\Scripts\activate</code>, Linux: <code>python -m venv venv && source venv/bin/activate</code> 
2. Install dependency <code>pip install -r requirements.txt</code>
3. For non Kali linux OS, it is required to install additional app/lib, you can read the details in here:
- scapy : https://scapy.readthedocs.io/en/latest/installation.html
- e.g., For Ubuntu: <code>sudo apt-get install libcap-dev</code> 

## List of Programs and Usage
#### 1. mac_changer.py Usage
This is a simple program to change your mac address, this is the example of usage:
```bash
python mac_changer --interface eth0 --mac 00:11:22:33:44:55
```

### 2. network_scanner.py Usage
To run this, you neet to use root/sudo. But make sure you use the right python from venv
e.g., sudo su first and then reactivate venv and run the script
```bash
python network_scanner.py -t 192.168.18.0/24
```