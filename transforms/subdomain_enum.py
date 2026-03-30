import dns.resolver
import requests
import asyncio
from typing import Set
from models.schema import Entity


# Common subdomain wordlist
DEFAULT_WORDLIST = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
    'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns',
    'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2',
    'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs', 'beta',
    'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web', 'media', 'email',
    'images', 'img', 'www1', 'intranet', 'portal', 'video', 'sip', 'dns2', 'api', 'cdn',
    'stats', 'dns1', 'ns4', 'www3', 'dns', 'search', 'staging', 'server', 'mx1', 'chat',
    'wap', 'my', 'svn', 'mail1', 'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup',
    'mx2', 'lyncdiscover', 'info', 'apps', 'download', 'remote', 'db', 'forums', 'store',
    'relay', 'files', 'newsletter', 'app', 'live', 'owa', 'en', 'start', 'sms', 'office',
    'exchange', 'ipv4', 'help', 'home', 'library', 'ftp2', 'ntp', 'monitor', 'login',
    'service', 'correo', 'www4', 'moodle', 'it', 'gateway', 'gw', 'i', 'stat', 'stage',
    'ldap', 'tv', 'ssl', 'web1', 'web2', 'ns5', 'upload', 'nagios', 'smtp2', 'online',
    'ad', 'survey', 'data', 'radio', 'extranet', 'test2', 'mssql', 'dns3', 'jobs', 'services',
    'panel', 'irc', 'hosting', 'cloud', 'de', 'gmail', 's', 'bbs', 'cs', 'ww', 'mrtg',
    'git', 'image', 'members', 'poczta', 'john', 's1', 'meet', 'preview', 'fr', 'cloudflare-resolve-to',
    'dev2', 'photo', 'jabber', 'legacy', 'go', 'es', 'ssh', 'redmine', 'partner', 'vps',
    'server1', 'sv', 'ns6', 'webmail2', 'av', 'community', 'cacti', 'time', 'sftp', 'lib',
    'facebook', 'www5', 'smtp1', 'feeds', 'w', 'games', 'ts', 'alumni', 'dl', 's2',
    'phpmyadmin', 'archive', 'cn', 'tools', 'stream', 'projects', 'elearning', 'im', 'iphone',
    'control', 'voip', 'test1', 'ws', 'rss', 'sp', 'wwww', 'vpn2', 'jira', 'list',
    'connect', 'gallery', 'billing', 'mailer', 'update', 'pda', 'game', 'ns0', 'testing',
    'sandbox', 'job', 'events', 'dialin', 'ml', 'fb', 'videos', 'music', 'a', 'partners',
    'mailhost', 'downloads', 'reports', 'ca', 'router', 'speedtest', 'local', 'training',
    'edu', 'bugs', 'manage', 's3', 'status', 'host2', 'ww2', 'marketing', 'conference',
    'content', 'network-ip', 'broadcast-ip', 'english', 'catalog', 'msoid', 'mailin', 'cdn2',
    'api2', 'ws1', 'security', 'twain', 'lang', 'mc', 'auth', 'cms2', 'www6', 'maintenance',
    'streaming', 'app1', 'track', 'log', 'sso', 'booking', 'eshop', 'pay', 'db1',
]


async def brute_force_subdomains(domain: str, wordlist: list[str] = None) -> list[Entity]:
    """
    Brute force subdomain enumeration using DNS queries
    """
    if wordlist is None:
        wordlist = DEFAULT_WORDLIST
    
    entities = []
    found = set()
    
    print(f"[*] Brute forcing subdomains for {domain}...")
    print(f"[*] Testing {len(wordlist)} potential subdomains...")
    
    for word in wordlist:
        subdomain = f"{word}.{domain}"
        
        # Skip if already found
        if subdomain in found:
            continue
            
        try:
            # Try A record
            answers = dns.resolver.resolve(subdomain, 'A')
            for rdata in answers:
                entities.append(Entity(
                    type="Subdomain",
                    value=f"{subdomain} -> {rdata}",
                    source="brute_force"
                ))
                found.add(subdomain)
                print(f"[+] Found: {subdomain} -> {rdata}")
        except dns.resolver.NXDOMAIN:
            pass  # Subdomain doesn't exist
        except dns.resolver.NoAnswer:
            pass  # No A record
        except dns.resolver.Timeout:
            pass  # DNS timeout
        except Exception as e:
            pass  # Other DNS errors
    
    return entities


def crt_sh_enum(domain: str) -> list[Entity]:
    """
    Query Certificate Transparency logs via crt.sh
    """
    entities = []
    found = set()
    
    print(f"[*] Querying Certificate Transparency logs for {domain}...")
    
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    
    try:
        response = requests.get(url, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            
            for item in data:
                name_value = item.get('name_value', '')
                
                # Split by newlines (crt.sh returns multiple domains per entry)
                for subdomain in name_value.split('\n'):
                    subdomain = subdomain.strip()
                    
                    # Skip wildcards and already found subdomains
                    if '*' in subdomain or subdomain in found:
                        continue
                    
                    # Only add if it's actually a subdomain of our target
                    if subdomain.endswith(domain):
                        entities.append(Entity(
                            type="Subdomain",
                            value=subdomain,
                            source="crt.sh"
                        ))
                        found.add(subdomain)
                        print(f"[+] Found: {subdomain}")
            
            print(f"[*] Found {len(found)} unique subdomains from CT logs")
        else:
            print(f"[-] crt.sh returned status code: {response.status_code}")
    
    except requests.exceptions.Timeout:
        print("[-] crt.sh request timed out")
    except requests.exceptions.RequestException as e:
        print(f"[-] Error querying crt.sh: {e}")
    except ValueError as e:
        print(f"[-] Error parsing crt.sh response: {e}")
    
    return entities


def dns_zone_transfer(domain: str) -> list[Entity]:
    """
    Attempt DNS Zone Transfer (AXFR)
    """
    entities = []
    
    print(f"[*] Attempting DNS Zone Transfer for {domain}...")
    
    try:
        # Get nameservers for the domain
        ns_records = dns.resolver.resolve(domain, 'NS')
        
        for ns in ns_records:
            ns_name = str(ns.target).rstrip('.')
            print(f"[*] Trying zone transfer from nameserver: {ns_name}")
            
            try:
                # Attempt zone transfer
                zone = dns.zone.from_xfr(dns.query.xfr(ns_name, domain))
                
                print(f"[+] Zone transfer successful from {ns_name}!")
                
                # Extract all records
                for name, node in zone.nodes.items():
                    subdomain = str(name)
                    if subdomain != '@':
                        full_domain = f"{subdomain}.{domain}" if subdomain else domain
                        entities.append(Entity(
                            type="Subdomain",
                            value=full_domain,
                            source=f"zone_transfer_{ns_name}"
                        ))
                        print(f"[+] Found: {full_domain}")
                
            except Exception as e:
                pass  # Zone transfer failed (expected in most cases)
    
    except Exception as e:
        print(f"[-] Could not retrieve nameservers for {domain}")
    
    if not entities:
        print("[-] Zone transfer not allowed (this is normal)")
    
    return entities


async def run(domain: str, method: str = "all") -> list[Entity]:
    """
    Main function to run subdomain enumeration
    
    Args:
        domain: Target domain (e.g., example.com)
        method: Enumeration method - 'all', 'brute', 'crt', or 'axfr'
    
    Returns:
        List of Entity objects with discovered subdomains
    """
    all_entities = []
    
    if method in ["all", "crt"]:
        # Certificate Transparency (fast, doesn't generate DNS traffic)
        crt_entities = crt_sh_enum(domain)
        all_entities.extend(crt_entities)
    
    if method in ["all", "axfr"]:
        # DNS Zone Transfer attempt (rarely works but fast)
        axfr_entities = dns_zone_transfer(domain)
        all_entities.extend(axfr_entities)
    
    if method in ["all", "brute"]:
        # Brute force (slower, generates DNS traffic)
        brute_entities = await brute_force_subdomains(domain)
        all_entities.extend(brute_entities)
    
    # Remove duplicates based on value
    unique_entities = []
    seen_values = set()
    
    for entity in all_entities:
        if entity.value not in seen_values:
            unique_entities.append(entity)
            seen_values.add(entity.value)
    
    print(f"\n[*] Total unique subdomains found: {len(unique_entities)}")
    
    return unique_entities
