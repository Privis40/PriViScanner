#!/usr/bin/env python3
import os
import socket
import requests
import re
import sys
import nmap
import urllib3
import time
import whois
from urllib.parse import urlparse
from datetime import datetime
from colorama import Fore, Style, init
from tqdm import tqdm

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)


def banner():
    print(Fore.RED + Style.BRIGHT + """
    ██████╗ ██████╗ ██╗██╗ ██╗██╗███████╗ ██████╗ █████╗ ███╗ ██╗███╗ ██╗███████╗██████╗ 
    ██╔══██╗██╔══██╗██║██║ ██║██║██╔════╝██╔════╝██╔══██╗████╗ ██║████╗ ██║██╔════╝██╔══██╗
    ██████╔╝██████╔╝██║██║ ██║██║███████╗██║ ███████║██╔██╗ ██║██╔██╗ ██║█████╗ ██████╔╝
    ██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝██║╚════██║██║ ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝ ██╔══██╗
    ██║ ██║ ██║██║ ╚████╔╝ ██║███████║╚██████╗██║ ██║██║ ╚████║██║ ╚████║███████╗██║ ██║
    ╚═╝ ╚═╝ ╚═╝╚═╝ ╚═══╝ ╚═╝╚══════╝ ╚═════╝╚═╝ ╚═╝╚═╝ ╚═══╝╚═╝ ╚═══╝╚══════╝╚═╝ ╚═╝
    """ + Style.RESET_ALL)
    print(Fore.YELLOW + " Advanced OSINT & Vulnerability Reconnaissance Framework")
    print(Fore.YELLOW + " Developed by Privis Creative Studio")
    print(Fore.YELLOW + " -------------------------------------------------------\n")


def update_objective(step_name, status="RUNNING"):
    try:
        if status == "RUNNING":
            print(Fore.CYAN + Style.BRIGHT + f"\n[>>] CURRENT OBJECTIVE: {step_name}...")
        elif status == "SUCCESS":
            print(Fore.GREEN + Style.BRIGHT + f"[+] OBJECTIVE COMPLETE: {step_name}")
            print(Fore.YELLOW + "-------------------------------------------------------")
        elif status == "FAILED":
            print(Fore.RED + Style.BRIGHT + f"[!] OBJECTIVE FAILED: {step_name}")
            print(Fore.YELLOW + "-------------------------------------------------------")
    except UnicodeEncodeError:
        if status == "RUNNING":
            print(f"\n[>>] CURRENT OBJECTIVE: {step_name}...")
        elif status == "SUCCESS":
            print(f"[+] OBJECTIVE COMPLETE: {step_name}")
        elif status == "FAILED":
            print(f"[!] OBJECTIVE FAILED: {step_name}")


def techy_progress(task_name, duration=1.5):
    print(Fore.MAGENTA + f" [~] Initializing {task_name}...")
    for _ in tqdm(range(50), desc=" Loading", ascii=" #",
                  bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}", leave=False):
        time.sleep(duration / 50)


def whois_lookup(domain, report_data):
    """Perform WHOIS lookup. Returns True on success, False on failure."""
    try:
        w = whois.whois(domain)
        created = w.creation_date
        expires = w.expiration_date
        if isinstance(created, list):
            created = created[0]
        if isinstance(expires, list):
            expires = expires[0]
        registrar = w.registrar[0] if isinstance(w.registrar, list) else w.registrar
        org = w.org[0] if isinstance(w.org, list) else w.org
        result = (
            f"Registrar : {registrar}\n"
            f"Created : {created}\n"
            f"Expires : {expires}\n"
            f"Org : {org}"
        )
        print(Fore.GREEN + f" [+] WHOIS data retrieved:\n{result}")
        report_data['whois'] = result
        # FIX #1: Now returns True so caller can conditionally fire SUCCESS.
        return True
    except Exception as e:
        print(Fore.YELLOW + f" [-] WHOIS lookup failed: {e}")
        report_data['whois'] = f"Failed: {e}"
        return False


def waf_detection(url, report_data):
    """Detect WAF. Returns True on success, False on network failure."""
    waf_signatures = {
        'Cloudflare': ['__cfduid', 'cf-ray', 'cloudflare'],
        'Incapsula': ['visid_incap', 'incap_ses', 'x-iinfo'],
        'Akamai': ['akamai-origin-hop', 'aka-ghost', 'x-akamai'],
        'ModSecurity': ['mod_security', 'modsecurity'],
        'F5 BIG-IP': ['x-waf-status', 'bigipserver'],
    }
    try:
        response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        headers = str(response.headers).lower()
        cookies = str(response.cookies).lower()
        detected = [
            waf for waf, sigs in waf_signatures.items()
            if any(s.lower() in headers or s.lower() in cookies for s in sigs)
        ]
        if detected:
            for waf in detected:
                print(Fore.RED + f" [!] WAF DETECTED: {waf}")
            report_data['waf'] = ', '.join(detected)
        else:
            print(Fore.GREEN + " [+] No WAF detected (Direct Access).")
            report_data['waf'] = "None"
        # FIX #2: Returns True so caller can conditionally fire SUCCESS.
        return True
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f" [-] WAF detection failed: {e}")
        report_data['waf'] = f"Error: {e}"
        return False


def subdomain_enumeration(domain, report_data):
    """Enumerate subdomains. Returns True always; found count indicates results."""
    common_subs = ['www', 'mail', 'ftp', 'dev', 'test', 'admin', 'api', 'vpn']
    found = []
    for sub in tqdm(common_subs, desc=" DNS Lookup", ascii=" ."):
        try:
            ip = socket.gethostbyname(f"{sub}.{domain}")
            tqdm.write(Fore.GREEN + f" [+] Found: {sub}.{domain} ({ip})")
            found.append(f"{sub}.{domain} ({ip})")
        except socket.gaierror:
            continue
    report_data['subdomains'] = found
    if not found:
        print(Fore.YELLOW + " [-] No subdomains found.")
    return True


def deep_scan(ip, report_data):
    """Run nmap vuln scan. Returns True on success, False on error."""
    # FIX #3: nmap.PortScanner() initialised BEFORE techy_progress so if nmap
    # is missing, it raises immediately with a clear error instead of running
    # the cosmetic progress bar first and then crashing.
    try:
        nm = nmap.PortScanner()
    except nmap.PortScannerError as e:
        print(Fore.RED + f" [-] Nmap not available: {e}")
        return False

    techy_progress("Nmap Vuln-Engine")

    try:
        scan_type = '-sS' if os.geteuid() == 0 else '-sT'
        if scan_type == '-sT':
            print(Fore.YELLOW + " [~] Not root — using -sT (TCP connect) instead of -sS (SYN).")

        # FIX #9: Restored full port coverage from previous version.
        # Ports 25,53,110,143,3389,8443 were dropped — these cover SMTP, DNS,
        # POP3, IMAP, RDP and alt-HTTPS which are common attack surfaces.
        nm.scan(ip, arguments=f'{scan_type} -sV --script vuln '
                               f'-p 21,22,25,53,80,110,143,443,445,3306,3389,8080,8443 -T4')
        scan_found = False
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in sorted(nm[host][proto].keys()):
                    scan_found = True
                    pinfo = nm[host][proto][port]
                    res = f"Port {port}/{proto} ({pinfo['name']}) is {pinfo['state']}"
                    print(Fore.GREEN + f" [+] {res}")
                    report_data['ports'].append(res)
                    if 'script' in pinfo:
                        for s_name, s_out in pinfo['script'].items():
                            v = f" [!] {s_name}: {s_out.strip().splitlines()[0]}"
                            print(Fore.RED + v)
                            report_data['ports'].append(v)
        if not scan_found:
            print(Fore.YELLOW + " [-] No open ports found in scanned range.")
        return True
    except nmap.PortScannerError as e:
        print(Fore.RED + f" [-] Nmap error (installed? running as root?): {e}")
        return False
    except Exception as e:
        print(Fore.RED + f" [-] Scan Error: {e}")
        return False


def main():
    banner()
    if len(sys.argv) != 2:
        print(Fore.RED + "Usage: sudo python3 priviscanner.py <target>")
        sys.exit(1)

    url_in = sys.argv[1]

    # urlparse() called once, result stored and reused.
    normalized = url_in if "://" in url_in else "http://" + url_in
    parsed = urlparse(normalized)
    domain = parsed.netloc or parsed.path

    if not domain:
        print(Fore.RED + "[-] Invalid Domain")
        sys.exit(1)

    report_data = {
        'ip': None,
        'whois': '',
        'leaks': [],
        'ports': [],
        'dorks': [],
        'waf': '',
        'subdomains': []
    }

    # STEP 1: RESOLUTION
    update_objective("Target Identification")
    try:
        report_data['ip'] = socket.gethostbyname(domain)
        print(Fore.GREEN + f" [+] Locked: {domain} ({report_data['ip']})")
        update_objective("Target Identification", "SUCCESS")
    except socket.gaierror as e:
        print(Fore.RED + f"[-] DNS Failure: {e}")
        sys.exit(1)

    # FIX #4: Added None guard before deep_scan. If the DNS step above
    # somehow completes without setting ip (shouldn't happen, but defensive),
    # passing None to nmap produces a cryptic error instead of a clear message.
    if report_data['ip'] is None:
        print(Fore.RED + "[-] IP resolution produced no result. Aborting.")
        sys.exit(1)

    # STEP 2: WHOIS — FIX #1: Check return value, fire FAILED if lookup failed.
    update_objective("WHOIS Reconnaissance")
    whois_ok = whois_lookup(domain, report_data)
    update_objective("WHOIS Reconnaissance", "SUCCESS" if whois_ok else "FAILED")

    # STEP 3: WAF — FIX #2: Check return value, fire FAILED on network error.
    update_objective("Perimeter Check (WAF)")
    waf_ok = waf_detection(url_in, report_data)
    update_objective("Perimeter Check (WAF)", "SUCCESS" if waf_ok else "FAILED")

    # STEP 4: SUBDOMAINS
    update_objective("Infrastructure Mapping")
    subdomain_enumeration(domain, report_data)
    update_objective("Infrastructure Mapping", "SUCCESS")

    # STEP 5: DEEP SCAN
    update_objective("Vulnerability Assessment")
    scan_ok = deep_scan(report_data['ip'], report_data)
    update_objective("Vulnerability Assessment", "SUCCESS" if scan_ok else "FAILED")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # FIX #7: Tightened services regex to only match port result lines
    # (which follow the pattern "Port NNN/proto (service) is state"),
    # preventing vuln script output parentheses from polluting the service list.
    port_lines = [p for p in report_data['ports'] if p.strip().startswith('Port')]
    services = list(set(re.findall(r'\((\w+)\)', ' '.join(port_lines))))

    print(Fore.CYAN + Style.BRIGHT + "\n[*] MISSION COMPLETE.")
    print(Fore.YELLOW + f" Completed : {timestamp}")
    print(Fore.YELLOW + f" WAF : {report_data['waf']}")
    print(Fore.YELLOW + f" Subdomains : {len(report_data['subdomains'])}")
    print(Fore.YELLOW + f" Ports : {len(report_data['ports'])}")
    print(Fore.YELLOW + f" Services : {', '.join(services) if services else 'none'}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Aborted.")
        sys.exit(0)


