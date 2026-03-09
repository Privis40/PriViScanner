#!/usr/bin/env python3
import os
import socket
import requests
import re
import sys
import nmap
import whois
import urllib3
import threading
import time
import dns.resolver
from urllib.parse import urlparse
from datetime import datetime
from colorama import Fore, Style, init
from fpdf import FPDF

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

# ─────────────────────────────────────────────
#  VISUALS: LOADING ANIMATION (Pulse HUD)
# ─────────────────────────────────────────────

stop_animation = False

def loading_animation(task_name):
    chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    idx = 0
    while not stop_animation:
        sys.stdout.write(f"\r{Fore.YELLOW}[{chars[idx % len(chars)]}] {Fore.WHITE}Tactical Objective: {task_name}...")
        sys.stdout.flush()
        idx += 1
        time.sleep(0.1)
    sys.stdout.write("\r" + " " * 85 + "\r")

# ─────────────────────────────────────────────
#  PDF REPORT ENGINE (PriViSecurity 🛡️)
# ─────────────────────────────────────────────

class PriViReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'PriViSecurity - Full Spectrum Recon Report', 0, 1, 'C')
        self.set_font('Arial', 'I', 10)
        self.cell(0, 5, 'Security Architect: Prince Ubebe', 0, 1, 'C')
        self.ln(10)

def generate_pdf_report(report_data, domain):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_domain = domain.replace('.', '_')
    filename = f"privireport_{safe_domain}_{timestamp}.pdf"

    try:
        pdf = PriViReport()
        pdf.add_page()
        
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 10, "1. Target & Organization Intelligence", 0, 1)
        pdf.set_font('Arial', '', 10)
        pdf.cell(0, 7, f"Organization: {report_data['whois'].get('org', 'REDACTED')}", 0, 1)
        pdf.cell(0, 7, f"Registrar: {report_data['whois'].get('registrar', 'Unknown')}", 0, 1)
        pdf.cell(0, 7, f"WAF Status: {report_data['waf']}", 0, 1)
        pdf.cell(0, 7, f"IP/Geo: {report_data['ip']} ({report_data['geo']})", 0, 1)
        pdf.ln(5)

        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 10, "2. DNS Infrastructure", 0, 1)
        pdf.set_font('Arial', '', 9)
        for record in report_data['dns_records']: pdf.cell(0, 6, f"- {record}", 0, 1)
        pdf.ln(5)

        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 10, "3. Scraped Intel & Vulnerabilities", 0, 1)
        pdf.set_font('Arial', '', 9)
        pdf.multi_cell(0, 6, f"Emails: {', '.join(report_data['emails']) if report_data['emails'] else 'None'}")
        for v in report_data['vulns']:
            pdf.set_text_color(220, 50, 50)
            pdf.multi_cell(0, 6, f"[CRITICAL] {v}")
            pdf.set_text_color(0,0,0)

        pdf.output(filename)
        return filename
    except Exception as e:
        print(Fore.RED + f"[-] PDF Error: {e}")
        return None

# ─────────────────────────────────────────────
#  TACTICAL OPERATIONS
# ─────────────────────────────────────────────

def banner():
    print(Fore.RED + Style.BRIGHT + r"""
    ██████╗ ██████╗ ██╗██╗   ██╗██╗███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
    ██╔══██╗██╔══██╗██║██║   ██║██║██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
    ██████╔╝██████╔╝██║██║   ██║██║███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
    ██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝██║╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
    ██║     ██║  ██║██║ ╚████╔╝ ██║███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
    """ + Style.RESET_ALL)
    print(Fore.YELLOW + "    " + "═" * 80)
    print(Fore.WHITE + Style.BRIGHT + f"    BRAND NAME : {Fore.CYAN}PriViSecurity 🛡️")
    print(Fore.WHITE + Style.BRIGHT + f"    DEVELOPER  : {Fore.GREEN}Prince Ubebe")
    print(Fore.YELLOW + "    " + "═" * 80 + "\n")

def main():
    global stop_animation
    if len(sys.argv) != 2:
        print(Fore.RED + "Usage: sudo python3 priviscanner.py <target>"); sys.exit(1)

    domain = urlparse(sys.argv[1] if "://" in sys.argv[1] else "http://" + sys.argv[1]).netloc or sys.argv[1]
    report_data = {'ip': None, 'geo': 'Unknown', 'whois': {}, 'emails': [], 'subdomains': [], 'ports': [], 'vulns': [], 'waf': 'None Detected', 'dns_records': []}

    banner()

    # PHASE 1: TARGET & ORGANIZATION IDENTIFICATION
    stop_animation = False
    threading.Thread(target=loading_animation, args=("Organization & WHOIS Recon",)).start()
    try:
        report_data['ip'] = socket.gethostbyname(domain)
        w = whois.whois(domain)
        report_data['whois'] = {'registrar': w.registrar, 'creation_date': w.creation_date, 'org': w.org}
        geo_res = requests.get(f"https://ip-api.com/json/{report_data['ip']}", timeout=5).json()
        if geo_res.get('status') == 'success':
            report_data['geo'] = f"{geo_res['country']}, {geo_res['city']} ({geo_res['isp']})"
    finally:
        stop_animation = True; time.sleep(0.5)

    print(Fore.CYAN + f"[>>] CURRENT OBJECTIVE: Target Identification ...")
    print(Fore.GREEN + f"    [+] ORGANIZATION : {report_data['whois']['org']}")
    print(Fore.GREEN + f"    [+] REGISTRAR    : {report_data['whois']['registrar']}")
    print(Fore.GREEN + f"    [+] TARGET IP    : {report_data['ip']} ({report_data['geo']})")

    # PHASE 2: PERIMETER CHECK (WAF)
    print(Fore.CYAN + f"\n[>>] CURRENT OBJECTIVE: Perimeter Check (WAF) ...")
    stop_animation = False
    threading.Thread(target=loading_animation, args=("Firewall Detection",)).start()
    try:
        req = requests.get(f"http://{domain}", timeout=5)
        waf_headers = ['x-powered-by', 'server', 'x-sucuri-id', 'cf-ray']
        for header in waf_headers:
            if header in req.headers:
                report_data['waf'] = f"Detected ({req.headers.get(header)})"
                break
        print(Fore.GREEN + f"    [+] WAF STATUS   : {report_data['waf']}")
    finally:
        stop_animation = True; time.sleep(0.5)

    # PHASE 3: DNS RESOLUTION
    print(Fore.CYAN + f"\n[>>] CURRENT OBJECTIVE: DNS Resolution ...")
    stop_animation = False
    threading.Thread(target=loading_animation, args=("Record Enumeration",)).start()
    try:
        for r_type in ['MX', 'NS', 'TXT']:
            try:
                answers = dns.resolver.resolve(domain, r_type)
                for rdata in answers:
                    val = f"{r_type}: {rdata.to_text()}"
                    report_data['dns_records'].append(val)
                    print(Fore.GREEN + f"    [+] {val}")
            except: continue
    finally:
        stop_animation = True; time.sleep(0.5)

    # PHASE 4: EVASION SCAN
    print(Fore.CYAN + f"\n[>>] CURRENT OBJECTIVE: Stealth Vuln-Engine ...")
    stop_animation = False
    threading.Thread(target=loading_animation, args=("Nmap Evasion Mode",)).start()
    try:
        nm = nmap.PortScanner()
        evasion_args = '-sV -f -D RND:5 --data-length 20 --version-intensity 3 -T4 --script vuln'
        nm.scan(report_data['ip'], arguments=f'{evasion_args} -p 21,22,80,443,3306')
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in sorted(nm[host][proto].keys()):
                    pinfo = nm[host][proto][port]
                    print(Fore.GREEN + f"    [+] Port {port}/{proto} is {pinfo['state']}")
                    if 'script' in pinfo:
                        for s_id in pinfo['script']:
                            report_data['vulns'].append(f"Port {port}: {s_id}")
                            print(Fore.RED + f"      [!] VULN FOUND: {s_id}")
    finally:
        stop_animation = True; time.sleep(0.5)

    # PHASE 5: REPORTING
    print(Fore.CYAN + "\n[>>] COMPILING FINAL REPORT...")
    report_file = generate_pdf_report(report_data, domain)
    if report_file: print(Fore.GREEN + Style.BRIGHT + f"[+] MISSION SUCCESS: {report_file} generated.")
    print(Fore.YELLOW + Style.BRIGHT + f"\n[*] ALL OBJECTIVES MET. PriViSecurity 🛡️ STANDING BY.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(Fore.RED + "[!] Error: Requires sudo for stealth features."); sys.exit(1)
    main()
    
