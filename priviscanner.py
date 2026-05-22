#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║       PriVi Network Recon Scanner v5.0                           ║
║       Full-Spectrum Domain Reconnaissance Suite                  ║
║       Developed by Prince Ubebe | PriViSecurity                  ║
╚══════════════════════════════════════════════════════════════════╝

LEGAL NOTICE:
  This tool is intended ONLY for use against domains and targets
  you own or have explicit written authorization to assess.
  Unauthorized reconnaissance against systems you do not own is
  illegal under the Computer Misuse Act, CFAA, and equivalent
  laws worldwide. PriViSecurity accepts no liability for
  unauthorized use.
"""

import sys, subprocess, importlib

def _auto_install():
    """Auto-install missing dependencies. Works on live Kali, VM, and fresh installs."""
    packages = {
        "requests":  "requests",
        "fpdf":      "fpdf2",
        "rich":      "rich",
        "nmap":      "python-nmap",
        "whois":     "python-whois",
        "dns":       "dnspython",
        "urllib3":   "urllib3",
        "bs4":       "beautifulsoup4",
    }
    missing = []
    for import_name, pip_name in packages.items():
        try:
            importlib.import_module(import_name)
        except ImportError:
            missing.append(pip_name)
    if missing:
        print(f"[PriViSecurity] Installing missing packages: {', '.join(missing)}")
        subprocess.check_call([
            sys.executable, "-m", "pip", "install",
            "--break-system-packages", "-q",
            *missing
        ])
        print("[PriViSecurity] Done. Launching tool...\n")

_auto_install()


import os
# sys, subprocess, importlib already imported above for _auto_install
import ssl
import json
import socket
# import hashlib  # unused
import threading
import time
import re
import base64
import nmap
import whois
import urllib3
import requests
import dns.resolver
from datetime import datetime
from urllib.parse import urlparse, quote
from fpdf import FPDF
from fpdf.enums import XPos, YPos
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

AUTHOR  = "Prince Ubebe"
BRAND   = "PriViSecurity"
VERSION = "5.0"
TOOL    = "PriVi Network Recon Scanner"


# ── AUTHORIZATION GATE ────────────────────────────────────────────────────────

def authorization_gate():
    os.system("clear")
    gate_text = Text()
    gate_text.append("\n  ⚠️  LEGAL AUTHORIZATION REQUIRED\n\n", style="bold red")
    gate_text.append(
        "  This tool performs active reconnaissance including WHOIS,\n"
        "  DNS enumeration, WAF detection, and Nmap vulnerability scanning.\n\n",
        style="white"
    )
    gate_text.append("  You MUST have one of the following before proceeding:\n\n", style="white")
    gate_text.append("    ✔  You own the target domain/system, OR\n", style="green")
    gate_text.append("    ✔  You hold a signed Letter of Authorization (LoA)\n", style="green")
    gate_text.append("       from the domain owner permitting this assessment.\n\n", style="green")
    gate_text.append(
        "  Unauthorized reconnaissance is illegal under the Computer\n"
        "  Misuse Act, CFAA, and equivalent laws worldwide.\n\n",
        style="dim white"
    )
    gate_text.append("  PriViSecurity accepts NO liability for unauthorized use.\n\n", style="dim red")

    console.print(Panel(
        gate_text,
        border_style="red",
        title=f"[bold red]{TOOL} v{VERSION}[/bold red]"
    ))

    console.print("[bold white]Do you have written authorization to scan the target domain?[/bold white]")
    console.print("[dim]Type [bold green]AGREE[/bold green] to confirm and proceed, or press Ctrl+C to exit.[/dim]\n")

    try:
        response = input("  > ").strip()
    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Session cancelled.[/bold yellow]")
        sys.exit(0)

    if response != "AGREE":
        console.print("\n[bold red][!] Authorization not confirmed. Exiting.[/bold red]")
        sys.exit(0)

    console.print("\n[bold green][✔] Authorization confirmed. Proceeding.[/bold green]\n")
    time.sleep(1)


# ── HEADER ────────────────────────────────────────────────────────────────────

def print_header():
    os.system("clear")
    header = Text()
    header.append(
        "\n"
        "  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗\n"
        "  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║\n"
        "  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║\n"
        "  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║\n"
        "  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║\n"
        "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝\n",
        style="bold cyan"
    )
    header.append(
        f"  {BRAND}  |  {TOOL} v{VERSION}  |  Full-Spectrum Domain Reconnaissance\n",
        style="dim white"
    )
    header.append(f"  Developer: {AUTHOR}  |  Authorized Use Only\n", style="dim red")
    console.print(Panel(header, border_style="blue"))


# ── ANIMATION  -  threading.Event (fixes race condition) ────────────────────────

class PhaseSpinner:
    """
    FIX: Replaces the raw global boolean stop_animation flag.

    The original bug: each phase set stop_animation=True in its finally block,
    then immediately set stop_animation=False for the next phase. If the
    animation thread hadn't checked the flag in that tiny window, it kept
    running through the next phase or indefinitely.

    threading.Event.set()/clear()/wait() is atomic  -  no race condition.
    join() ensures the thread is fully stopped before the next phase starts.
    """
    def __init__(self):
        self._stop_event = threading.Event()
        self._thread     = None

    def start(self, task_name: str):
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._spin, args=(task_name,), daemon=True
        )
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=1.5)  # wait for thread to actually exit
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()

    def _spin(self, task_name: str):
        chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        idx = 0
        while not self._stop_event.is_set():
            sys.stdout.write(
                f"\r  \033[93m[{chars[idx % len(chars)]}]\033[0m "
                f"\033[97m{task_name}...\033[0m"
            )
            sys.stdout.flush()
            idx += 1
            time.sleep(0.1)


# ── EMAIL SCRAPER (was missing entirely) ──────────────────────────────────────

def scrape_emails(domain: str) -> list:
    """
    FIX: Email scraping was completely absent in the original  -  report_data['emails']
    was initialized as [] and written to the PDF without ever being populated,
    so the PDF always showed 'None'.

    IMPROVED: Now crawls homepage + common contact/about pages for better coverage.
    """
    emails = set()
    email_pattern = re.compile(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
    )

    base_urls = [f"https://{domain}", f"https://www.{domain}"]
    subpages  = ["/contact", "/about", "/team", "/contact-us", "/about-us",
                 "/support", "/help", "/info"]

    def fetch_and_extract(url):
        try:
            resp = requests.get(
                url,
                timeout=8,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; security-audit/1.0)"},
                allow_redirects=True,
            )
            found = email_pattern.findall(resp.text)
            for email in found:
                if any(skip in email.lower() for skip in [
                    ".png", ".jpg", ".gif", ".svg", ".js", ".css",
                    "example.", "yourdomain.", "email@", "user@",
                    "test@", "noreply@domain", "@2x",
                ]):
                    continue
                emails.add(email)
        except requests.RequestException:
            pass

    # Try base URLs first
    working_base = None
    for base in base_urls:
        try:
            resp = requests.get(base, timeout=6, verify=False,
                                headers={"User-Agent": "Mozilla/5.0"},
                                allow_redirects=True)
            found = email_pattern.findall(resp.text)
            for email in found:
                if not any(skip in email.lower() for skip in [
                    ".png", ".jpg", ".gif", ".svg", ".js", ".css",
                    "example.", "yourdomain.", "email@", "user@",
                    "test@", "noreply@domain", "@2x",
                ]):
                    emails.add(email)
            working_base = base
            break
        except requests.RequestException:
            continue

    # Crawl subpages on the working base
    if working_base:
        for page in subpages:
            fetch_and_extract(working_base + page)

    return sorted(emails)


# ── WHOIS ENRICHMENT ──────────────────────────────────────────────────────────

def enrich_whois(domain: str) -> dict:
    """
    Extended WHOIS: registrar, org, creation/expiry dates, nameservers,
    abuse contact, and registrar URL — beyond what python-whois gives by default.
    """
    result = {
        "registrar":      "Unknown",
        "registrar_url":  "Unknown",
        "org":            "Unknown",
        "creation_date":  "Unknown",
        "expiry_date":    "Unknown",
        "days_to_expiry": None,
        "updated_date":   "Unknown",
        "nameservers":    [],
        "abuse_email":    "Unknown",
        "status":         [],
        "dnssec":         "Unknown",
    }
    try:
        w = whois.whois(domain)

        def _first(val):
            if isinstance(val, list):
                return str(val[0]) if val else "Unknown"
            return str(val) if val else "Unknown"

        result["registrar"]     = _first(getattr(w, "registrar",     None))
        result["registrar_url"] = _first(getattr(w, "registrar_url", None))
        result["org"]           = _first(getattr(w, "org",           None))
        result["dnssec"]        = _first(getattr(w, "dnssec",        None))

        # Dates
        creation = getattr(w, "creation_date", None)
        expiry   = getattr(w, "expiration_date", None)
        updated  = getattr(w, "updated_date", None)

        if creation:
            dt = creation[0] if isinstance(creation, list) else creation
            result["creation_date"] = dt.strftime("%Y-%m-%d") if hasattr(dt, "strftime") else str(dt)
        if expiry:
            dt = expiry[0] if isinstance(expiry, list) else expiry
            result["expiry_date"] = dt.strftime("%Y-%m-%d") if hasattr(dt, "strftime") else str(dt)
            if hasattr(dt, "strftime"):
                result["days_to_expiry"] = (dt - datetime.utcnow()).days
        if updated:
            dt = updated[0] if isinstance(updated, list) else updated
            result["updated_date"] = dt.strftime("%Y-%m-%d") if hasattr(dt, "strftime") else str(dt)

        # Nameservers
        ns = getattr(w, "name_servers", []) or []
        result["nameservers"] = sorted(set(n.lower() for n in ns)) if ns else []

        # Status
        status = getattr(w, "status", []) or []
        if isinstance(status, str):
            status = [status]
        result["status"] = [s.split(" ")[0] for s in status][:5]

        # Abuse email — try emails field
        emails = getattr(w, "emails", []) or []
        if isinstance(emails, str):
            emails = [emails]
        abuse = [e for e in emails if "abuse" in e.lower()]
        result["abuse_email"] = abuse[0] if abuse else (emails[0] if emails else "Unknown")

    except Exception as e:
        result["error"] = str(e)

    return result


# ── OSINT HARVESTING ──────────────────────────────────────────────────────────

def harvest_osint(domain: str) -> dict:
    """
    Multi-source OSINT harvesting:
    - crt.sh  : certificate transparency logs  →  subdomains + emails
    - HackerTarget : DNS, reverse IP, hosting history
    - Shodan  : host intelligence (no API key needed for basic host lookup)
    - GitHub  : public code leaks mentioning the domain
    - Archive : Wayback Machine endpoint discovery
    """
    result = {
        "crt_subdomains": [],
        "crt_emails":     [],
        "hackertarget":   {},
        "shodan_basic":   {},
        "wayback_urls":   [],
        "github_leaks":   [],
    }

    # ── crt.sh (certificate transparency) ─────────────────────────────────────
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0 (compatible; PriViSecurity/2.0)"},
        )
        if r.status_code == 200:
            entries     = r.json()
            email_pat   = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
            subs, mails = set(), set()
            for e in entries:
                name = e.get("name_value", "")
                for line in name.splitlines():
                    line = line.strip().lstrip("*.")
                    if domain in line and " " not in line:
                        subs.add(line.lower())
                for em in email_pat.findall(name):
                    mails.add(em.lower())
            result["crt_subdomains"] = sorted(subs)[:80]
            result["crt_emails"]     = sorted(mails)
    except Exception:
        pass

    # ── HackerTarget ──────────────────────────────────────────────────────────
    ht = {}
    for endpoint, key in [
        (f"https://api.hackertarget.com/hostsearch/?q={domain}",    "hosts"),
        (f"https://api.hackertarget.com/reverseiplookup/?q={domain}", "reverse_ip"),
        (f"https://api.hackertarget.com/dnslookup/?q={domain}",      "dns"),
    ]:
        try:
            r = requests.get(endpoint, timeout=10,
                             headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 200 and "error" not in r.text.lower()[:30]:
                ht[key] = [l.strip() for l in r.text.strip().splitlines() if l.strip()]
        except Exception:
            pass
    result["hackertarget"] = ht

    # ── Shodan (no key — basic host search via web) ────────────────────────────
    try:
        ip = socket.gethostbyname(domain)
        r  = requests.get(
            f"https://internetdb.shodan.io/{ip}",
            timeout=8,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if r.status_code == 200:
            data = r.json()
            result["shodan_basic"] = {
                "ip":       ip,
                "ports":    data.get("ports", []),
                "cpes":     data.get("cpes", []),
                "vulns":    data.get("vulns", []),
                "hostnames":data.get("hostnames", []),
                "tags":     data.get("tags", []),
            }
    except Exception:
        pass

    # ── Wayback Machine (endpoint discovery) ──────────────────────────────────
    try:
        r = requests.get(
            f"https://web.archive.org/cdx/search/cdx"
            f"?url={domain}/*&output=json&fl=original&collapse=urlkey&limit=120",
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if r.status_code == 200:
            rows = r.json()
            urls = [row[0] for row in rows[1:] if row]  # skip header
            # Filter to interesting paths only
            interesting = [u for u in urls if re.search(
                r"\.(php|asp|aspx|jsp|env|sql|bak|json|xml|config|log|txt)$"
                r"|/admin|/api|/login|/upload|/backup|/debug|/test|/dev",
                u, re.I
            )]
            result["wayback_urls"] = interesting[:60]
    except Exception:
        pass

    # ── GitHub public code leak search ────────────────────────────────────────
    try:
        r = requests.get(
            f"https://api.github.com/search/code?q={quote(domain)}+in:file"
            f"&sort=indexed&per_page=10",
            timeout=10,
            headers={
                "User-Agent":  "Mozilla/5.0",
                "Accept":      "application/vnd.github.v3+json",
            },
        )
        if r.status_code == 200:
            items = r.json().get("items", [])
            for item in items:
                result["github_leaks"].append({
                    "repo":  item.get("repository", {}).get("full_name", "?"),
                    "file":  item.get("name", "?"),
                    "url":   item.get("html_url", "?"),
                })
    except Exception:
        pass

    return result


# ── CLOUDFLARE / CDN BYPASS ───────────────────────────────────────────────────

def bypass_cdn(domain: str) -> dict:
    """
    Attempt to discover the real origin IP behind Cloudflare / CDN:
    - DNS history via SecurityTrails-compatible public APIs
    - crt.sh subdomain IPs that may point to origin
    - MX record IP (mail servers are often on the same host)
    - Common origin-revealing subdomains (direct.*, origin.*, cpanel.*)
    - SPF record IP extraction
    - Shodan internetdb cross-reference
    """
    result = {
        "cdn_detected":   False,
        "cdn_name":       None,
        "real_ip_candidates": [],
        "method_used":    [],
        "spf_ips":        [],
        "mx_ips":         [],
    }

    CLOUDFLARE_RANGES_PREFIX = ("104.", "172.64.", "172.65.", "172.66.", "172.67.",
                                 "108.162.", "141.101.", "188.114.", "190.93.",
                                 "197.234.", "198.41.")
    CDN_HEADERS = {
        "cf-ray":        "Cloudflare",
        "x-sucuri-id":   "Sucuri",
        "x-cdn":         "Generic CDN",
        "x-akamai-transformed": "Akamai",
        "x-amz-cf-id":   "Amazon CloudFront",
        "x-vercel-id":   "Vercel",
        "x-netlify":     "Netlify",
        "server":        None,  # checked separately
    }

    candidates = set()

    # Step 1 — detect CDN
    try:
        r = requests.get(f"https://{domain}", timeout=8, verify=False,
                         headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
        hdrs = {k.lower(): v for k, v in r.headers.items()}
        # Check named CDN headers first
        for hdr, cdn_name in CDN_HEADERS.items():
            if hdr in hdrs and cdn_name is not None:
                result["cdn_detected"] = True
                result["cdn_name"]     = cdn_name
                break
        # If not yet detected, check server header for cloudflare
        if not result["cdn_detected"]:
            if "cloudflare" in hdrs.get("server", "").lower():
                result["cdn_detected"] = True
                result["cdn_name"]     = "Cloudflare"
    except Exception:
        pass

    # Step 2 — MX record IPs
    try:
        mx_answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        for rdata in mx_answers:
            mx_host = str(rdata.exchange).rstrip(".")
            try:
                mx_ip = socket.gethostbyname(mx_host)
                result["mx_ips"].append({"host": mx_host, "ip": mx_ip})
                if not any(mx_ip.startswith(p) for p in CLOUDFLARE_RANGES_PREFIX):
                    candidates.add(mx_ip)
                    result["method_used"].append("MX record")
            except Exception:
                pass
    except Exception:
        pass

    # Step 3 — SPF record IP extraction
    try:
        txt_answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        ip_pat = re.compile(r"ip[46]:(\S+)")
        for rdata in txt_answers:
            txt = rdata.to_text()
            if "spf" in txt.lower():
                for match in ip_pat.findall(txt):
                    ip = match.split("/")[0]
                    result["spf_ips"].append(ip)
                    if not any(ip.startswith(p) for p in CLOUDFLARE_RANGES_PREFIX):
                        candidates.add(ip)
                        result["method_used"].append("SPF record")
    except Exception:
        pass

    # Step 4 — common bypass subdomains
    bypass_subs = ["direct", "origin", "origin-www", "real", "backend",
                   "cpanel", "whm", "webmail", "ftp", "mail", "smtp"]
    for sub in bypass_subs:
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            if not any(ip.startswith(p) for p in CLOUDFLARE_RANGES_PREFIX):
                candidates.add(ip)
                result["method_used"].append(f"Bypass subdomain ({fqdn})")
        except Exception:
            pass

    # Step 5 — crt.sh subdomains IPs
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json",
                         timeout=12, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code == 200:
            subs = set()
            for entry in r.json():
                for line in entry.get("name_value", "").splitlines():
                    line = line.strip().lstrip("*.")
                    if domain in line and " " not in line:
                        subs.add(line)
            for sub in list(subs)[:20]:
                try:
                    ip = socket.gethostbyname(sub)
                    if not any(ip.startswith(p) for p in CLOUDFLARE_RANGES_PREFIX):
                        candidates.add(ip)
                        result["method_used"].append(f"crt.sh subdomain ({sub})")
                except Exception:
                    pass
    except Exception:
        pass

    result["real_ip_candidates"] = list(candidates)
    result["method_used"]        = list(set(result["method_used"]))
    return result


# ── CMS & ADMIN PANEL DETECTION ───────────────────────────────────────────────

CMS_SIGNATURES = {
    "WordPress":   ["/wp-login.php", "/wp-admin/", "/wp-content/", "/xmlrpc.php"],
    "Joomla":      ["/administrator/", "/components/", "/modules/", "/templates/"],
    "Drupal":      ["/user/login", "/sites/default/", "/core/misc/drupal.js"],
    "Magento":     ["/admin/", "/index.php/admin/", "/downloader/"],
    "OpenCart":    ["/admin/index.php", "/catalog/view/"],
    "PrestaShop":  ["/adminpanel/", "/modules/ps_"],
    "TYPO3":       ["/typo3/", "/typo3conf/"],
    "Laravel":     ["/login", "/_debugbar/"],
    "Django":      ["/admin/", "/django-admin/"],
    "Flask":       ["/__debug__/", "/console"],
    "Strapi":      ["/admin/", "/api/"],
    "Ghost":       ["/ghost/", "/ghost/signin/"],
}

ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/login", "/admin/index.php",
    "/administrator", "/administrator/index.php",
    "/adminpanel", "/admin-panel", "/admin_area",
    "/backend", "/backend/login", "/dashboard",
    "/login", "/signin", "/user/login", "/account/login",
    "/portal", "/manage", "/management", "/manager",
    "/wp-admin", "/wp-login.php", "/wp-admin/admin-ajax.php",
    "/cpanel", "/whm", "/webmail",
    "/phpmyadmin", "/phpmyadmin/", "/pma/",
    "/adminer.php", "/adminer/",
    "/config", "/configuration.php", "/config.php",
    "/.env", "/.git/config", "/.git/HEAD",
    "/api/v1", "/api/v2", "/api/admin",
    "/console", "/actuator", "/actuator/health",
    "/actuator/env", "/actuator/mappings",
    "/swagger", "/swagger-ui", "/swagger-ui.html",
    "/swagger.json", "/openapi.json", "/api-docs",
    "/graphql", "/graphiql",
    "/jenkins", "/jenkins/login",
    "/jira", "/confluence",
    "/kibana", "/grafana",
    "/solr", "/solr/admin",
    "/elmah.axd", "/trace.axd",
    "/server-status", "/server-info",
    "/.DS_Store", "/robots.txt", "/sitemap.xml",
    "/backup", "/backup.zip", "/backup.sql",
    "/dump.sql", "/db.sql", "/database.sql",
    "/.htaccess", "/web.config",
]

SENSITIVE_STATUS = {200, 201, 301, 302, 401, 403}


def detect_cms_and_admin(domain: str, max_threads: int = 25) -> dict:
    """
    - CMS fingerprinting via known path probing
    - Admin panel discovery across 50+ common paths
    - Sensitive file exposure check
    Returns detected CMS list and all interesting endpoints found.
    """
    result = {
        "cms_detected": [],
        "admin_panels": [],
        "sensitive_files": [],
        "interesting_paths": [],
    }

    base = f"https://{domain}"
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; PriViSecurity/2.0)"})
    session.verify = False

    def probe(path):
        url = base + path
        try:
            r = session.get(url, timeout=6, allow_redirects=False)
            return path, r.status_code, len(r.content), r.headers.get("Location", "")
        except Exception:
            return path, None, 0, ""

    try:
        # CMS detection
        for cms, paths in CMS_SIGNATURES.items():
            for path in paths:
                _, code, size, _ = probe(path)
                if code in SENSITIVE_STATUS and size > 100:
                    if cms not in result["cms_detected"]:
                        result["cms_detected"].append(cms)
                    break

        # Admin + sensitive path scan (threaded)
        with ThreadPoolExecutor(max_workers=max_threads) as ex:
            futures = {ex.submit(probe, p): p for p in ADMIN_PATHS}
            for future in as_completed(futures):
                path, code, size, location = future.result()
                if code is None:
                    continue
                entry = {"path": path, "status": code, "size": size, "redirect": location}
                if path in ["/.env", "/.git/config", "/.git/HEAD",
                            "/backup.zip", "/backup.sql", "/dump.sql",
                            "/db.sql", "/database.sql", "/.htaccess", "/web.config"]:
                    if code == 200 and size > 0:
                        result["sensitive_files"].append(entry)
                elif path in ["/wp-admin", "/administrator", "/phpmyadmin",
                              "/adminer.php", "/cpanel", "/dashboard", "/admin"]:
                    if code in SENSITIVE_STATUS:
                        result["admin_panels"].append(entry)
                elif code in {200, 401, 403} and size > 100:
                    result["interesting_paths"].append(entry)
    finally:
        # Sort by status
        for key in ["admin_panels", "sensitive_files", "interesting_paths"]:
            result[key].sort(key=lambda x: x["status"])
        session.close()

    return result


# ── API FUZZING ───────────────────────────────────────────────────────────────

API_PATHS = [
    # REST versioned endpoints
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/api/v1/users", "/api/v1/user", "/api/v1/admin",
    "/api/v1/config", "/api/v1/status", "/api/v1/health",
    "/api/v1/accounts", "/api/v1/me", "/api/v1/profile",
    "/api/v1/token", "/api/v1/auth", "/api/v1/login",
    "/api/v2/users", "/api/v2/admin", "/api/v2/config",
    # GraphQL
    "/graphql", "/graphiql", "/graph", "/gql",
    "/api/graphql", "/v1/graphql", "/v2/graphql",
    # Swagger / OpenAPI
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/swagger-ui.html", "/swagger-ui", "/api-docs", "/api-docs.json",
    "/v2/api-docs", "/v3/api-docs",
    # Spring Boot actuator
    "/actuator", "/actuator/health", "/actuator/info",
    "/actuator/env", "/actuator/mappings", "/actuator/beans",
    "/actuator/loggers", "/actuator/threaddump", "/actuator/heapdump",
    # Debug / internal
    "/__debug__", "/debug", "/_debug", "/console",
    "/status", "/health", "/health-check", "/ping",
    "/metrics", "/stats", "/info",
    # SOAP / WSDL
    "/soap", "/wsdl", "/service.wsdl", "/api/soap",
    # Laravel / Framework
    "/telescope", "/horizon", "/_debugbar",
    # Node
    "/.well-known/openid-configuration",
    "/oauth/.well-known/openid-configuration",
]

GRAPHQL_INTROSPECTION = '{"query":"{__schema{types{name kind}}}"}'
# SQLI_PROBES removed — active SQLi testing is out of scope for recon


def fuzz_api(domain: str, max_threads: int = 20) -> dict:
    """
    - Probe all common API endpoints for unauthenticated access
    - Attempt GraphQL introspection
    - Test for IDOR on /api/v1/users/1, /2, /3
    - Check for verbose error messages (SQL/stack traces)
    - Detect exposed Swagger/OpenAPI schemas
    """
    result = {
        "open_endpoints":       [],
        "graphql_introspection": None,
        "swagger_exposed":      [],
        "actuator_exposed":     [],
        "error_disclosure":     [],
        "idor_hints":           [],
    }

    base    = f"https://{domain}"
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; PriViSecurity/2.0)",
        "Accept":     "application/json, text/plain, */*",
    })

    def probe(path):
        url = base + path
        try:
            r = session.get(url, timeout=6, verify=False, allow_redirects=False)
            return path, r.status_code, r.text[:400], r.headers.get("Content-Type", "")
        except Exception:
            return path, None, "", ""

    # Parallel endpoint probing
    with ThreadPoolExecutor(max_workers=max_threads) as ex:
        futures = {ex.submit(probe, p): p for p in API_PATHS}
        for future in as_completed(futures):
            path, code, body, ctype = future.result()
            if code is None:
                continue

            is_json = "json" in ctype.lower()
            body_l  = body.lower()

            # Open unauthenticated endpoint
            if code == 200 and (is_json or len(body) > 50):
                entry = {"path": path, "status": code,
                         "content_type": ctype[:40], "preview": body[:120]}
                if any(k in path for k in ["/swagger", "/openapi", "/api-docs"]):
                    result["swagger_exposed"].append(entry)
                elif "actuator" in path:
                    result["actuator_exposed"].append(entry)
                else:
                    result["open_endpoints"].append(entry)

            # Verbose error disclosure
            error_kws = ["traceback", "stack trace", "exception", "sqlexception",
                         "syntax error", "mysql_fetch", "pg_query", "ora-0",
                         "undefined index", "notice:", "warning:"]
            if any(kw in body_l for kw in error_kws):
                result["error_disclosure"].append({
                    "path": path, "status": code, "snippet": body[:200]
                })

    # GraphQL introspection
    for gql_path in ["/graphql", "/api/graphql", "/gql", "/v1/graphql"]:
        try:
            r = session.post(
                base + gql_path,
                data=GRAPHQL_INTROSPECTION,
                headers={"Content-Type": "application/json"},
                timeout=8, verify=False,
            )
            if r.status_code == 200 and "__schema" in r.text:
                result["graphql_introspection"] = {
                    "path":    gql_path,
                    "status":  r.status_code,
                    "preview": r.text[:300],
                }
                break
        except Exception:
            pass

    # IDOR probe — /api/v1/users/1, /2, /3
    for uid in [1, 2, 3]:
        for path in [f"/api/v1/users/{uid}", f"/api/v1/user/{uid}",
                     f"/api/users/{uid}", f"/api/v2/users/{uid}"]:
            _, code, body, ctype = probe(path)
            if code == 200 and ("json" in (ctype or "").lower() or len(body) > 40):
                result["idor_hints"].append({
                    "path": path, "status": code, "preview": body[:150]
                })
                break

    session.close()
    return result


# ── AUTH TESTING ──────────────────────────────────────────────────────────────

DEFAULT_CREDENTIALS = [
    ("admin",     "admin"),
    ("admin",     "password"),
    ("admin",     "admin123"),
    ("admin",     "123456"),
    ("admin",     ""),
    ("root",      "root"),
    ("root",      "toor"),
    ("root",      "password"),
    ("test",      "test"),
    ("user",      "user"),
    ("guest",     "guest"),
    ("demo",      "demo"),
    ("admin",     "admin@123"),
    ("administrator", "administrator"),
]

LOGIN_PATHS = [
    "/login", "/admin/login", "/admin", "/wp-login.php",
    "/administrator/index.php", "/user/login", "/signin",
    "/auth/login", "/api/v1/auth", "/api/login",
]

# JWT_WEAK_SECRETS — reserved for future active JWT cracking module


def test_auth(domain: str) -> dict:
    """
    - Default credential probing on discovered login endpoints
    - HTTP Basic Auth probe
    - JWT none-algorithm and weak secret detection
    - Session fixation indicator check
    - Password in URL detection
    - Missing auth on sensitive endpoints
    """
    result = {
        "login_pages_found": [],
        "default_creds_hits": [],
        "basic_auth_exposed": [],
        "jwt_issues":         [],
        "session_issues":     [],
        "auth_bypass_hints":  [],
        "password_in_url":    [],
    }

    base    = f"https://{domain}"
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; PriViSecurity/2.0)",
        "Accept":     "application/json, text/html, */*",
    })

    # Step 1 — find login pages
    for path in LOGIN_PATHS:
        try:
            r = session.get(base + path, timeout=6, verify=False,
                            allow_redirects=True)
            if r.status_code in {200, 401, 403} and len(r.content) > 200:
                page_lower = r.text.lower()
                has_form   = any(k in page_lower for k in
                                 ["password", "login", "signin", "username", "email"])
                result["login_pages_found"].append({
                    "path":   path,
                    "status": r.status_code,
                    "has_form": has_form,
                })

                # Step 2 — HTTP Basic Auth (401 with WWW-Authenticate)
                www_auth = r.headers.get("WWW-Authenticate", "")
                if r.status_code == 401 and "Basic" in www_auth:
                    result["basic_auth_exposed"].append({
                        "path":  path,
                        "realm": www_auth[:80],
                    })
                    # Try default creds via Basic Auth
                    for user, pw in DEFAULT_CREDENTIALS[:6]:
                        try:
                            br = requests.get(base + path, auth=(user, pw),
                                              timeout=5, verify=False)
                            if br.status_code == 200:
                                result["default_creds_hits"].append({
                                    "path":     path,
                                    "method":   "HTTP Basic",
                                    "username": user,
                                    "password": pw,
                                    "status":   200,
                                })
                        except Exception:
                            pass

                # Step 3 — form-based default credential probe
                if has_form and r.status_code == 200:
                    soup    = BeautifulSoup(r.text, "html.parser")
                    form    = soup.find("form")
                    action  = ""
                    if form:
                        action = form.get("action", path)
                        if not action.startswith("http"):
                            action = base + ("/" + action.lstrip("/"))
                        inputs   = form.find_all("input")
                        user_field = next((i.get("name") for i in inputs
                                           if i.get("type") in ["text","email"]
                                           or "user" in (i.get("name") or "").lower()
                                           or "email" in (i.get("name") or "").lower()), "username")
                        pass_field = next((i.get("name") for i in inputs
                                           if i.get("type") == "password"
                                           or "pass" in (i.get("name") or "").lower()), "password")
                        for user, pw in DEFAULT_CREDENTIALS[:8]:
                            try:
                                pr = session.post(
                                    action,
                                    data={user_field: user, pass_field: pw},
                                    timeout=6, verify=False,
                                    allow_redirects=True,
                                )
                                body_l = pr.text.lower()
                                # Signs of successful login
                                success_signals = ["dashboard", "welcome", "logout",
                                                   "sign out", "profile", "account"]
                                fail_signals    = ["invalid", "incorrect", "wrong",
                                                   "failed", "error", "denied"]
                                if (pr.status_code in {200, 302}
                                        and any(s in body_l for s in success_signals)
                                        and not any(f in body_l for f in fail_signals)):
                                    result["default_creds_hits"].append({
                                        "path":     path,
                                        "method":   "Form POST",
                                        "username": user,
                                        "password": pw,
                                        "status":   pr.status_code,
                                    })
                            except Exception:
                                pass

                # Step 4 — session fixation check
                for cookie in r.cookies:
                    if "session" in cookie.name.lower() or "sess" in cookie.name.lower():
                        if not cookie.has_nonstandard_attr("HttpOnly") and not cookie._rest.get("HttpOnly"):
                            result["session_issues"].append({
                                "path":   path,
                                "issue":  f"Session cookie '{cookie.name}' missing HttpOnly flag",
                                "cookie": f"{cookie.name}={str(cookie.value)[:30]}",
                            })
                        if not cookie.secure:
                            result["session_issues"].append({
                                "path":   path,
                                "issue":  f"Session cookie '{cookie.name}' missing Secure flag",
                                "cookie": f"{cookie.name}={str(cookie.value)[:30]}",
                            })

        except Exception:
            pass

    # Step 5 — JWT none-algorithm probe
    none_header  = base64.urlsafe_b64encode(
        b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
    none_payload = base64.urlsafe_b64encode(
        b'{"sub":"1","role":"admin","iat":1}').decode().rstrip("=")
    none_jwt = f"{none_header}.{none_payload}."

    for path in ["/api/v1/admin", "/api/v1/users", "/admin", "/dashboard"]:
        try:
            r = requests.get(
                base + path,
                headers={"Authorization": f"Bearer {none_jwt}",
                         "User-Agent": "Mozilla/5.0"},
                timeout=6, verify=False,
            )
            if r.status_code == 200 and len(r.content) > 50:
                result["jwt_issues"].append({
                    "path":  path,
                    "issue": "Server accepted JWT with 'none' algorithm",
                    "status": r.status_code,
                })
        except Exception:
            pass

    # Step 6 — auth bypass via header manipulation
    bypass_headers = [
        {"X-Original-URL":  "/admin"},
        {"X-Rewrite-URL":   "/admin"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP":     "127.0.0.1"},
        {"X-Client-IP":     "127.0.0.1"},
    ]
    for path in ["/admin", "/dashboard", "/api/v1/admin"]:
        for hdr in bypass_headers:
            try:
                r = requests.get(
                    base + path,
                    headers={**hdr, "User-Agent": "Mozilla/5.0"},
                    timeout=5, verify=False,
                )
                if r.status_code == 200 and len(r.content) > 100:
                    result["auth_bypass_hints"].append({
                        "path":   path,
                        "header": hdr,
                        "status": r.status_code,
                        "size":   len(r.content),
                    })
            except Exception:
                pass

    session.close()
    return result


# ── CVE CORRELATION (NVD API) ─────────────────────────────────────────────────

def correlate_cves(tech_stack: list, port_results: list) -> list:
    """
    Query NIST NVD API (free, no key needed) to map detected software
    versions to known CVEs. Combines tech stack + nmap version banners.
    Returns list of CVE findings with CVSS score and description.
    """
    findings  = []
    seen_cves = set()
    NVD_URL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Build search terms from tech stack
    search_terms = []
    for tech in tech_stack:
        name = tech.split("(")[0].strip().split(" ")[0].lower()
        if name and name not in ["none", "could", "detected"]:
            search_terms.append(name)

    # Add software from nmap version banners
    for port in port_results:
        version = port.get("version", "").strip()
        service = port.get("service", "").strip()
        if version:
            search_terms.append(f"{service} {version}".strip())

    # Deduplicate and limit
    search_terms = list(dict.fromkeys(search_terms))[:12]

    for term in search_terms:
        if not term or len(term) < 3:
            continue
        try:
            r = requests.get(
                NVD_URL,
                params={
                    "keywordSearch":    term,
                    "resultsPerPage":   5,
                    "cvssV3Severity":   "HIGH",
                },
                timeout=10,
                headers={"User-Agent": "Mozilla/5.0 (PriViSecurity/5.0)"},
            )
            if r.status_code != 200:
                continue
            data = r.json()
            for vuln in data.get("vulnerabilities", []):
                cve   = vuln.get("cve", {})
                cve_id = cve.get("id", "?")
                if cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)

                # Description
                descs = cve.get("descriptions", [])
                desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "No description")

                # CVSS v3 score
                metrics    = cve.get("metrics", {})
                cvss_data  = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
                score      = "N/A"
                severity   = "N/A"
                vector     = "N/A"
                if cvss_data:
                    cvss = cvss_data[0].get("cvssData", {})
                    score    = str(cvss.get("baseScore", "N/A"))
                    severity = cvss.get("baseSeverity", "N/A")
                    vector   = cvss.get("vectorString", "N/A")

                findings.append({
                    "cve_id":    cve_id,
                    "term":      term,
                    "score":     score,
                    "severity":  severity,
                    "vector":    vector,
                    "desc":      desc[:300],
                    "url":       f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                })
            time.sleep(0.6)   # NVD rate limit: ~5 req/s without API key
        except Exception:
            continue

    # Sort by CVSS score descending
    findings.sort(
        key=lambda x: float(x["score"]) if x["score"] != "N/A" else 0,
        reverse=True
    )
    return findings


# ── JAVASCRIPT FILE ANALYSIS ──────────────────────────────────────────────────

SECRET_PATTERNS = {
    "AWS Access Key":       re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Key":       re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    "Generic API Key":      re.compile(r"(?i)(api[_-]?key|apikey).{0,10}['\"][a-zA-Z0-9_\-]{20,}['\"]"),
    "Generic Secret":       re.compile(r"(?i)(secret|private.?key).{0,10}['\"][a-zA-Z0-9_\-]{16,}['\"]"),
    "Bearer Token":         re.compile(r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*"),
    "Basic Auth (b64)":     re.compile(r"(?i)basic\s+[a-zA-Z0-9+/]{20,}={0,2}"),
    "Private Key Header":   re.compile(r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"),
    "Google API Key":       re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Stripe Key":           re.compile(r"(?:r|s)k_(?:live|test)_[0-9a-zA-Z]{24}"),
    "Slack Token":          re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,}"),
    "GitHub Token":         re.compile(r"gh[pousr]_[0-9a-zA-Z]{36}"),
    "JWT Token":            re.compile(r"eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+"),
    "Internal Endpoint":    re.compile(r"(?i)(https?://(?:localhost|127\.|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)[^\s\"']+)"),
    "Database URL":         re.compile(r"(?i)(mongodb|postgres|mysql|redis|amqp)://[^\s\"']{8,}"),
    "Password in Code":     re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]"),
    "Email Address":        re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
}

INTERNAL_PATH_PAT = re.compile(
    r"['\"](/[a-zA-Z0-9_\-/]+(?:\.[a-zA-Z]{2,4})?)['\"]"
)


def analyze_js_files(domain: str, max_files: int = 20) -> dict:
    """
    1. Fetch homepage and discover all linked JS files
    2. Download each JS file
    3. Scan for secrets, API keys, internal endpoints, hardcoded passwords
    4. Extract internal paths and endpoints from JS code
    """
    result = {
        "js_files_found":    [],
        "secrets":           [],
        "internal_paths":    [],
        "errors":            [],
    }

    base_url = f"https://{domain}"
    headers  = {"User-Agent": "Mozilla/5.0 (compatible; PriViSecurity/5.0)"}
    js_urls  = set()

    # Step 1 — discover JS files from homepage
    try:
        r    = requests.get(base_url, timeout=8, verify=False, headers=headers)
        soup = BeautifulSoup(r.text, "html.parser")
        for tag in soup.find_all("script", src=True):
            src = tag["src"]
            if src.startswith("//"):
                src = "https:" + src
            elif src.startswith("/"):
                src = base_url + src
            elif not src.startswith("http"):
                src = base_url + "/" + src
            # Only scan same-domain JS
            if domain in src:
                js_urls.add(src)
    except Exception as e:
        result["errors"].append(f"Homepage fetch failed: {e}")
        return result

    result["js_files_found"] = list(js_urls)[:max_files]

    # Step 2 — download and scan each JS file
    for js_url in result["js_files_found"]:
        try:
            r = requests.get(js_url, timeout=8, verify=False, headers=headers)
            if r.status_code != 200:
                continue
            content = r.text

            # Step 3 — secret scanning
            for secret_type, pattern in SECRET_PATTERNS.items():
                matches = pattern.findall(content)
                for match in matches[:3]:   # cap at 3 per type per file
                    match_str = match if isinstance(match, str) else match[0]
                    match_str = match_str.strip()
                    # Skip very short or obvious false positives
                    if len(match_str) < 6:
                        continue
                    if secret_type == "Email Address" and any(
                        skip in match_str for skip in ["example", "yourdomain", "@2x", ".png"]
                    ):
                        continue
                    result["secrets"].append({
                        "file":    js_url.split("/")[-1][:40],
                        "type":    secret_type,
                        "match":   match_str[:120],
                    })

            # Step 4 — internal path extraction
            paths = INTERNAL_PATH_PAT.findall(content)
            for path in paths:
                if len(path) > 3 and not any(skip in path for skip in [
                    ".png", ".jpg", ".gif", ".svg", ".ico", ".woff",
                    ".ttf", ".eot", ".css", "__", "{{", "}}"
                ]):
                    result["internal_paths"].append({
                        "file":  js_url.split("/")[-1][:40],
                        "path":  path,
                    })

        except Exception as e:
            result["errors"].append(f"{js_url}: {e}")

    # Deduplicate internal paths
    seen_paths = set()
    deduped    = []
    for p in result["internal_paths"]:
        key = p["path"]
        if key not in seen_paths:
            seen_paths.add(key)
            deduped.append(p)
    result["internal_paths"] = deduped[:60]

    # Deduplicate secrets (same match from multiple files)
    seen_secrets = set()
    deduped_s    = []
    for s in result["secrets"]:
        key = (s["type"], s["match"][:40])
        if key not in seen_secrets:
            seen_secrets.add(key)
            deduped_s.append(s)
    result["secrets"] = deduped_s

    return result


# ── WAF DETECTION ─────────────────────────────────────────────────────────────

WAF_SIGNATURES = {
    "cf-ray":                "Cloudflare",
    "x-sucuri-id":           "Sucuri",
    "x-sucuri-cache":        "Sucuri",
    "x-firewall-protection": "Generic WAF",
    "x-waf-event-info":      "Barracuda WAF",
}

SERVER_WAF_MAP = {
    "cloudflare": "Cloudflare",
    "sucuri":     "Sucuri",
    "incapsula":  "Imperva Incapsula",
    "akamai":     "Akamai",
    "fortiweb":   "FortiWeb",
    "f5":         "F5 BIG-IP",
}


def detect_waf(domain: str) -> str:
    try:
        resp = requests.get(
            f"https://{domain}",
            timeout=6,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; security-audit/1.0)"},
            allow_redirects=True,
        )
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        for sig, waf_name in WAF_SIGNATURES.items():
            if sig in headers_lower:
                return f"Detected  -  {waf_name} ({headers_lower[sig]})"

        # Check server header
        server = headers_lower.get("server", "").lower()
        for keyword, name in SERVER_WAF_MAP.items():
            if keyword in server:
                return f"Detected  -  {name} (via Server header)"

        # No WAF found but return server info as useful intel
        server_raw = resp.headers.get("server", "")
        return f"None Detected  (Server: {server_raw})" if server_raw else "None Detected"

    except requests.RequestException as e:
        return f"Detection failed: {e}"


# ── TECH STACK FINGERPRINTING ─────────────────────────────────────────────────

TECH_SIGNATURES = {
    # Server headers
    "server": {
        "nginx":          "Nginx",
        "apache":         "Apache",
        "iis":            "Microsoft IIS",
        "netlify":        "Netlify",
        "cloudflare":     "Cloudflare",
        "litespeed":      "LiteSpeed",
        "caddy":          "Caddy",
        "gunicorn":       "Gunicorn (Python)",
        "openresty":      "OpenResty",
        "vercel":         "Vercel",
    },
    # X-Powered-By / other headers
    "x-powered-by": {
        "php":            "PHP",
        "asp.net":        "ASP.NET",
        "express":        "Express.js (Node.js)",
        "next.js":        "Next.js",
    },
    # Cookie names
    "cookies": {
        "laravel_session": "Laravel (PHP)",
        "django":          "Django (Python)",
        "rack.session":    "Ruby on Rails",
        "jsessionid":      "Java (JSP/Servlet)",
        "phpsessid":       "PHP",
        "wp-settings":     "WordPress",
    },
    # HTML body patterns
    "body": {
        "wp-content":       "WordPress",
        "wp-includes":      "WordPress",
        "shopify":          "Shopify",
        "squarespace":      "Squarespace",
        "wix.com":          "Wix",
        "react":            "React",
        "__next":           "Next.js",
        "gatsby":           "Gatsby",
        "vue.js":           "Vue.js",
        "angular":          "Angular",
        "bootstrap":        "Bootstrap CSS",
        "jquery":           "jQuery",
        "drupal":           "Drupal",
        "joomla":           "Joomla",
    },
}


def fingerprint_tech_stack(domain: str) -> list:
    """
    Fingerprint the technology stack of the target by analysing
    HTTP response headers, cookies, and page body patterns.
    Returns a deduplicated sorted list of detected technologies.
    """
    detected = set()
    try:
        resp = requests.get(
            f"https://{domain}",
            timeout=8,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; security-audit/1.0)"},
            allow_redirects=True,
        )
        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
        body_lower    = resp.text.lower()

        # Server header
        server_val = headers_lower.get("server", "")
        for keyword, label in TECH_SIGNATURES["server"].items():
            if keyword in server_val:
                detected.add(label)

        # X-Powered-By
        xpb = headers_lower.get("x-powered-by", "")
        for keyword, label in TECH_SIGNATURES["x-powered-by"].items():
            if keyword in xpb:
                detected.add(label)

        # Cookies
        set_cookie = headers_lower.get("set-cookie", "")
        for keyword, label in TECH_SIGNATURES["cookies"].items():
            if keyword in set_cookie:
                detected.add(label)

        # Body patterns
        for keyword, label in TECH_SIGNATURES["body"].items():
            if keyword in body_lower:
                detected.add(label)

        # Extra: detect CDN from headers
        if "x-amz-cf-id" in headers_lower or "x-amz-request-id" in headers_lower:
            detected.add("Amazon CloudFront CDN")
        if "x-vercel-id" in headers_lower:
            detected.add("Vercel")
        if "x-netlify" in headers_lower or "netlify" in headers_lower.get("server",""):
            detected.add("Netlify")

    except requests.RequestException:
        pass

    return sorted(detected) if detected else ["Could not fingerprint (connection issue)"]


# ── SUBDOMAIN ENUMERATION ─────────────────────────────────────────────────────

SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "email",
    "admin", "administrator", "portal", "dashboard", "panel", "cpanel",
    "api", "api2", "api-v1", "api-v2", "rest", "graphql", "backend",
    "dev", "development", "staging", "stage", "uat", "qa", "test",
    "demo", "sandbox", "beta", "alpha", "preview", "preprod",
    "app", "apps", "mobile", "m", "web", "webapp",
    "cdn", "static", "assets", "media", "images", "img", "files",
    "blog", "shop", "store", "pay", "payment", "checkout", "billing",
    "help", "support", "docs", "documentation", "wiki", "kb",
    "status", "monitor", "health", "metrics", "grafana", "kibana",
    "vpn", "remote", "gateway", "proxy", "ns1", "ns2", "ns3",
    "internal", "intranet", "extranet", "private", "secure",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "auth", "login", "sso", "oauth", "id", "accounts",
    "git", "gitlab", "github", "jira", "jenkins", "ci", "cd",
    "mail2", "mx1", "mx2", "mx", "exchange",
]


def enumerate_subdomains(domain: str, max_threads: int = 30) -> list:
    """
    Brute-force subdomain enumeration using a curated wordlist.
    Uses threading for speed. Returns list of dicts with subdomain + IP.
    Confirms existence via DNS resolution (not just HTTP) to avoid
    false positives from wildcard DNS.
    """
    found       = []
    found_lock  = threading.Lock()

    # Wildcard detection — if a random subdomain resolves, it's a wildcard DNS
    # and we can't trust resolution-based confirmation
    random_sub  = f"privi-wildcard-check-xq9z.{domain}"
    is_wildcard = False
    try:
        socket.gethostbyname(random_sub)
        is_wildcard = True
    except socket.gaierror:
        pass

    def check(sub: str):
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            if is_wildcard:
                # Extra check: wildcard domains all resolve to the same IP
                # Only flag if this IP differs from the base domain IP
                try:
                    base_ip = socket.gethostbyname(domain)
                    if ip == base_ip:
                        return  # likely wildcard, skip
                except Exception:
                    return
            with found_lock:
                found.append({"subdomain": fqdn, "ip": ip})
        except (socket.gaierror, socket.timeout):
            pass

    threads = []
    for word in SUBDOMAIN_WORDLIST:
        t = threading.Thread(target=check, args=(word,), daemon=True)
        threads.append(t)
        t.start()
        # Throttle: keep max_threads active at once
        while sum(1 for th in threads if th.is_alive()) >= max_threads:
            time.sleep(0.05)

    for t in threads:
        t.join(timeout=8)

    # Sort by subdomain name for clean output
    return sorted(found, key=lambda x: x["subdomain"])


# ── DNS ENUMERATION ───────────────────────────────────────────────────────────

def enumerate_dns(domain: str) -> list:
    records = []
    for r_type in ["A", "AAAA", "MX", "NS", "TXT", "SOA"]:
        try:
            answers = dns.resolver.resolve(domain, r_type, lifetime=5)
            for rdata in answers:
                records.append(f"{r_type}: {rdata.to_text()}")
        except Exception:
            continue
    return records


# ── NMAP SCAN ─────────────────────────────────────────────────────────────────

PORT_RISK = {
    21:    ("FTP",              "HIGH   - credentials often sent in plaintext"),
    22:    ("SSH",              "LOW    - encrypted, but brute-force target"),
    23:    ("Telnet",           "CRITICAL - plaintext remote access"),
    25:    ("SMTP",             "MEDIUM - mail relay / spam abuse risk"),
    53:    ("DNS",              "MEDIUM - zone transfer / amplification risk"),
    80:    ("HTTP",             "LOW    - unencrypted web traffic"),
    110:   ("POP3",             "HIGH   - plaintext mail retrieval"),
    143:   ("IMAP",             "HIGH   - plaintext mail access"),
    443:   ("HTTPS",            "INFO   - encrypted web traffic"),
    445:   ("SMB",              "CRITICAL - common ransomware vector"),
    1433:  ("MSSQL",            "HIGH   - database exposure"),
    1521:  ("Oracle DB",        "HIGH   - database exposure"),
    2375:  ("Docker (unauth)",  "CRITICAL - unauthenticated Docker API"),
    2376:  ("Docker TLS",       "MEDIUM - Docker with TLS"),
    3000:  ("Dev server",       "MEDIUM - often unprotected app server"),
    3306:  ("MySQL",            "HIGH   - database exposure"),
    3389:  ("RDP",              "HIGH   - remote desktop brute-force target"),
    4443:  ("HTTPS-alt",        "LOW    - alternate HTTPS port"),
    5432:  ("PostgreSQL",       "HIGH   - database exposure"),
    5900:  ("VNC",              "HIGH   - remote desktop, often no auth"),
    6379:  ("Redis",            "CRITICAL - often no auth by default"),
    7001:  ("WebLogic",         "HIGH   - known critical CVEs"),
    8000:  ("HTTP-alt",         "MEDIUM - dev/staging server"),
    8080:  ("HTTP-proxy",       "MEDIUM - proxy / app server"),
    8443:  ("HTTPS-alt",        "LOW    - alternate HTTPS"),
    8888:  ("Jupyter/HTTP-alt", "HIGH   - Jupyter often has no auth"),
    9200:  ("Elasticsearch",    "CRITICAL - often unauthenticated"),
    9300:  ("Elasticsearch",    "HIGH   - cluster communication port"),
    27017: ("MongoDB",          "CRITICAL - often unauthenticated"),
    27018: ("MongoDB",          "HIGH   - shard server"),
}

EXPANDED_PORTS = ",".join(str(p) for p in sorted(PORT_RISK.keys()))


def run_nmap_scan(ip: str) -> tuple:
    """Returns (port_results list, vuln_findings list)."""
    port_results  = []
    vuln_findings = []
    try:
        nm = nmap.PortScanner()
        # -sV: version detection, -T4: fast timing, --script vuln
        scan_args = "-sV -T4 --script vuln --version-intensity 3"
        nm.scan(ip, arguments=f"{scan_args} -p {EXPANDED_PORTS}")

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in sorted(nm[host][proto].keys()):
                    pinfo = nm[host][proto][port]
                    risk_label = PORT_RISK.get(port, ("", ""))[1]
                    port_results.append({
                        "port":    port,
                        "proto":   proto,
                        "state":   pinfo.get("state", "?"),
                        "service": pinfo.get("name", "?"),
                        "version": pinfo.get("version", ""),
                        "risk":    risk_label,
                    })
                    if "script" in pinfo:
                        for script_id, output in pinfo["script"].items():
                            vuln_findings.append({
                                "port":      port,
                                "script_id": script_id,
                                "output":    output[:300],
                            })
    except Exception as e:
        vuln_findings.append({
            "port": 0, "script_id": "scan-error", "output": str(e)
        })

    return port_results, vuln_findings


# ── SSL CERTIFICATE INSPECTION ────────────────────────────────────────────────

def inspect_ssl_certificate(domain: str) -> dict:
    """
    Retrieve and parse the TLS certificate for the target.
    Extracts: issuer, expiry date, days remaining, SANs (Subject Alt Names).
    SANs are gold — they often reveal subdomains not found by wordlist.
    """
    result = {
        "valid":        False,
        "issuer":       "Unknown",
        "subject":      "Unknown",
        "expiry":       "Unknown",
        "days_left":    None,
        "sans":         [],
        "error":        None,
    }
    try:
        ctx  = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.create_connection((domain, 443), timeout=8),
            server_hostname=domain,
        )
        cert = conn.getpeercert()
        conn.close()

        # Issuer
        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
        result["issuer"]  = issuer_dict.get("organizationName", "Unknown")
        subject_dict      = dict(x[0] for x in cert.get("subject", []))
        result["subject"] = subject_dict.get("commonName", domain)

        # Expiry
        expiry_str = cert.get("notAfter", "")
        if expiry_str:
            expiry_dt          = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
            result["expiry"]   = expiry_dt.strftime("%Y-%m-%d")
            result["days_left"] = (expiry_dt - datetime.utcnow()).days

        # SANs — Subject Alternative Names
        sans = []
        for san_type, san_value in cert.get("subjectAltName", []):
            if san_type == "DNS":
                sans.append(san_value)
        result["sans"]  = sorted(set(sans))
        result["valid"] = True

    except ssl.SSLCertVerificationError as e:
        result["error"] = f"Certificate invalid/untrusted: {e}"
    except Exception as e:
        result["error"] = f"Could not retrieve certificate: {e}"

    return result


# ── HTTP SECURITY HEADERS CHECK ───────────────────────────────────────────────

SECURITY_HEADERS = {
    "strict-transport-security": {
        "label":  "Strict-Transport-Security (HSTS)",
        "risk":   "HIGH",
        "impact": "Missing HSTS allows SSL stripping attacks — attacker downgrades HTTPS to HTTP.",
    },
    "content-security-policy": {
        "label":  "Content-Security-Policy (CSP)",
        "risk":   "HIGH",
        "impact": "No CSP means injected scripts can load external malware freely.",
    },
    "x-frame-options": {
        "label":  "X-Frame-Options",
        "risk":   "MEDIUM",
        "impact": "Page can be embedded in an iframe — enables clickjacking attacks.",
    },
    "x-content-type-options": {
        "label":  "X-Content-Type-Options",
        "risk":   "MEDIUM",
        "impact": "MIME sniffing enabled — browsers may execute uploaded files as scripts.",
    },
    "referrer-policy": {
        "label":  "Referrer-Policy",
        "risk":   "LOW",
        "impact": "Sensitive URLs may leak in Referer header to third-party sites.",
    },
    "permissions-policy": {
        "label":  "Permissions-Policy",
        "risk":   "LOW",
        "impact": "Browser features (camera, mic, geolocation) unrestricted.",
    },
    "x-xss-protection": {
        "label":  "X-XSS-Protection",
        "risk":   "LOW",
        "impact": "Legacy XSS filter absent (deprecated but still checked by scanners).",
    },
    "cache-control": {
        "label":  "Cache-Control",
        "risk":   "LOW",
        "impact": "Sensitive pages may be cached by browsers or proxies.",
    },
}

RISK_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def check_security_headers(domain: str) -> dict:
    """
    Check which security headers are present and which are missing.
    Returns dict with 'present' and 'missing' lists, each item includes
    risk level and impact description.
    """
    result = {"present": [], "missing": [], "error": None}
    try:
        resp = requests.get(
            f"https://{domain}",
            timeout=8,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; security-audit/1.0)"},
            allow_redirects=True,
        )
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        for header_key, meta in SECURITY_HEADERS.items():
            if header_key in headers_lower:
                result["present"].append({
                    "header": meta["label"],
                    "value":  headers_lower[header_key][:80],
                    "risk":   meta["risk"],
                })
            else:
                result["missing"].append({
                    "header": meta["label"],
                    "risk":   meta["risk"],
                    "impact": meta["impact"],
                })

        # Sort missing by risk severity
        result["missing"].sort(key=lambda x: RISK_ORDER.get(x["risk"], 99))
        result["present"].sort(key=lambda x: RISK_ORDER.get(x["risk"], 99))

    except requests.RequestException as e:
        result["error"] = str(e)

    return result


# ── PDF REPORT ────────────────────────────────────────────────────────────────

def _find_dejavu_path() -> str:
    """Find DejaVu fonts across different Linux distros and macOS."""
    candidates = [
        "/usr/share/fonts/truetype/dejavu/",          # Debian/Ubuntu/Kali
        "/usr/share/fonts/dejavu/",                    # Fedora/RHEL
        "/usr/share/fonts/dejavu-sans-fonts/",         # CentOS
        "/usr/local/share/fonts/dejavu/",              # macOS (homebrew)
        "/System/Library/Fonts/",                      # macOS system
    ]
    for path in candidates:
        import os
        if os.path.exists(path + "DejaVuSans.ttf"):
            return path
    return None

DEJAVU_PATH = _find_dejavu_path()


class ReconReport(FPDF):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if DEJAVU_PATH:
            # Register DejaVu as Unicode-capable font family
            self.add_font("DejaVu", "",   DEJAVU_PATH + "DejaVuSans.ttf")
            self.add_font("DejaVu", "B",  DEJAVU_PATH + "DejaVuSans-Bold.ttf")
            self.add_font("DejaVu", "I",  DEJAVU_PATH + "DejaVuSans-Oblique.ttf")
            self.add_font("DejaVu", "BI", DEJAVU_PATH + "DejaVuSans-BoldOblique.ttf")
            self._font_family = "DejaVu"
        else:
            # Fallback — strip Unicode symbols from output at generation time
            self._font_family = "Helvetica"
            console.print(
                "[bold yellow][!] DejaVu fonts not found. PDF will use Helvetica "
                "(Unicode symbols replaced with ASCII equivalents).[/bold yellow]"
            )

    def header(self):
        self.set_fill_color(26, 26, 46)
        self.rect(0, 0, 210, 38, "F")
        self.set_xy(10, 8)
        self.set_font(self._font_family, "B", 16)
        self.set_text_color(255, 255, 255)
        self.cell(0, 10, "PriVi Full-Spectrum Recon Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_xy(10, 20)
        self.set_font(self._font_family, "", 10)
        self.set_text_color(180, 180, 180)
        self.cell(0, 8,
                  f"PriViSecurity  |  {TOOL} v{VERSION}",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(18)

    def footer(self):
        self.set_y(-14)
        self.set_font(self._font_family, "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(
            0, 10,
            f"Page {self.page_no()}  |  Powered by PriViSecurity  |  Developed by Prince Ubebe",
            align="C"
        )

    def section_title(self, title: str):
        self.set_fill_color(196, 30, 58)
        self.set_text_color(255, 255, 255)
        self.set_font(self._font_family, "B", 11)
        self.cell(0, 9, f"  {title}", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def kv(self, key: str, value: str, alert: bool = False):
        self.set_font(self._font_family, "B", 9)
        self.set_text_color(60, 60, 60)
        self.cell(45, 7, f"  {key}:", new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_font(self._font_family, "", 9)
        self.set_text_color(196, 30, 58) if alert else self.set_text_color(0, 0, 0)
        self.cell(0, 7, str(value)[:100], new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)


def generate_pdf_report(report_data: dict, domain: str, operator: dict = None) -> str:
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:19]
    safe_domain = domain.replace(".", "_").replace(":", "_")
    filename    = f"PriVi_Recon_{safe_domain}_{timestamp}.pdf"

    try:
        pdf = ReconReport()
        pdf.add_page()

        # Font-family shorthand for generate_pdf_report scope
        FF = pdf._font_family

        # If falling back to Helvetica, sanitise Unicode symbols to ASCII equivalents
        def _safe(text: str) -> str:
            if FF == "Helvetica":
                return (text
                    .replace("✔", "[OK]")
                    .replace("✘", "[X]")
                    .replace("⚠", "[!]")
                    .replace("🔴", "[!!]")
                    .replace("•", "-")
                    .encode("latin-1", errors="replace").decode("latin-1"))
            return text

        # 1  -  Target intelligence
        pdf.section_title("1. Target & Organization Intelligence")
        op_display = (operator or {}).get("name", "Operator")
        if operator and operator.get("org"):
            op_display += f"  |  {operator['org']}"
        we  = report_data.get("whois_ext", {})
        cdn = report_data.get("cdn_bypass", {})
        pdf.kv("Conducted by", op_display)
        pdf.kv("Domain",       domain)
        pdf.kv("IP Address",   report_data.get("ip", "Unknown"))
        pdf.kv("Geo / ISP",    report_data.get("geo", "Unknown"))
        pdf.kv("Registrar",    we.get("registrar", str(report_data.get("whois", {}).get("registrar", "Unknown"))))
        pdf.kv("Registrar URL",we.get("registrar_url", "Unknown"))
        pdf.kv("Org",          we.get("org", str(report_data.get("whois", {}).get("org", "Unknown"))))
        pdf.kv("Created",      we.get("creation_date", "Unknown"))
        pdf.kv("Expires",      we.get("expiry_date", "Unknown"),
               alert=isinstance(we.get("days_to_expiry"), int) and we["days_to_expiry"] < 30)
        pdf.kv("DNSSEC",       we.get("dnssec", "Unknown"))
        pdf.kv("Abuse Email",  we.get("abuse_email", "Unknown"))
        pdf.kv("Nameservers",  ", ".join(we.get("nameservers", [])) or "Unknown")
        pdf.kv("WAF Status",   report_data.get("waf", "Unknown"),
               alert="Detected" in report_data.get("waf", ""))
        if cdn.get("cdn_detected"):
            pdf.kv("CDN", cdn.get("cdn_name", "Unknown"), alert=True)
            if cdn.get("real_ip_candidates"):
                pdf.kv("Origin IP Candidates",
                       ", ".join(cdn["real_ip_candidates"]), alert=True)
        else:
            pdf.kv("CDN", "None detected")
        pdf.kv("Audit Date",   datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        pdf.ln(4)

        # 2  —  OSINT
        pdf.section_title("2. OSINT Intelligence")
        osint = report_data.get("osint", {})

        # crt.sh subdomains
        crt_subs = osint.get("crt_subdomains", [])
        pdf.set_font(FF, "B", 9)
        pdf.set_text_color(60, 60, 60)
        pdf.cell(0, 6, f"  crt.sh Subdomains ({len(crt_subs)} found):",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font(FF, "", 8)
        pdf.set_text_color(0, 0, 0)
        if crt_subs:
            # Two-column layout
            col_w = 90
            items = crt_subs[:60]
            for i in range(0, len(items), 2):
                left  = items[i]
                right = items[i+1] if i+1 < len(items) else ""
                pdf.cell(col_w, 5, _safe(f_safe("  • {left[:42]}")), new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.cell(0, 5, _safe(f_safe("  • {right[:42]}")) if right else "",
                         new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            pdf.set_font(FF, "I", 8)
            pdf.cell(0, 5, "  None found.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.ln(2)

        # Shodan
        sh_data = osint.get("shodan_basic", {})
        if sh_data:
            pdf.set_font(FF, "B", 9)
            pdf.set_text_color(60, 60, 60)
            pdf.cell(0, 6, "  Shodan InternetDB:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font(FF, "", 8)
            pdf.set_text_color(0, 0, 0)
            pdf.kv("  Open Ports",  ", ".join(str(p) for p in sh_data.get("ports", [])) or "None")
            pdf.kv("  Hostnames",   ", ".join(sh_data.get("hostnames", [])) or "None")
            pdf.kv("  CPEs",        ", ".join(sh_data.get("cpes", [])) or "None")
            vulns = sh_data.get("vulns", [])
            pdf.kv("  Known CVEs",  ", ".join(vulns) or "None", alert=bool(vulns))

        pdf.ln(2)

        # Wayback
        wb_urls = osint.get("wayback_urls", [])
        pdf.set_font(FF, "B", 9)
        pdf.set_text_color(60, 60, 60)
        pdf.cell(0, 6, f"  Wayback Machine Endpoints ({len(wb_urls)} interesting):",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font(FF, "", 7)
        pdf.set_text_color(0, 0, 0)
        for url in wb_urls[:25]:
            pdf.cell(0, 4, _safe(f_safe("  • {url[:95]}")), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.ln(2)

        # GitHub leaks
        leaks = osint.get("github_leaks", [])
        pdf.set_font(FF, "B", 9)
        pdf.set_text_color(196, 30, 58) if leaks else pdf.set_text_color(60, 60, 60)
        pdf.cell(0, 6, f"  GitHub Code Exposure ({len(leaks)} result(s)):",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font(FF, "", 8)
        pdf.set_text_color(0, 0, 0)
        for leak in leaks:
            pdf.cell(0, 5, _safe(f_safe("  • [{leak['repo']}] {leak['file']}")),
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font(FF, "I", 7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(0, 4, f"    {leak['url'][:95]}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font(FF, "", 8)
            pdf.set_text_color(0, 0, 0)
        if not leaks:
            pdf.set_font(FF, "I", 8)
            pdf.cell(0, 5, "  No public code exposure found.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

        # 3  —  CMS & Admin Panels
        pdf.section_title("3. CMS Detection & Admin Panel Discovery")
        ca = report_data.get("cms_admin", {})
        cms_list = ca.get("cms_detected", [])
        pdf.set_font(FF, "B", 9)
        pdf.set_text_color(60, 60, 60)
        pdf.cell(0, 6, f"  CMS Detected: {', '.join(cms_list) if cms_list else 'None'}",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)

        def _pdf_path_table(title, items, cols, alert=False):
            if not items:
                return
            # Map display column names to lowercase dict keys
            col_key_map = {c: c.lower() for c in cols}
            pdf.set_font(FF, "B", 9)
            pdf.set_text_color(196, 30, 58) if alert else pdf.set_text_color(60, 60, 60)
            pdf.cell(0, 6, f"  {title}:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            usable    = 180
            num_extra = len(cols) - 1
            extra_w   = 18
            path_w    = usable - (num_extra * extra_w)
            widths    = [path_w] + [extra_w] * num_extra
            pdf.set_font(FF, "B", 8)
            pdf.set_fill_color(26, 26, 46)
            pdf.set_text_color(255, 255, 255)
            for col, w in zip(cols, widths):
                pdf.cell(w, 6, f"  {col}", fill=True,
                         new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.cell(0, 6, "", fill=False, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font(FF, "", 8)
            pdf.set_text_color(0, 0, 0)
            alt = False
            for item in items[:30]:
                pdf.set_fill_color(245, 245, 250) if alt else pdf.set_fill_color(255, 255, 255)
                alt = not alt
                for col, w in zip(cols, widths):
                    key       = col_key_map[col]
                    val       = str(item.get(key, ""))
                    max_chars = max(1, int(w / 2.1))
                    pdf.cell(w, 5, f"  {val[:max_chars]}", fill=True,
                             new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.cell(0, 5, "", fill=False, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(2)

        _pdf_path_table("Sensitive Files Exposed",
                        ca.get("sensitive_files", []),
                        ["Path", "Status", "Size"], alert=True)
        _pdf_path_table("Admin Panels Found",
                        ca.get("admin_panels", []),
                        ["Path", "Status", "Size"], alert=True)
        _pdf_path_table("Interesting Paths",
                        ca.get("interesting_paths", []),
                        ["Path", "Status", "Size"])
        pdf.ln(4)

        # 4  —  API Fuzzing
        pdf.section_title("4. API Fuzzing & Endpoint Discovery")
        af = report_data.get("api_fuzz", {})

        gql = af.get("graphql_introspection")
        pdf.set_font(FF, "B", 9)
        if gql:
            pdf.set_text_color(196, 30, 58)
            pdf.cell(0, 6, _safe(f_safe("  ⚠ GraphQL Introspection ENABLED at {gql['path']}")),
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            pdf.set_text_color(30, 130, 30)
            pdf.cell(0, 6, _safe("  ✔ GraphQL Introspection: Not detected"),
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(2)

        _pdf_path_table("Swagger / OpenAPI Schema Exposed",
                        af.get("swagger_exposed", []),
                        ["Path", "Status"], alert=True)
        _pdf_path_table("Spring Actuator Endpoints Exposed",
                        af.get("actuator_exposed", []),
                        ["Path", "Status"], alert=True)
        _pdf_path_table("Open Unauthenticated Endpoints",
                        af.get("open_endpoints", []),
                        ["Path", "Status"])
        _pdf_path_table("Possible IDOR Hints",
                        af.get("idor_hints", []),
                        ["Path", "Status"], alert=True)

        if af.get("error_disclosure"):
            pdf.set_font(FF, "B", 9)
            pdf.set_text_color(196, 30, 58)
            pdf.cell(0, 6, "  Error / Stack Trace Disclosure:",
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font(FF, "", 7)
            pdf.set_text_color(0, 0, 0)
            for e in af["error_disclosure"][:5]:
                pdf.cell(0, 4, _safe(f_safe("  • {e['path']} (HTTP {e['status']})")),
                         new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_font(FF, "I", 7)
                pdf.set_text_color(80, 80, 80)
                pdf.cell(0, 4, f"    {e.get('snippet','')[:90]}",
                         new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_font(FF, "", 7)
                pdf.set_text_color(0, 0, 0)
        pdf.ln(4)

        # 5  —  Auth Testing
        pdf.section_title("5. Authentication Testing")
        at = report_data.get("auth_test", {})

        hits = at.get("default_creds_hits", [])
        if hits:
            pdf.set_font(FF, "B", 10)
            pdf.set_text_color(196, 30, 58)
            pdf.cell(0, 7, _safe("  🔴 DEFAULT CREDENTIALS ACCEPTED:"),
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font(FF, "B", 8)
            pdf.set_fill_color(196, 30, 58)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(60, 6, "  Path",     fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.cell(25, 6, "Method",     fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.cell(30, 6, "Username",   fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.cell(30, 6, "Password",   fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.cell(0,  6, "Status",     fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font(FF, "", 8)
            pdf.set_text_color(0, 0, 0)
            for h in hits:
                pdf.cell(60, 5, f"  {h['path'][:28]}",   fill=False, new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.cell(25, 5, h["method"],              fill=False, new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.cell(30, 5, h["username"],            fill=False, new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.cell(30, 5, h["password"],            fill=False, new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.cell(0,  5, str(h["status"]),         fill=False, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            pdf.set_font(FF, "", 9)
            pdf.set_text_color(30, 130, 30)
            pdf.cell(0, 6, _safe("  ✔ No default credentials accepted."),
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(2)

        jwt_issues = at.get("jwt_issues", [])
        pdf.set_font(FF, "B", 9)
        if jwt_issues:
            pdf.set_text_color(196, 30, 58)
            for j in jwt_issues:
                pdf.cell(0, 6, _safe(f_safe("  ⚠ JWT Issue at {j['path']}: {j['issue']}")),
                         new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            pdf.set_text_color(30, 130, 30)
            pdf.cell(0, 6, _safe("  ✔ No JWT vulnerabilities detected."),
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(2)

        bypass_hints = at.get("auth_bypass_hints", [])
        if bypass_hints:
            pdf.set_font(FF, "B", 9)
            pdf.set_text_color(196, 30, 58)
            pdf.cell(0, 6, _safe(f_safe("  ⚠ {len(bypass_hints)} Auth Bypass Hint(s) via Header Manipulation:")),
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font(FF, "", 8)
            pdf.set_text_color(0, 0, 0)
            for b in bypass_hints[:10]:
                pdf.cell(0, 5, _safe(f_safe("  • {b['path']}  |  Header: {b['header']}  |  Status: {b['status']}")),
                         new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        session_issues = at.get("session_issues", [])
        if session_issues:
            pdf.ln(2)
            pdf.set_font(FF, "B", 9)
            pdf.set_text_color(200, 120, 0)
            pdf.cell(0, 6, "  Session Cookie Issues:",
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font(FF, "", 8)
            pdf.set_text_color(0, 0, 0)
            for s in session_issues:
                pdf.cell(0, 5, _safe(f_safe("  • {s['path']}: {s['issue']}")),
                         new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

        # 6  —  Subdomains
        pdf.section_title("6. Subdomain Enumeration")
        subdomains = report_data.get("subdomains", [])
        if subdomains:
            pdf.set_font(FF, "B", 8)
            pdf.set_fill_color(26, 26, 46)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(110, 7, "  Subdomain", fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.cell(0,   7, "IP Address",  fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font(FF, "", 8)
            pdf.set_text_color(0, 0, 0)
            alt = False
            for sd in subdomains:
                pdf.set_fill_color(245, 245, 250) if alt else pdf.set_fill_color(255, 255, 255)
                alt = not alt
                pdf.cell(110, 6, f"  {sd['subdomain']}", fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.cell(0,   6, sd["ip"],               fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            pdf.set_font(FF, "I", 9)
            pdf.cell(0, 6, "  No subdomains discovered.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

        # 7  -  DNS
        pdf.section_title("7. DNS Infrastructure")
        dns_records = report_data.get("dns_records", [])
        pdf.set_font(FF, "", 9)
        if dns_records:
            for rec in dns_records:
                pdf.cell(0, 6, f"  * {rec}",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            pdf.set_font(FF, "I", 9)
            pdf.cell(0, 6, "  No DNS records retrieved.",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

        # 8  -  Tech Stack
        pdf.section_title("8. Technology Stack Fingerprint")
        tech_stack = report_data.get("tech_stack", [])
        pdf.set_font(FF, "", 9)
        if tech_stack:
            for tech in tech_stack:
                pdf.cell(0, 6, f"  * {tech}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            pdf.set_font(FF, "I", 9)
            pdf.cell(0, 6, "  No technologies identified.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

        # 9  -  Email intelligence
        pdf.section_title("9. Email Intelligence (Scraped from Homepage & Subpages)")
        emails = report_data.get("emails", [])
        if emails:
            pdf.set_font(FF, "", 9)
            for email in emails:
                pdf.cell(0, 6, f"  * {email}",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            pdf.set_font(FF, "I", 9)
            pdf.cell(0, 6, "  No email addresses found on target homepage.",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

        # 10  —  JavaScript Analysis
        pdf.section_title("10. JavaScript File Analysis")
        js = report_data.get("js_analysis", {})
        js_files   = js.get("js_files_found", [])
        js_secrets = js.get("secrets", [])
        js_paths   = js.get("internal_paths", [])
        pdf.set_font(FF, "B", 9)
        pdf.set_text_color(60, 60, 60)
        pdf.cell(0, 6, f"  JS Files Scanned: {len(js_files)}",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(1)
        if js_secrets:
            pdf.set_font(FF, "B", 9)
            pdf.set_text_color(196, 30, 58)
            pdf.cell(0, 6, _safe(f_safe("  ⚠ {len(js_secrets)} Secret(s) / Credential(s) Found:")),
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font(FF, "B", 8)
            pdf.set_fill_color(26, 26, 46)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(50, 6, "  File",  fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.cell(45, 6, "Type",    fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.cell(0,  6, "Match",   fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font(FF, "", 7)
            pdf.set_text_color(0, 0, 0)
            alt = False
            for s in js_secrets:
                pdf.set_fill_color(255, 240, 240) if alt else pdf.set_fill_color(255, 255, 255)
                alt = not alt
                pdf.cell(50, 5, f"  {s['file'][:24]}",    fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.cell(45, 5, s["type"][:22],            fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.cell(0,  5, s["match"][:60],           fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            pdf.set_font(FF, "", 9)
            pdf.set_text_color(30, 130, 30)
            pdf.cell(0, 6, _safe("  ✔ No secrets or credentials found in JS files."),
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(2)
        if js_paths:
            pdf.set_font(FF, "B", 9)
            pdf.set_text_color(60, 60, 60)
            pdf.cell(0, 6, f"  Internal Paths Discovered ({len(js_paths)}):",
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font(FF, "", 8)
            pdf.set_text_color(0, 0, 0)
            for p in js_paths[:30]:
                pdf.cell(0, 4, _safe(f_safe("  • [{p['file'][:20]}] {p['path'][:70]}")),
                         new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

        # 11  —  CVE Correlation
        pdf.section_title("11. CVE Correlation (NIST NVD)")
        cves = report_data.get("cve_findings", [])
        if cves:
            pdf.set_font(FF, "B", 9)
            pdf.set_text_color(196, 30, 58)
            pdf.cell(0, 6, _safe(f_safe("  ⚠ {len(cves)} CVE(s) matched to detected technologies:")),
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(1)
            pdf.set_font(FF, "B", 8)
            pdf.set_fill_color(26, 26, 46)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(28, 6, "  CVE ID",   fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.cell(12, 6, "Score",      fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.cell(18, 6, "Severity",   fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.cell(30, 6, "Term",       fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.cell(0,  6, "Summary",    fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font(FF, "", 7)
            pdf.set_text_color(0, 0, 0)
            alt = False
            for c in cves:
                pdf.set_fill_color(255, 242, 242) if alt else pdf.set_fill_color(255, 255, 255)
                alt = not alt
                sev_color = (
                    (196, 30, 58) if c["severity"] == "CRITICAL" else
                    (200, 80, 0)  if c["severity"] == "HIGH"     else
                    (180, 140, 0) if c["severity"] == "MEDIUM"   else
                    (80, 80, 80)
                )
                pdf.cell(28, 5, f"  {c['cve_id']}",     fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.cell(12, 5, c["score"],              fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.set_text_color(*sev_color)
                pdf.cell(18, 5, c["severity"],           fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.set_text_color(0, 0, 0)
                pdf.cell(30, 5, c["term"][:16],          fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.cell(0,  5, c["desc"][:55],          fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(2)
            pdf.set_font(FF, "I", 8)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(0, 5, "  Full CVE details: https://nvd.nist.gov/vuln/detail/<CVE-ID>",
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            pdf.set_font(FF, "", 9)
            pdf.set_text_color(30, 130, 30)
            pdf.cell(0, 6, _safe("  ✔ No HIGH/CRITICAL CVEs matched to detected tech stack."),
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(4)

        # 12  -  Port scan
        pdf.section_title("12. Port Scan Results")
        port_results = report_data.get("ports", [])
        if port_results:
            pdf.set_font(FF, "B", 8)
            pdf.set_fill_color(26, 26, 46)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(14, 7, "  Port",   fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.cell(13, 7, "Proto",    fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.cell(16, 7, "State",    fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.cell(22, 7, "Service",  fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.cell(30, 7, "Version",  fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.cell(0,  7, "Risk",     fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font(FF, "", 7)
            pdf.set_text_color(0, 0, 0)
            alt = False
            for p in port_results:
                pdf.set_fill_color(245, 245, 250) if alt else pdf.set_fill_color(255, 255, 255)
                alt = not alt
                state_color = (30, 160, 30) if p["state"] == "open" else (160, 30, 30)
                risk = p.get("risk", "")
                risk_color = (
                    (196, 30, 58)  if "CRITICAL" in risk else
                    (200, 80, 0)   if "HIGH"     in risk else
                    (180, 140, 0)  if "MEDIUM"   in risk else
                    (80, 80, 80)
                )
                pdf.cell(14, 5, f"  {p['port']}",     fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.cell(13, 5, p["proto"],            fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.set_text_color(*state_color)
                pdf.cell(16, 5, p["state"],            fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.set_text_color(0, 0, 0)
                pdf.cell(22, 5, p["service"][:12],     fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.cell(30, 5, p["version"][:18],     fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.set_text_color(*risk_color)
                pdf.cell(0,  5, risk[:45],             fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_text_color(0, 0, 0)
        else:
            pdf.set_font(FF, "I", 9)
            pdf.cell(0, 6, "  No port scan data available.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

        # 13  -  SSL Certificate
        pdf.section_title("13. SSL/TLS Certificate")
        cert = report_data.get("ssl_cert", {})
        if cert.get("valid"):
            days = cert.get("days_left", "?")
            pdf.set_font(FF, "", 9)
            pdf.kv("Issuer",    cert.get("issuer", "?"))
            pdf.kv("Subject",   cert.get("subject", "?"))
            pdf.kv("Expires",   cert.get("expiry", "?"))
            warn = " ⚠ EXPIRING SOON" if isinstance(days, int) and days <= 30 else ""
            pdf.kv("Days Left", f"{days}{warn}", alert=bool(warn))
            sans = cert.get("sans", [])
            if sans:
                pdf.set_font(FF, "B", 9)
                pdf.set_text_color(60, 60, 60)
                pdf.cell(0, 7, "  Subject Alternative Names (SANs):",
                         new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_font(FF, "", 8)
                pdf.set_text_color(0, 0, 0)
                for san in sans:
                    pdf.cell(0, 5, _safe(f_safe("    • {san}")), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            pdf.set_font(FF, "I", 9)
            pdf.cell(0, 6, f"  {cert.get('error', 'Certificate inspection failed.')}",
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

        # 14  -  Security Headers
        pdf.section_title("14. HTTP Security Headers")
        sh = report_data.get("sec_headers", {})
        missing_hdrs = sh.get("missing", [])
        present_hdrs = sh.get("present", [])
        if missing_hdrs or present_hdrs:
            # Missing first (most important)
            if missing_hdrs:
                pdf.set_font(FF, "B", 8)
                pdf.set_text_color(196, 30, 58)
                pdf.cell(0, 6, "  Missing Headers:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_font(FF, "", 8)
                for h in missing_hdrs:
                    risk_color = (
                        (196, 30, 58) if h["risk"] == "HIGH"   else
                        (200, 120, 0) if h["risk"] == "MEDIUM" else
                        (80, 80, 80)
                    )
                    pdf.set_text_color(*risk_color)
                    pdf.cell(0, 5, _safe(f_safe("    ✘ [{h['risk']}] {h['header']}")),
                             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.set_font(FF, "I", 7)
                    pdf.set_text_color(80, 80, 80)
                    pdf.cell(0, 4, f"      → {h['impact'][:90]}",
                             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.set_font(FF, "", 8)
            if present_hdrs:
                pdf.ln(2)
                pdf.set_font(FF, "B", 8)
                pdf.set_text_color(30, 130, 30)
                pdf.cell(0, 6, "  Present Headers:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_font(FF, "", 8)
                for h in present_hdrs:
                    pdf.set_text_color(30, 130, 30)
                    pdf.cell(0, 5, _safe(f_safe("    ✔ {h['header']}")),
                             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_text_color(0, 0, 0)
        else:
            pdf.set_font(FF, "I", 9)
            pdf.cell(0, 6, f"  {sh.get('error', 'Header check failed.')}",
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

        # 15  -  Nmap Vulnerabilities
        pdf.section_title("15. Nmap Vulnerability Findings")
        vulns = report_data.get("vulns", [])
        if vulns:
            for v in vulns:
                pdf.set_text_color(196, 30, 58)
                pdf.set_font(FF, "B", 9)
                pdf.cell(0, 6,
                         f"  [FINDING] Port {v['port']}  -  {v['script_id']}",
                         new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_font(FF, "", 8)
                pdf.set_text_color(60, 60, 60)
                pdf.multi_cell(0, 5, f"    {v['output'][:250]}")
                pdf.ln(1)
            pdf.set_text_color(0, 0, 0)
        else:
            pdf.set_font(FF, "", 9)
            pdf.cell(0, 6, "  No script-based vulnerabilities detected.",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

        # 16  -  Legal
        pdf.add_page()
        pdf.section_title("16. Legal & Scope Declaration")
        pdf.set_font(FF, "", 9)
        pdf.multi_cell(
            0, 6,
            f"This report was generated by {TOOL} v{VERSION}, developed by "
            f"{AUTHOR} / {BRAND}. The tool was used under the explicit "
            "authorization acknowledgment confirmed by the operator at session start.\n\n"
            "This report is confidential and intended solely for the authorized "
            "recipient. Redistribution without consent of the system owner is "
            "prohibited.\n\n"
            f"{BRAND} accepts no liability for actions taken based on the findings "
            "in this report without appropriate change-control, testing, and "
            "professional review."
        )

        pdf.output(filename)
        return filename

    except Exception as e:
        console.print(f"[bold red][!] PDF generation failed: {e}[/bold red]")
        return None


# ── RESULT DISPLAY ────────────────────────────────────────────────────────────

def display_results(report_data: dict, domain: str):
    # Target intel
    intel = Table(
        title="[bold cyan]Target Intelligence[/bold cyan]",
        border_style="blue", show_lines=True
    )
    intel.add_column("Field", style="bold white", width=22)
    intel.add_column("Value", style="white")
    waf = report_data.get("waf", "")
    we  = report_data.get("whois_ext", {})
    cdn = report_data.get("cdn_bypass", {})
    intel.add_row("Domain",       domain)
    intel.add_row("IP",           report_data.get("ip", "?"))
    intel.add_row("Geo / ISP",    report_data.get("geo", "?"))
    intel.add_row("Registrar",    we.get("registrar", str(report_data.get("whois", {}).get("registrar", "?"))))
    intel.add_row("Org",          we.get("org", str(report_data.get("whois", {}).get("org", "?"))))
    intel.add_row("Created",      we.get("creation_date", "?"))
    intel.add_row("Expires",      we.get("expiry_date", "?"))
    intel.add_row("DNSSEC",       we.get("dnssec", "?"))
    intel.add_row("Abuse Email",  we.get("abuse_email", "?"))
    intel.add_row("Nameservers",  "\n".join(we.get("nameservers", [])) or "?")
    intel.add_row("WAF",
        f"[bold red]{waf}[/bold red]" if "Detected" in waf else f"[green]{waf}[/green]")
    intel.add_row("CDN",
        f"[bold yellow]{cdn.get('cdn_name','?')}[/bold yellow]"
        if cdn.get("cdn_detected") else "[green]None detected[/green]")
    if cdn.get("real_ip_candidates"):
        intel.add_row("Origin IP Candidates",
            "\n".join(cdn["real_ip_candidates"]))
    console.print(intel)

    # Subdomains
    if report_data.get("subdomains"):
        sd_t = Table(
            title="[bold cyan]Subdomains Discovered[/bold cyan]",
            border_style="blue", show_lines=True
        )
        sd_t.add_column("Subdomain",  style="yellow")
        sd_t.add_column("IP Address", style="cyan")
        for sd in report_data["subdomains"]:
            sd_t.add_row(sd["subdomain"], sd["ip"])
        console.print(sd_t)
    else:
        console.print("[dim]  No subdomains discovered.[/dim]")

    # Tech Stack
    if report_data.get("tech_stack"):
        ts_t = Table(
            title="[bold cyan]Technology Stack[/bold cyan]",
            border_style="blue", show_lines=True
        )
        ts_t.add_column("Detected Technology", style="green")
        for tech in report_data["tech_stack"]:
            ts_t.add_row(tech)
        console.print(ts_t)

    # DNS
    if report_data.get("dns_records"):
        dns_t = Table(
            title="[bold cyan]DNS Records[/bold cyan]",
            border_style="blue", show_lines=True
        )
        dns_t.add_column("Record", style="white")
        for rec in report_data["dns_records"]:
            dns_t.add_row(rec)
        console.print(dns_t)

    # Emails
    if report_data.get("emails"):
        em_t = Table(
            title="[bold cyan]Email Intelligence[/bold cyan]",
            border_style="blue", show_lines=True
        )
        em_t.add_column("Email Address", style="yellow")
        for em in report_data["emails"]:
            em_t.add_row(em)
        console.print(em_t)
    else:
        console.print("[dim]  No email addresses found on target homepage.[/dim]")

    # Ports
    if report_data.get("ports"):
        pt = Table(
            title="[bold cyan]Port Scan Results[/bold cyan]",
            border_style="blue", show_lines=True
        )
        pt.add_column("Port",    style="cyan",      width=7)
        pt.add_column("Proto",   style="white",     width=7)
        pt.add_column("State",   width=10)
        pt.add_column("Service", style="white",     width=14)
        pt.add_column("Version", style="dim white", width=20)
        pt.add_column("Risk",    width=40)
        for p in report_data["ports"]:
            state_str = (
                f"[bold green]{p['state']}[/bold green]"
                if p["state"] == "open"
                else f"[dim]{p['state']}[/dim]"
            )
            risk = p.get("risk", "")
            risk_color = (
                "bold red"    if "CRITICAL" in risk else
                "red"         if "HIGH"     in risk else
                "yellow"      if "MEDIUM"   in risk else
                "dim"
            )
            pt.add_row(
                str(p["port"]), p["proto"], state_str,
                p["service"], p["version"],
                f"[{risk_color}]{risk}[/{risk_color}]"
            )
        console.print(pt)

    # SSL Certificate
    cert = report_data.get("ssl_cert", {})
    if cert:
        ssl_t = Table(
            title="[bold cyan]SSL/TLS Certificate[/bold cyan]",
            border_style="blue", show_lines=True
        )
        ssl_t.add_column("Field",  style="bold white", width=18)
        ssl_t.add_column("Value",  style="white")
        if cert.get("valid"):
            days      = cert.get("days_left", "?")
            day_color = "green" if isinstance(days, int) and days > 30 else "bold red"
            ssl_t.add_row("Issuer",       cert.get("issuer", "?"))
            ssl_t.add_row("Subject",      cert.get("subject", "?"))
            ssl_t.add_row("Expires",      cert.get("expiry", "?"))
            ssl_t.add_row("Days Left",    f"[{day_color}]{days}[/{day_color}]")
            ssl_t.add_row("SANs",         "\n".join(cert.get("sans", [])) or "None")
        else:
            ssl_t.add_row("Error", cert.get("error", "Unknown error"))
        console.print(ssl_t)

    # Security Headers
    sh = report_data.get("sec_headers", {})
    if sh:
        sh_t = Table(
            title="[bold cyan]HTTP Security Headers[/bold cyan]",
            border_style="blue", show_lines=True
        )
        sh_t.add_column("Status",  width=10)
        sh_t.add_column("Risk",    width=10)
        sh_t.add_column("Header",  style="white", width=35)
        sh_t.add_column("Detail",  style="dim white")
        for h in sh.get("present", []):
            sh_t.add_row("[green]✔ PRESENT[/green]", f"[dim]{h['risk']}[/dim]",
                         h["header"], h.get("value", ""))
        for h in sh.get("missing", []):
            risk_color = "bold red" if h["risk"] == "HIGH" else (
                         "yellow"   if h["risk"] == "MEDIUM" else "dim")
            sh_t.add_row(
                "[bold red]✘ MISSING[/bold red]",
                f"[{risk_color}]{h['risk']}[/{risk_color}]",
                h["header"], h.get("impact", "")
            )
        console.print(sh_t)

    # OSINT
    osint = report_data.get("osint", {})
    if osint:
        # crt.sh subdomains
        if osint.get("crt_subdomains"):
            ct = Table(title="[bold cyan]OSINT — crt.sh Subdomains[/bold cyan]",
                       border_style="blue", show_lines=True)
            ct.add_column("Subdomain", style="yellow")
            for s in osint["crt_subdomains"][:40]:
                ct.add_row(s)
            console.print(ct)

        # Shodan
        sh_data = osint.get("shodan_basic", {})
        if sh_data:
            st = Table(title="[bold cyan]OSINT — Shodan InternetDB[/bold cyan]",
                       border_style="blue", show_lines=True)
            st.add_column("Field",  style="bold white", width=16)
            st.add_column("Value",  style="white")
            st.add_row("IP",        sh_data.get("ip", "?"))
            st.add_row("Open Ports", ", ".join(str(p) for p in sh_data.get("ports", [])) or "None")
            st.add_row("Hostnames", "\n".join(sh_data.get("hostnames", [])) or "None")
            st.add_row("CPEs",      "\n".join(sh_data.get("cpes", [])) or "None")
            st.add_row("CVEs",
                "\n".join(f"[bold red]{v}[/bold red]" for v in sh_data.get("vulns", [])) or "[green]None[/green]")
            st.add_row("Tags",      ", ".join(sh_data.get("tags", [])) or "None")
            console.print(st)

        # Wayback URLs
        if osint.get("wayback_urls"):
            wt = Table(title="[bold cyan]OSINT — Wayback Machine Endpoints[/bold cyan]",
                       border_style="blue", show_lines=True)
            wt.add_column("URL", style="yellow")
            for u in osint["wayback_urls"][:30]:
                wt.add_row(u)
            console.print(wt)

        # GitHub leaks
        if osint.get("github_leaks"):
            gt = Table(title="[bold red]OSINT — GitHub Code Exposure[/bold red]",
                       border_style="red", show_lines=True)
            gt.add_column("Repo",  style="bold yellow", width=35)
            gt.add_column("File",  style="white",       width=25)
            gt.add_column("URL",   style="dim cyan")
            for leak in osint["github_leaks"]:
                gt.add_row(leak["repo"], leak["file"], leak["url"])
            console.print(gt)

        # crt.sh emails
        if osint.get("crt_emails"):
            et = Table(title="[bold cyan]OSINT — Emails from crt.sh[/bold cyan]",
                       border_style="blue", show_lines=True)
            et.add_column("Email", style="yellow")
            for em in osint["crt_emails"]:
                et.add_row(em)
            console.print(et)

    # CMS & Admin Panels
    ca = report_data.get("cms_admin", {})
    if ca:
        cms_list = ca.get("cms_detected", [])
        if cms_list:
            console.print(f"\n  [bold cyan]CMS Detected:[/bold cyan] {', '.join(cms_list)}")

        if ca.get("sensitive_files"):
            sft = Table(title="[bold red]⚠ Sensitive Files Exposed[/bold red]",
                        border_style="red", show_lines=True)
            sft.add_column("Path",     style="bold red",    width=35)
            sft.add_column("Status",   style="bold yellow", width=8)
            sft.add_column("Size",     width=8)
            for f in ca["sensitive_files"]:
                sft.add_row(f["path"], str(f["status"]), str(f["size"]))
            console.print(sft)

        if ca.get("admin_panels"):
            apt = Table(title="[bold yellow]Admin Panels Found[/bold yellow]",
                        border_style="yellow", show_lines=True)
            apt.add_column("Path",    style="yellow", width=35)
            apt.add_column("Status",  width=8)
            apt.add_column("Redirect", style="dim")
            for p in ca["admin_panels"]:
                apt.add_row(p["path"], str(p["status"]), p.get("redirect",""))
            console.print(apt)

        if ca.get("interesting_paths"):
            ipt = Table(title="[bold cyan]Interesting Paths[/bold cyan]",
                        border_style="blue", show_lines=True)
            ipt.add_column("Path",   style="cyan", width=35)
            ipt.add_column("Status", width=8)
            ipt.add_column("Size",   width=10)
            for p in ca["interesting_paths"][:25]:
                ipt.add_row(p["path"], str(p["status"]), str(p["size"]))
            console.print(ipt)

    # API Fuzzing
    af = report_data.get("api_fuzz", {})
    if af:
        if af.get("graphql_introspection"):
            gql = af["graphql_introspection"]
            console.print(
                f"\n  [bold red]⚠ GraphQL Introspection ENABLED at {gql['path']} "
                f"(status {gql['status']})[/bold red]")

        if af.get("swagger_exposed"):
            swt = Table(title="[bold red]⚠ API Schema / Swagger Exposed[/bold red]",
                        border_style="red", show_lines=True)
            swt.add_column("Path",         style="bold red",  width=35)
            swt.add_column("Status",       width=8)
            swt.add_column("Content-Type", style="dim")
            for e in af["swagger_exposed"]:
                swt.add_row(e["path"], str(e["status"]), e.get("content_type",""))
            console.print(swt)

        if af.get("actuator_exposed"):
            act = Table(title="[bold red]⚠ Spring Actuator Endpoints Exposed[/bold red]",
                        border_style="red", show_lines=True)
            act.add_column("Path",    style="bold red", width=35)
            act.add_column("Status",  width=8)
            act.add_column("Preview", style="dim white")
            for e in af["actuator_exposed"]:
                act.add_row(e["path"], str(e["status"]), e.get("preview","")[:80])
            console.print(act)

        if af.get("open_endpoints"):
            oet = Table(title="[bold yellow]Open Unauthenticated API Endpoints[/bold yellow]",
                        border_style="yellow", show_lines=True)
            oet.add_column("Path",         style="yellow", width=35)
            oet.add_column("Status",       width=8)
            oet.add_column("Content-Type", style="dim",    width=20)
            oet.add_column("Preview",      style="dim white")
            for e in af["open_endpoints"][:20]:
                oet.add_row(e["path"], str(e["status"]),
                            e.get("content_type",""), e.get("preview","")[:60])
            console.print(oet)

        if af.get("idor_hints"):
            idt = Table(title="[bold red]⚠ Possible IDOR — User Enumeration[/bold red]",
                        border_style="red", show_lines=True)
            idt.add_column("Path",    style="bold red", width=35)
            idt.add_column("Status",  width=8)
            idt.add_column("Preview", style="dim white")
            for e in af["idor_hints"]:
                idt.add_row(e["path"], str(e["status"]), e.get("preview","")[:80])
            console.print(idt)

        if af.get("error_disclosure"):
            edt = Table(title="[bold red]⚠ Verbose Error / Stack Trace Disclosure[/bold red]",
                        border_style="red", show_lines=True)
            edt.add_column("Path",    style="bold red", width=35)
            edt.add_column("Status",  width=8)
            edt.add_column("Snippet", style="dim white")
            for e in af["error_disclosure"]:
                edt.add_row(e["path"], str(e["status"]), e.get("snippet","")[:80])
            console.print(edt)

    # Auth Testing
    at = report_data.get("auth_test", {})
    if at:
        if at.get("default_creds_hits"):
            dct = Table(title="[bold red]🔴 DEFAULT CREDENTIALS ACCEPTED[/bold red]",
                        border_style="red", show_lines=True)
            dct.add_column("Path",     style="bold red", width=25)
            dct.add_column("Method",   width=12)
            dct.add_column("Username", style="bold yellow", width=15)
            dct.add_column("Password", style="bold yellow", width=15)
            dct.add_column("Status",   width=8)
            for h in at["default_creds_hits"]:
                dct.add_row(h["path"], h["method"],
                            h["username"], h["password"], str(h["status"]))
            console.print(dct)

        if at.get("jwt_issues"):
            jwt_t = Table(title="[bold red]⚠ JWT Vulnerability Detected[/bold red]",
                          border_style="red", show_lines=True)
            jwt_t.add_column("Path",  style="bold red", width=30)
            jwt_t.add_column("Issue", style="white")
            for j in at["jwt_issues"]:
                jwt_t.add_row(j["path"], j["issue"])
            console.print(jwt_t)

        if at.get("basic_auth_exposed"):
            bat = Table(title="[bold yellow]HTTP Basic Auth Exposed[/bold yellow]",
                        border_style="yellow", show_lines=True)
            bat.add_column("Path",  style="yellow", width=30)
            bat.add_column("Realm", style="white")
            for b in at["basic_auth_exposed"]:
                bat.add_row(b["path"], b["realm"])
            console.print(bat)

        if at.get("auth_bypass_hints"):
            abt = Table(title="[bold red]⚠ Possible Auth Bypass via Header Manipulation[/bold red]",
                        border_style="red", show_lines=True)
            abt.add_column("Path",   style="bold red", width=25)
            abt.add_column("Header", style="yellow",   width=40)
            abt.add_column("Status", width=8)
            abt.add_column("Size",   width=8)
            for b in at["auth_bypass_hints"]:
                abt.add_row(b["path"], str(b["header"]),
                            str(b["status"]), str(b["size"]))
            console.print(abt)

        if at.get("session_issues"):
            sit = Table(title="[bold yellow]Session Security Issues[/bold yellow]",
                        border_style="yellow", show_lines=True)
            sit.add_column("Path",   style="yellow", width=25)
            sit.add_column("Issue",  style="white",  width=40)
            sit.add_column("Cookie", style="dim")
            for s in at["session_issues"]:
                sit.add_row(s["path"], s["issue"], s.get("cookie","")[:60])
            console.print(sit)

    # JS Analysis
    js = report_data.get("js_analysis", {})
    if js.get("secrets"):
        sec_t = Table(
            title="[bold red]🔴 Secrets / Keys Found in JavaScript Files[/bold red]",
            border_style="red", show_lines=True)
        sec_t.add_column("File",   style="bold yellow", width=30)
        sec_t.add_column("Type",   style="bold red",    width=22)
        sec_t.add_column("Match",  style="white")
        for s in js["secrets"]:
            sec_t.add_row(s["file"], s["type"], s["match"][:80])
        console.print(sec_t)

    if js.get("internal_paths"):
        ip_t = Table(
            title="[bold cyan]Internal Paths from JS Files[/bold cyan]",
            border_style="blue", show_lines=True)
        ip_t.add_column("File",  style="dim",    width=30)
        ip_t.add_column("Path",  style="yellow")
        for p in js["internal_paths"][:30]:
            ip_t.add_row(p["file"], p["path"])
        console.print(ip_t)

    # CVE Findings
    cves = report_data.get("cve_findings", [])
    if cves:
        cve_t = Table(
            title="[bold red]⚠ CVE Matches (via NIST NVD)[/bold red]",
            border_style="red", show_lines=True)
        cve_t.add_column("CVE ID",    style="bold red",    width=16)
        cve_t.add_column("Score",     style="bold yellow", width=7)
        cve_t.add_column("Severity",  width=10)
        cve_t.add_column("Term",      style="dim",         width=20)
        cve_t.add_column("Summary",   style="white")
        for c in cves:
            sev_color = (
                "bold red"    if c["severity"] == "CRITICAL" else
                "red"         if c["severity"] == "HIGH"     else
                "yellow"      if c["severity"] == "MEDIUM"   else "dim"
            )
            cve_t.add_row(
                c["cve_id"], c["score"],
                f"[{sev_color}]{c['severity']}[/{sev_color}]",
                c["term"], c["desc"][:80]
            )
        console.print(cve_t)

    # Vulns
    if report_data.get("vulns"):
        vt = Table(
            title="[bold red]Vulnerability Findings[/bold red]",
            border_style="red", show_lines=True
        )
        vt.add_column("Port",    style="bold red",    width=8)
        vt.add_column("Script",  style="bold yellow", width=25)
        vt.add_column("Summary", style="white")
        for v in report_data["vulns"]:
            vt.add_row(str(v["port"]), v["script_id"], v["output"][:120])
        console.print(vt)


# ── MAIN ──────────────────────────────────────────────────────────────────────


def get_operator_info() -> dict:
    """
    Prompt for operator name and organization.
    Appears in the PDF report as "Conducted by".
    PriViSecurity brand and Prince Ubebe developer credit
    remain fixed in the report header — always.
    """
    console.print(Panel(
        "\n  [bold white]Operator Details[/bold white]\n\n"
        "  These will appear in the PDF report footer.\n"
        "  [dim]PriViSecurity branding stays fixed in the header.[/dim]\n",
        border_style="blue",
        title="[bold cyan]Report Configuration[/bold cyan]"
    ))
    op_name = console.input(
        "  [cyan]Your name[/cyan]          (analyst conducting this audit): "
    ).strip()
    op_org = console.input(
        "  [cyan]Organization[/cyan]       (optional, press Enter to skip):  "
    ).strip()
    if not op_name:
        op_name = "Operator"
    return {"name": op_name, "org": op_org}

def main():
    authorization_gate()
    print_header()
    operator = get_operator_info()

    # Target input
    if len(sys.argv) == 2:
        raw_target = sys.argv[1]
    else:
        raw_target = Prompt.ask(
            "[cyan]Target domain[/cyan]  (e.g. example.com)"
        ).strip()

    if "://" not in raw_target:
        raw_target = "http://" + raw_target
    domain = urlparse(raw_target).netloc or raw_target
    domain = domain.split(":")[0].strip().lower()
    if domain.startswith("www."):
        domain = domain[4:]
    if not domain:
        console.print("[bold red][!] Invalid domain. Exiting.[/bold red]")
        sys.exit(1)

    console.print(f"\n[bold cyan][*] Target locked: {domain}[/bold cyan]\n")

    report_data = {
        "ip":           None,
        "geo":          "Unknown",
        "whois":        {},
        "whois_ext":    {},
        "emails":       [],
        "ports":        [],
        "vulns":        [],
        "waf":          "None Detected",
        "dns_records":  [],
        "tech_stack":   [],
        "subdomains":   [],
        "ssl_cert":     {},
        "sec_headers":  {},
        "osint":        {},
        "cdn_bypass":   {},
        "cms_admin":    {},
        "api_fuzz":     {},
        "auth_test":    {},
        "cve_findings": [],
        "js_analysis":  {},
    }

    spinner = PhaseSpinner()

    # ── Phase 1  WHOIS & Geo ──────────────────────────────────────────────────
    console.print("[bold white]Phase  1/17  ─  WHOIS & Organization Intelligence[/bold white]")
    spinner.start("WHOIS & geo lookup")
    try:
        report_data["ip"] = socket.gethostbyname(domain)
        w = whois.whois(domain)
        report_data["whois"] = {
            "registrar":     getattr(w, "registrar",  "Unknown"),
            "creation_date": str(getattr(w, "creation_date", "Unknown")),
            "org":           getattr(w, "org", "Unknown"),
        }
        geo = requests.get(
            f"https://ip-api.com/json/{report_data['ip']}", timeout=5).json()
        if geo.get("status") == "success":
            report_data["geo"] = (
                f"{geo.get('country','?')}, {geo.get('city','?')} ({geo.get('isp','?')})")
        else:
            try:
                geo2 = requests.get(
                    f"https://ipinfo.io/{report_data['ip']}/json", timeout=5).json()
                report_data["geo"] = (
                    f"{geo2.get('country','?')}, {geo2.get('city','?')} ({geo2.get('org','?')})")
            except Exception:
                report_data["geo"] = f"IP: {report_data['ip']} (geo lookup failed)"
    except Exception as e:
        console.print(f"\n[bold yellow][~] WHOIS partial failure: {e}[/bold yellow]")
    finally:
        spinner.stop()
    console.print(
        f"  [green]✔[/green] IP: {report_data['ip']}  |  "
        f"Org: {report_data['whois'].get('org','?')}")

    # ── Phase 2  WHOIS Enrichment ─────────────────────────────────────────────
    console.print("\n[bold white]Phase  2/17  ─  Extended WHOIS Enrichment[/bold white]")
    spinner.start("Enriching WHOIS data")
    try:
        report_data["whois_ext"] = enrich_whois(domain)
    except Exception as e:
        report_data["whois_ext"] = {"error": str(e)}
    finally:
        spinner.stop()
    we = report_data["whois_ext"]
    console.print(
        f"  [green]✔[/green] Registrar: {we.get('registrar','?')}  |  "
        f"Expiry: {we.get('expiry_date','?')}  |  "
        f"NS: {len(we.get('nameservers',[]))} records")

    # ── Phase 3  WAF & Perimeter ──────────────────────────────────────────────
    console.print("\n[bold white]Phase  3/17  ─  WAF & Perimeter Detection[/bold white]")
    spinner.start("WAF fingerprinting")
    try:
        report_data["waf"] = detect_waf(domain)
    except Exception as e:
        report_data["waf"] = f"Detection error: {e}"
    finally:
        spinner.stop()
    waf_display = (
        f"[bold red]{report_data['waf']}[/bold red]"
        if "Detected" in report_data["waf"]
        else f"[green]{report_data['waf']}[/green]")
    console.print(f"  [green]✔[/green] WAF: {waf_display}")

    # ── Phase 4  CDN Bypass ───────────────────────────────────────────────────
    console.print("\n[bold white]Phase  4/17  ─  CDN / Cloudflare Bypass[/bold white]")
    spinner.start("Attempting origin IP discovery")
    try:
        report_data["cdn_bypass"] = bypass_cdn(domain)
    except Exception as e:
        report_data["cdn_bypass"] = {"error": str(e)}
    finally:
        spinner.stop()
    cdn = report_data["cdn_bypass"]
    if cdn.get("cdn_detected"):
        candidates  = len(cdn.get("real_ip_candidates", []))
        cand_color  = "green" if candidates else "dim"
        console.print(
            f"  [bold yellow]⚠[/bold yellow] CDN: {cdn['cdn_name']}  |  "
            f"[{cand_color}]{candidates} origin IP candidate(s) found[/{cand_color}]")
    else:
        console.print("  [green]✔[/green] No CDN detected — origin IP likely exposed directly")

    # ── Phase 5  Tech Stack ───────────────────────────────────────────────────
    console.print("\n[bold white]Phase  5/17  ─  Technology Stack Fingerprinting[/bold white]")
    spinner.start("Fingerprinting tech stack")
    try:
        report_data["tech_stack"] = fingerprint_tech_stack(domain)
    except Exception as e:
        report_data["tech_stack"] = [f"Error: {e}"]
    finally:
        spinner.stop()
    console.print(f"  [green]✔[/green] Detected: {', '.join(report_data['tech_stack'])}")

    # ── Phase 6  Subdomain Enumeration ────────────────────────────────────────
    console.print("\n[bold white]Phase  6/17  ─  Subdomain Enumeration (Wordlist)[/bold white]")
    console.print("  [dim]Brute-forcing subdomains via wordlist (threaded)...[/dim]")
    spinner.start("Subdomain enumeration")
    try:
        report_data["subdomains"] = enumerate_subdomains(domain)
    except Exception as e:
        console.print(f"\n[bold yellow][~] Subdomain error: {e}[/bold yellow]")
    finally:
        spinner.stop()
    sub_count = len(report_data["subdomains"])
    console.print(
        f"  [green]✔[/green] {sub_count} subdomain(s) discovered"
        if sub_count else "  [dim]  No subdomains discovered[/dim]")

    # ── Phase 7  OSINT Harvesting ─────────────────────────────────────────────
    console.print("\n[bold white]Phase  7/17  ─  OSINT Harvesting (crt.sh / HackerTarget / Shodan / Wayback / GitHub)[/bold white]")
    console.print("  [dim]Querying external intelligence sources...[/dim]")
    spinner.start("OSINT harvesting in progress")
    try:
        report_data["osint"] = harvest_osint(domain)
    except Exception as e:
        report_data["osint"] = {"error": str(e)}
    finally:
        spinner.stop()
    osint = report_data["osint"]
    console.print(
        f"  [green]✔[/green] "
        f"crt.sh subdomains: {len(osint.get('crt_subdomains',[]))}  |  "
        f"Wayback URLs: {len(osint.get('wayback_urls',[]))}  |  "
        f"GitHub leaks: {len(osint.get('github_leaks',[]))}  |  "
        f"Shodan ports: {len(osint.get('shodan_basic',{}).get('ports',[]))}")

    # ── Phase 8  DNS Enumeration ──────────────────────────────────────────────
    console.print("\n[bold white]Phase  8/17  ─  DNS Record Enumeration[/bold white]")
    spinner.start("DNS enumeration")
    try:
        report_data["dns_records"] = enumerate_dns(domain)
    except Exception as e:
        console.print(f"\n[bold yellow][~] DNS error: {e}[/bold yellow]")
    finally:
        spinner.stop()
    console.print(f"  [green]✔[/green] {len(report_data['dns_records'])} record(s) retrieved")

    # ── Phase 9  Email Scraping ───────────────────────────────────────────────
    console.print("\n[bold white]Phase  9/17  ─  Email Intelligence Scraping[/bold white]")
    spinner.start("Scraping for email addresses")
    try:
        report_data["emails"] = scrape_emails(domain)
    except Exception as e:
        console.print(f"\n[bold yellow][~] Scraping error: {e}[/bold yellow]")
    finally:
        spinner.stop()
    count = len(report_data["emails"])
    console.print(
        f"  [green]✔[/green] {count} email address(es) found"
        if count else "  [dim]  No emails found[/dim]")

    # ── Phase 10  JavaScript Analysis ────────────────────────────────────────
    console.print("\n[bold white]Phase 10/17  ─  JavaScript File Analysis[/bold white]")
    console.print("  [dim]Scanning JS files for secrets, API keys, internal endpoints...[/dim]")
    spinner.start("JS analysis in progress")
    try:
        report_data["js_analysis"] = analyze_js_files(domain)
    except Exception as e:
        report_data["js_analysis"] = {"error": str(e), "secrets": [], "js_files_found": []}
    finally:
        spinner.stop()
    js = report_data["js_analysis"]
    secret_count = len(js.get("secrets", []))
    secret_color = "bold red" if secret_count else "green"
    console.print(
        f"  [green]✔[/green] JS files: {len(js.get('js_files_found',[]))}  |  "
        f"[{secret_color}]Secrets found: {secret_count}[/{secret_color}]  |  "
        f"Internal paths: {len(js.get('internal_paths',[]))}")

    # ── Phase 11  SSL Certificate ─────────────────────────────────────────────
    console.print("\n[bold white]Phase 11/17  ─  SSL/TLS Certificate Inspection[/bold white]")
    spinner.start("Inspecting TLS certificate")
    try:
        report_data["ssl_cert"] = inspect_ssl_certificate(domain)
    except Exception as e:
        report_data["ssl_cert"] = {"error": str(e), "valid": False, "sans": []}
    finally:
        spinner.stop()
    cert = report_data["ssl_cert"]
    if cert.get("valid"):
        days  = cert.get("days_left", "?")
        color = "green" if isinstance(days, int) and days > 30 else "bold red"
        console.print(
            f"  [green]✔[/green] Issuer: {cert.get('issuer','?')}  |  "
            f"Expires: {cert.get('expiry','?')}  |  "
            f"[{color}]{days} days remaining[/{color}]  |  "
            f"{len(cert.get('sans',[]))} SAN(s)")
    else:
        console.print(f"  [bold yellow][~] {cert.get('error','Could not inspect')}[/bold yellow]")

    # ── Phase 11  Security Headers ────────────────────────────────────────────
    console.print("\n[bold white]Phase 12/17  ─  HTTP Security Headers Check[/bold white]")
    spinner.start("Checking HTTP security headers")
    try:
        report_data["sec_headers"] = check_security_headers(domain)
    except Exception as e:
        report_data["sec_headers"] = {"missing": [], "present": [], "error": str(e)}
    finally:
        spinner.stop()
    sh = report_data["sec_headers"]
    mc = len(sh.get("missing", []))
    pc = len(sh.get("present", []))
    mc_color = "bold red" if mc > 3 else "yellow"
    console.print(
        f"  [green]✔[/green] {pc} present  |  "
        f"[{mc_color}]{mc} missing[/{mc_color}]")

    # ── Phase 12  CMS & Admin Detection ──────────────────────────────────────
    console.print("\n[bold white]Phase 13/17  ─  CMS Detection & Admin Panel Discovery[/bold white]")
    console.print("  [dim]Probing 50+ paths for admin panels and sensitive files...[/dim]")
    spinner.start("CMS and admin panel scan")
    try:
        report_data["cms_admin"] = detect_cms_and_admin(domain)
    except Exception as e:
        report_data["cms_admin"] = {"error": str(e)}
    finally:
        spinner.stop()
    ca = report_data["cms_admin"]
    console.print(
        f"  [green]✔[/green] CMS: {', '.join(ca.get('cms_detected',[])) or 'None detected'}  |  "
        f"Admin panels: {len(ca.get('admin_panels',[]))}  |  "
        f"Sensitive files: {len(ca.get('sensitive_files',[]))}  |  "
        f"Interesting paths: {len(ca.get('interesting_paths',[]))}")

    # ── Phase 13  API Fuzzing ─────────────────────────────────────────────────
    console.print("\n[bold white]Phase 14/17  ─  API Fuzzing & Endpoint Discovery[/bold white]")
    console.print("  [dim]Fuzzing API endpoints, GraphQL, Swagger, actuators...[/dim]")
    spinner.start("API fuzzing in progress")
    try:
        report_data["api_fuzz"] = fuzz_api(domain)
    except Exception as e:
        report_data["api_fuzz"] = {"error": str(e)}
    finally:
        spinner.stop()
    af = report_data["api_fuzz"]
    gql = "YES ⚠" if af.get("graphql_introspection") else "No"
    console.print(
        f"  [green]✔[/green] Open endpoints: {len(af.get('open_endpoints',[]))}  |  "
        f"Swagger exposed: {len(af.get('swagger_exposed',[]))}  |  "
        f"GraphQL introspection: {gql}  |  "
        f"Actuator exposed: {len(af.get('actuator_exposed',[]))}")

    # ── Phase 14  Auth Testing ────────────────────────────────────────────────
    console.print("\n[bold white]Phase 15/17  ─  Authentication Testing[/bold white]")
    console.print("  [dim]Testing default credentials, JWT weaknesses, auth bypass headers...[/dim]")
    spinner.start("Auth testing in progress")
    try:
        report_data["auth_test"] = test_auth(domain)
    except Exception as e:
        report_data["auth_test"] = {"error": str(e)}
    finally:
        spinner.stop()
    at = report_data["auth_test"]
    hits = len(at.get("default_creds_hits", []))
    hits_color = "bold red" if hits else "green"
    console.print(
        f"  [green]✔[/green] Login pages: {len(at.get('login_pages_found',[]))}  |  "
        f"[{hits_color}]Default cred hits: {hits}[/{hits_color}]  |  "
        f"JWT issues: {len(at.get('jwt_issues',[]))}  |  "
        f"Bypass hints: {len(at.get('auth_bypass_hints',[]))}")

    # ── Phase 15  Nmap ────────────────────────────────────────────────────────
    console.print("\n[bold white]Phase 16/17  ─  Nmap Port Scan & Vulnerability Scripts[/bold white]")
    console.print("  [dim]This may take 1–3 minutes depending on target...[/dim]")
    if not report_data.get("ip"):
        console.print("  [bold yellow][~] Skipping Nmap — IP resolution failed in Phase 1.[/bold yellow]")
    else:
        spinner.start("Nmap stealth scan in progress")
        try:
            ports, vulns = run_nmap_scan(report_data["ip"])
            report_data["ports"] = ports
            report_data["vulns"] = vulns
        except Exception as e:
            console.print(f"\n[bold yellow][~] Nmap error: {e}[/bold yellow]")
        finally:
            spinner.stop()
        console.print(
            f"  [green]✔[/green] {len(report_data['ports'])} port(s) scanned  |  "
            f"{len(report_data['vulns'])} vuln finding(s)")

    # ── Phase 17  CVE Correlation ─────────────────────────────────────────────
    console.print("\n[bold white]Phase 17/17  ─  CVE Correlation (NVD)[/bold white]")
    console.print("  [dim]Querying NIST National Vulnerability Database for known CVEs...[/dim]")
    spinner.start("CVE correlation in progress")
    try:
        report_data["cve_findings"] = correlate_cves(
            report_data.get("tech_stack", []),
            report_data.get("ports", [])
        )
    except Exception as e:
        report_data["cve_findings"] = []
        console.print(f"\n[bold yellow][~] CVE correlation error: {e}[/bold yellow]")
    finally:
        spinner.stop()
    cve_count = len(report_data["cve_findings"])
    if cve_count == 0:
        console.print("  [green]✔[/green] No HIGH/CRITICAL CVEs matched to detected tech stack.")
    else:
        console.print(f"  [bold red]⚠[/bold red] {cve_count} CVE(s) found — review immediately")
    console.print("\n")
    display_results(report_data, domain)

    console.print("\n[bold cyan][*] Generating PDF report...[/bold cyan]")
    pdf_file = generate_pdf_report(report_data, domain, operator)
    if pdf_file:
        console.print(f"[bold green][+] Report saved: {pdf_file}[/bold green]")
    else:
        console.print("[bold red][!] PDF generation failed.[/bold red]")

    console.print(
        "\n[bold green][✔] Reconnaissance complete. PriViSecurity standing by.[/bold green]\n"
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Scan aborted by user.[/bold yellow]")
        sys.exit(0)
