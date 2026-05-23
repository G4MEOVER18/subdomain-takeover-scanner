#!/usr/bin/env python3
"""
subdomain-takeover-scanner
Comprehensive subdomain takeover vulnerability scanner.

Author : G4MEOVER18
License: MIT
"""

import argparse
import csv
import json
import os
import socket
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# ---------------------------------------------------------------------------
# Colour helpers (no external deps)
# ---------------------------------------------------------------------------
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
DIM    = "\033[2m"

def _supports_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

USE_COLOR = _supports_color()

def c(text: str, color: str) -> str:
    return f"{color}{text}{RESET}" if USE_COLOR else text

# ---------------------------------------------------------------------------
# Provider fingerprint database
# ---------------------------------------------------------------------------
@dataclass
class Provider:
    name: str
    cname_patterns: List[str]          # substrings to match in CNAME answer
    http_fingerprint: str              # substring to look for in HTTP body
    nxdomain_takeover: bool = True     # can be claimed after NXDOMAIN?
    notes: str = ""

PROVIDERS: List[Provider] = [
    Provider("AWS S3",
             ["s3.amazonaws.com", "s3-website"],
             "NoSuchBucket",
             notes="Bucket must match subdomain name exactly"),
    Provider("GitHub Pages",
             ["github.io", "github.com"],
             "There isn't a GitHub Pages site here",
             notes="Claim the username/repo at github.com"),
    Provider("Heroku",
             ["herokuapp.com", "herokussl.com", "herokudns.com"],
             "No such app",
             notes="Heroku custom domains can be claimed freely"),
    Provider("Netlify",
             ["netlify.app", "netlify.com"],
             "Not Found",
             notes="Deploy a site and add the custom domain"),
    Provider("Shopify",
             ["myshopify.com", "shopify.com"],
             "Sorry, this shop is currently unavailable",
             notes="Create a Shopify store and map the domain"),
    Provider("Tumblr",
             ["tumblr.com"],
             "There's nothing here",
             notes="Create a Tumblr blog with matching custom domain"),
    Provider("Fastly",
             ["fastly.net"],
             "Fastly error: unknown domain",
             notes="Activate a Fastly service for the domain"),
    Provider("Azure Web Apps",
             ["azurewebsites.net"],
             "404 Web Site not found",
             notes="Create an Azure Web App with that hostname"),
    Provider("Azure Traffic Manager",
             ["trafficmanager.net"],
             "404 Not Found",
             notes="Azure Traffic Manager endpoint unclaimed"),
    Provider("Azure Cloud Services",
             ["cloudapp.net", "cloudapp.azure.com"],
             "404 - Web app not found",
             notes="Azure Cloud Service hostname unclaimed"),
    Provider("Zendesk",
             ["zendesk.com"],
             "Help Center Closed",
             notes="Register a Zendesk account with that subdomain"),
    Provider("Acquia",
             ["acquia-sites.com"],
             "Web Site Not Configured",
             notes="Acquia hosting — unclaimed site slot"),
    Provider("Campaign Monitor",
             ["createsend.com", "cmail1.com", "cmail19.com"],
             "Double check the URL",
             notes="Campaign Monitor client subdomain"),
    Provider("Ghost",
             ["ghost.io"],
             "The thing you were looking for is no longer here",
             notes="Create a Ghost(Pro) publication"),
    Provider("Pantheon",
             ["pantheonsite.io", "panth.io"],
             "The gods are wise, but do not know of the site",
             notes="Pantheon hosting — claim the site"),
    Provider("ReadMe.io",
             ["readme.io", "readmessl.com"],
             "Project doesnt exist",
             notes="Create a ReadMe project and map domain"),
    Provider("SmugMug",
             ["smugmug.com"],
             "Page Not Found",
             notes="SmugMug custom domain not mapped"),
    Provider("Squarespace",
             ["squarespace.com"],
             "No Such Account",
             notes="Squarespace custom domain — account deleted"),
    Provider("StatusPage",
             ["statuspage.io"],
             "page not found",
             notes="Atlassian StatusPage — unclaimed page"),
    Provider("Surge.sh",
             ["surge.sh"],
             "project not found",
             notes="Deploy a Surge project to claim"),
    Provider("WordPress.com",
             ["wordpress.com", "wp.com"],
             "Do you want to register",
             notes="WordPress.com blog — username available"),
    Provider("Unbounce",
             ["unbounce.com"],
             "The requested URL was not found on this server",
             notes="Unbounce landing page — account deleted"),
    Provider("Desk.com / Salesforce",
             ["desk.com"],
             "Sorry, we couldn't find your desk.com site",
             notes="Salesforce Desk — service discontinued"),
    Provider("UserVoice",
             ["uservoice.com"],
             "This UserVoice subdomain is currently available",
             notes="UserVoice forum — unclaimed subdomain"),
    Provider("Intercom",
             ["custom.intercom.help", "intercom.help"],
             "This page doesn't exist",
             notes="Intercom help center — custom domain not mapped"),
    Provider("Webflow",
             ["webflow.io"],
             "The page you are looking for doesn't exist",
             notes="Webflow project — unclaimed custom domain"),
    Provider("Strikingly",
             ["strikingly.com", "s.strikinglydns.com"],
             "But if you're looking to build your own website",
             notes="Strikingly — free tier domain unclaimed"),
    Provider("Tilda",
             ["tilda.ws"],
             "Please renew your subscription",
             notes="Tilda subscription lapsed"),
    Provider("HubSpot",
             ["hubspot.com", "hs-sites.com", "hubspotpagebuilder.com"],
             "Domain not configured",
             notes="HubSpot landing page domain mapping removed"),
    Provider("JetBrains Space",
             ["jetbrains.space"],
             "Page Not Found",
             notes="JetBrains Space org subdomain"),
    Provider("Vercel",
             ["vercel.app", "now.sh"],
             "The deployment could not be found",
             notes="Vercel deployment — CNAME dangling"),
    Provider("Render",
             ["onrender.com"],
             "Service Not Found",
             notes="Render service deleted but DNS remains"),
    Provider("Fly.io",
             ["fly.dev", "fly.io"],
             "404: Not Found",
             notes="Fly.io app deleted but CNAME remains"),
    Provider("Cargo Collective",
             ["cargocollective.com"],
             "404 Not Found",
             notes="Cargo Collective site — account deleted"),
    Provider("Agile CRM",
             ["agilecrm.com"],
             "Sorry, this page is no longer available",
             notes="Agile CRM custom domain unclaimed"),
]

# Build quick lookup: cname_fragment -> Provider
_CNAME_INDEX: Dict[str, Provider] = {}
for _p in PROVIDERS:
    for _pat in _p.cname_patterns:
        _CNAME_INDEX[_pat.lower()] = _p

# Configurable DNS servers (overridable via --dns)
_DNS_SERVERS: List[str] = ["8.8.8.8", "1.1.1.1"]

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_INFO     = "INFO"
SEVERITY_SAFE     = "SAFE"

@dataclass
class ScanResult:
    subdomain: str
    cname: Optional[str]          = None
    cname_chain: List[str]        = field(default_factory=list)
    chain_depth: int              = 0
    ip: Optional[str]             = None
    provider: Optional[str]       = None
    nxdomain: bool                = False
    http_status: Optional[int]    = None
    fingerprint_match: bool       = False
    tls_sans: List[str]           = field(default_factory=list)
    severity: str                 = SEVERITY_INFO
    detail: str                   = ""
    error: Optional[str]          = None

# ---------------------------------------------------------------------------
# DNS helpers
# ---------------------------------------------------------------------------
def _raw_cname_query(host: str, timeout: float = 3.0,
                     dns_servers: Optional[List[str]] = None) -> Optional[str]:
    """Minimalist raw DNS CNAME query over UDP. Tries each DNS server in order."""
    import struct, random

    if dns_servers is None:
        dns_servers = _DNS_SERVERS

    def encode_name(name: str) -> bytes:
        parts = name.rstrip(".").split(".")
        out = b""
        for part in parts:
            enc = part.encode()
            out += bytes([len(enc)]) + enc
        return out + b"\x00"

    def decode_name(data: bytes, offset: int) -> Tuple[str, int]:
        labels = []
        visited = set()
        while offset < len(data):
            if offset in visited:
                break
            visited.add(offset)
            length = data[offset]
            if length == 0:
                offset += 1
                break
            elif (length & 0xC0) == 0xC0:
                ptr = ((length & 0x3F) << 8) | data[offset + 1]
                offset += 2
                label, _ = decode_name(data, ptr)
                labels.append(label)
                break
            else:
                offset += 1
                labels.append(data[offset:offset + length].decode(errors="replace"))
                offset += length
        return ".".join(labels), offset

    txid = random.randint(0, 0xFFFF)
    qname = encode_name(host)
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = qname + struct.pack(">HH", 5, 1)   # QTYPE=CNAME(5), QCLASS=IN(1)
    packet = header + question

    for dns_server in dns_servers:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (dns_server, 53))
            resp, _ = sock.recvfrom(512)
        except Exception:
            continue
        finally:
            sock.close()

        ancount = struct.unpack(">H", resp[6:8])[0]
        if ancount == 0:
            return None

        pos = 12
        while pos < len(resp):
            ll = resp[pos]
            if ll == 0:
                pos += 1
                break
            elif (ll & 0xC0) == 0xC0:
                pos += 2
                break
            pos += 1 + ll
        pos += 4  # QTYPE + QCLASS

        _name, pos = decode_name(resp, pos)
        if pos + 10 > len(resp):
            return None
        rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", resp[pos:pos + 10])
        pos += 10
        if rtype == 5:
            cname_target, _ = decode_name(resp, pos)
            return cname_target
        return None

    return None


def resolve_cname_chain(host: str, max_hops: int = 10) -> List[str]:
    """Follow the full CNAME chain up to max_hops. Returns list of CNAME targets."""
    chain: List[str] = []
    current = host
    seen: set = set()

    for _ in range(max_hops):
        if current in seen:
            break
        seen.add(current)

        # Try dnspython first
        target = None
        try:
            import dns.resolver  # type: ignore
            answers = dns.resolver.resolve(current, "CNAME")
            target = str(answers[0].target).rstrip(".")
        except ImportError:
            pass
        except Exception:
            pass

        if target is None:
            try:
                target = _raw_cname_query(current)
            except Exception:
                pass

        if target is None:
            break
        chain.append(target)
        current = target

    return chain


def resolve_cname(host: str) -> Optional[str]:
    """Return the first CNAME target for host (or None)."""
    chain = resolve_cname_chain(host, max_hops=1)
    return chain[0] if chain else None


def resolve_a(host: str) -> Tuple[Optional[str], bool]:
    """Returns (ip_str, nxdomain_bool)."""
    try:
        ip = socket.gethostbyname(host)
        return ip, False
    except socket.gaierror as e:
        nxdomain = "Name or service not known" in str(e) or \
                   "No such host" in str(e) or \
                   str(e.args[0]) in ("11001", "11004", "-2", "-5")
        return None, nxdomain


# ---------------------------------------------------------------------------
# TLS / SSL helpers
# ---------------------------------------------------------------------------
def get_tls_sans(host: str, timeout: float = 5.0) -> List[str]:
    """Connect via TLS and extract Subject Alternative Names from the certificate."""
    sans: List[str] = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                if cert:
                    for rdn_type, value in cert.get("subjectAltName", []):
                        if rdn_type == "DNS":
                            sans.append(value)
    except Exception:
        pass
    return sans


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
_UA = "Mozilla/5.0 (compatible; SubdomainTakeoverScanner/2.0)"


def http_get(url: str, timeout: int = 8) -> Tuple[int, str]:
    """Return (status_code, body_text). Body is truncated to 8 KB."""
    req = Request(url, headers={"User-Agent": _UA})
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read(8192).decode("utf-8", errors="replace")
            return resp.status, body
    except HTTPError as e:
        try:
            body = e.read(8192).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return e.code, body
    except URLError:
        return 0, ""
    except Exception:
        return 0, ""


def http_get_with_retry(url: str, retries: int = 2, timeout: int = 8) -> Tuple[int, str]:
    """HTTP GET with exponential backoff retry on connection failure."""
    delay = 0.5
    for attempt in range(retries + 1):
        status, body = http_get(url, timeout=timeout)
        if status > 0:
            return status, body
        if attempt < retries:
            time.sleep(delay)
            delay *= 2
    return 0, ""


# ---------------------------------------------------------------------------
# Provider matching
# ---------------------------------------------------------------------------
def match_provider_by_cname(cname: str) -> Optional[Provider]:
    cname_l = cname.lower()
    for pattern, provider in _CNAME_INDEX.items():
        if pattern in cname_l:
            return provider
    return None


def check_fingerprint(provider: Provider, body: str) -> bool:
    return provider.http_fingerprint.lower() in body.lower()


def load_providers_file(path: str) -> List[Provider]:
    """Load additional provider fingerprints from a JSON file."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    providers: List[Provider] = []
    for entry in data:
        providers.append(Provider(
            name=entry["name"],
            cname_patterns=entry.get("cname_patterns", []),
            http_fingerprint=entry.get("http_fingerprint", ""),
            nxdomain_takeover=entry.get("nxdomain_takeover", True),
            notes=entry.get("notes", ""),
        ))
    return providers


# ---------------------------------------------------------------------------
# Core scan logic
# ---------------------------------------------------------------------------
def scan_subdomain(subdomain: str, http_timeout: int = 8, retries: int = 2,
                   enumerate_sans: bool = False) -> ScanResult:
    result = ScanResult(subdomain=subdomain)

    # 1. Resolve full CNAME chain (up to 10 hops)
    chain = resolve_cname_chain(subdomain, max_hops=10)
    result.cname_chain = chain
    result.chain_depth = len(chain)
    result.cname = chain[0] if chain else None

    # 2. Resolve A record
    ip, nxdomain = resolve_a(subdomain)
    result.ip = ip
    result.nxdomain = nxdomain

    # 3. Match provider — check every hop in the chain
    provider: Optional[Provider] = None
    matched_cname: Optional[str] = None
    for hop in chain:
        p = match_provider_by_cname(hop)
        if p:
            provider = p
            matched_cname = hop
            break
    if provider:
        result.provider = provider.name

    # 4. Classify severity
    if nxdomain and chain:
        result.severity = SEVERITY_CRITICAL
        result.detail = (
            f"CNAME '{chain[-1]}' resolves to NXDOMAIN (chain depth {len(chain)}). "
            f"Provider: {provider.name if provider else 'unknown'}. "
            "Subdomain ist wahrscheinlich übernehmbar."
        )
        return result

    if nxdomain and not chain:
        result.severity = SEVERITY_INFO
        result.detail = "Host existiert nicht (NXDOMAIN, kein hängender CNAME)."
        return result

    if not ip and not nxdomain:
        result.severity = SEVERITY_INFO
        result.detail = "DNS-Auflösung fehlgeschlagen (Timeout oder anderer Fehler)."
        result.error = "DNS timeout"
        return result

    # 5. Suspicious chain depth (>3 hops without known provider = dangling risk)
    if len(chain) > 3 and not provider:
        result.severity = SEVERITY_MEDIUM
        result.detail = (
            f"CNAME-Kette mit {len(chain)} Hops ohne bekannten Provider. "
            f"Letzte Hop: {chain[-1]}. Manuelle Prüfung empfohlen."
        )

    # 6. TLS SAN enumeration (reveals additional hostnames from cert)
    if enumerate_sans and ip:
        sans = get_tls_sans(subdomain)
        result.tls_sans = sans

    # 7. HTTP fingerprint check if provider matched
    if provider:
        for scheme in ("https", "http"):
            status, body = http_get_with_retry(
                f"{scheme}://{subdomain}", retries=retries, timeout=http_timeout
            )
            if status > 0:
                result.http_status = status
                if check_fingerprint(provider, body):
                    result.fingerprint_match = True
                    result.severity = SEVERITY_HIGH
                    result.detail = (
                        f"HTTP {status}: Fingerprint '{provider.http_fingerprint}' "
                        f"gefunden. Provider: {provider.name} via '{matched_cname}'. "
                        "Subdomain wahrscheinlich übernehmbar."
                    )
                    return result
                else:
                    result.severity = SEVERITY_MEDIUM
                    result.detail = (
                        f"CNAME zeigt auf {provider.name} ({matched_cname}) aber "
                        "Fingerprint nicht gefunden. Möglicherweise noch angreifbar."
                    )
                    return result
        result.severity = SEVERITY_MEDIUM
        result.detail = (
            f"CNAME zeigt auf {provider.name} ({matched_cname}) aber "
            "HTTP-Anfrage fehlgeschlagen. Manuelle Prüfung empfohlen."
        )
        return result

    # 8. Resolved fine, no known provider
    if result.severity == SEVERITY_INFO:
        result.severity = SEVERITY_SAFE
        result.detail = f"Aufgelöst zu {ip}. Kein bekannter Takeover-Provider erkannt."
    return result


# ---------------------------------------------------------------------------
# Progress bar
# ---------------------------------------------------------------------------
_progress_lock = threading.Lock()
_progress_done = 0
_progress_total = 0


def _init_progress(total: int):
    global _progress_done, _progress_total
    _progress_done = 0
    _progress_total = total


def _tick_progress(label: str = ""):
    global _progress_done
    with _progress_lock:
        _progress_done += 1
        pct = int(_progress_done / _progress_total * 40) if _progress_total else 0
        bar = "#" * pct + "-" * (40 - pct)
        sys.stderr.write(
            f"\r  [{bar}] {_progress_done}/{_progress_total}  {label[:40]:<40}"
        )
        sys.stderr.flush()


def _finish_progress():
    sys.stderr.write("\n")
    sys.stderr.flush()


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
SEV_COLORS = {
    SEVERITY_CRITICAL: RED + BOLD,
    SEVERITY_HIGH:     RED,
    SEVERITY_MEDIUM:   YELLOW,
    SEVERITY_INFO:     DIM,
    SEVERITY_SAFE:     GREEN,
}

COL_W = {
    "subdomain": 38,
    "severity": 10,
    "provider": 22,
    "cname": 40,
    "detail": 55,
}


def _col(text: str, width: int) -> str:
    text = str(text or "")
    if len(text) > width:
        text = text[:width - 1] + "…"
    return text.ljust(width)


def print_table_header():
    header = (
        _col("SUBDOMAIN", COL_W["subdomain"]) + "  " +
        _col("SEV", COL_W["severity"]) + "  " +
        _col("PROVIDER", COL_W["provider"]) + "  " +
        _col("CNAME", COL_W["cname"]) + "  " +
        _col("DETAIL", COL_W["detail"])
    )
    print(c("\n" + header, BOLD + WHITE))
    print(c("-" * len(header), DIM))


def print_result_row(r: ScanResult):
    sev_color = SEV_COLORS.get(r.severity, "")
    row = (
        _col(r.subdomain, COL_W["subdomain"]) + "  " +
        _col(r.severity,  COL_W["severity"]) + "  " +
        _col(r.provider or "-", COL_W["provider"]) + "  " +
        _col(r.cname or "-",    COL_W["cname"]) + "  " +
        _col(r.detail,          COL_W["detail"])
    )
    print(c(row, sev_color))
    if r.tls_sans:
        print(c(f"    TLS SANs: {', '.join(r.tls_sans[:6])}", DIM))
    if r.chain_depth > 1:
        chain_str = " → ".join(r.cname_chain[:5])
        if r.chain_depth > 5:
            chain_str += " → …"
        print(c(f"    CNAME-Kette ({r.chain_depth} Hops): {chain_str}", DIM))


def print_summary(results: List[ScanResult]):
    counts: Dict[str, int] = {}
    for r in results:
        counts[r.severity] = counts.get(r.severity, 0) + 1

    print(c("\n=== SCAN ZUSAMMENFASSUNG ===", BOLD + WHITE))
    total = len(results)
    print(f"  Gesamt gescannt: {total}")
    for sev in (SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_SAFE, SEVERITY_INFO):
        n = counts.get(sev, 0)
        if n:
            print(c(f"  {sev:<12}: {n}", SEV_COLORS.get(sev, "")))
    print()


def write_json(results: List[ScanResult], path: str):
    data = []
    for r in results:
        data.append({
            "subdomain":         r.subdomain,
            "severity":          r.severity,
            "provider":          r.provider,
            "cname":             r.cname,
            "cname_chain":       r.cname_chain,
            "chain_depth":       r.chain_depth,
            "ip":                r.ip,
            "nxdomain":          r.nxdomain,
            "http_status":       r.http_status,
            "fingerprint_match": r.fingerprint_match,
            "tls_sans":          r.tls_sans,
            "detail":            r.detail,
            "error":             r.error,
        })
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    print(c(f"  [+] JSON-Report geschrieben: {path}", CYAN))


def write_csv(results: List[ScanResult], path: str):
    fields = ["subdomain", "severity", "provider", "cname", "chain_depth",
              "ip", "nxdomain", "http_status", "fingerprint_match",
              "tls_sans", "detail", "error"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for r in results:
            w.writerow({
                "subdomain":         r.subdomain,
                "severity":          r.severity,
                "provider":          r.provider or "",
                "cname":             r.cname or "",
                "chain_depth":       r.chain_depth,
                "ip":                r.ip or "",
                "nxdomain":          r.nxdomain,
                "http_status":       r.http_status or "",
                "fingerprint_match": r.fingerprint_match,
                "tls_sans":          ";".join(r.tls_sans),
                "detail":            r.detail,
                "error":             r.error or "",
            })
    print(c(f"  [+] CSV-Report geschrieben: {path}", CYAN))


# ---------------------------------------------------------------------------
# Subdomain generation
# ---------------------------------------------------------------------------
def load_wordlist(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]


def build_targets(args: argparse.Namespace) -> List[str]:
    targets: List[str] = []

    if args.domain:
        base = args.domain.lstrip("*").strip(".")
        if args.wordlist:
            words = load_wordlist(args.wordlist)
            targets = [f"{w}.{base}" for w in words]
        else:
            targets = [base]

    if args.list:
        with open(args.list, "r", encoding="utf-8") as fh:
            for line in fh:
                host = line.strip()
                if host and not host.startswith("#"):
                    targets.append(host)

    seen: set = set()
    unique: List[str] = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="takeover.py",
        description=(
            "Subdomain Takeover Scanner — prüft 35+ Provider-Fingerprints\n"
            "auf hängende CNAMEs und nicht beanspruchte Hosting-Slots.\n"
            "Unterstützt CNAME-Ketten-Analyse, TLS-SAN-Enumeration,\n"
            "konfigurierbare DNS-Server und eigene Provider-Fingerprints."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  python takeover.py --domain example.com --wordlist wordlist.txt
  python takeover.py --list subdomains.txt --json results.json --csv out.csv
  python takeover.py --domain example.com --wordlist wordlist.txt --workers 50
  python takeover.py --list targets.txt --dns 8.8.8.8,9.9.9.9
  python takeover.py --list targets.txt --providers-file eigene_provider.json
  python takeover.py --list targets.txt --tls-sans --only-vulnerable

Providers-Datei Format (JSON):
  [{"name": "MeinProvider", "cname_patterns": ["myhost.example.com"],
    "http_fingerprint": "Account not found", "nxdomain_takeover": true}]

Exit-Codes:
  0  — keine CRITICAL oder HIGH Funde
  1  — mindestens ein CRITICAL oder HIGH Fund
  2  — Verwendungsfehler / Datei-Fehler
""",
    )
    p.add_argument("--domain", "-d", metavar="DOMAIN",
                   help="Basis-Domain. Benötigt --wordlist für Enumeration, "
                        "oder scannt nur den Apex.")
    p.add_argument("--wordlist", "-w", metavar="FILE",
                   help="Wortlisten-Datei (ein Prefix pro Zeile). Wird mit --domain verwendet.")
    p.add_argument("--list", "-l", metavar="FILE",
                   help="Datei mit vollständigen Hostnamen (einer pro Zeile).")
    p.add_argument("--workers", "-t", metavar="N", type=int, default=20,
                   help="Parallele Worker-Threads (Standard: 20).")
    p.add_argument("--json", metavar="FILE",
                   help="Ergebnisse als JSON in FILE schreiben.")
    p.add_argument("--csv", metavar="FILE",
                   help="Ergebnisse als CSV in FILE schreiben.")
    p.add_argument("--no-color", action="store_true",
                   help="ANSI-Farbausgabe deaktivieren.")
    p.add_argument("--only-vulnerable", action="store_true",
                   help="Nur CRITICAL und HIGH Funde ausgeben.")
    p.add_argument("--timeout", metavar="SEC", type=int, default=8,
                   help="HTTP-Anfrage-Timeout in Sekunden (Standard: 8).")
    p.add_argument("--retries", metavar="N", type=int, default=2,
                   help="HTTP-Wiederholungsversuche bei Verbindungsfehlern (Standard: 2).")
    p.add_argument("--dns", metavar="SERVER[,SERVER]",
                   help="Kommagetrennte DNS-Server für CNAME-Auflösung (Standard: 8.8.8.8,1.1.1.1).")
    p.add_argument("--tls-sans", action="store_true",
                   help="TLS-Zertifikat-SANs auflesen (zeigt weitere Hostnamen aus dem Cert).")
    p.add_argument("--providers-file", metavar="FILE",
                   help="JSON-Datei mit eigenen Provider-Fingerprints (wird mit Built-ins zusammengeführt).")
    p.add_argument("--providers", action="store_true",
                   help="Alle eingebauten Provider-Fingerprints auflisten und beenden.")
    return p


def list_providers():
    print(c("\nEingebaute Provider-Fingerprints", BOLD + WHITE))
    print(c("-" * 80, DIM))
    fmt = "  {:<25} {:<35} {}"
    print(c(fmt.format("PROVIDER", "CNAME-MUSTER", "HTTP-FINGERPRINT"), BOLD))
    print(c("-" * 80, DIM))
    for prov in PROVIDERS:
        patterns = ", ".join(prov.cname_patterns[:2])
        print(fmt.format(prov.name[:24], patterns[:34], prov.http_fingerprint[:45]))
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    global USE_COLOR, _DNS_SERVERS, _CNAME_INDEX

    parser = build_parser()
    args = parser.parse_args()

    if args.providers:
        list_providers()
        sys.exit(0)

    if args.no_color:
        USE_COLOR = False

    # Configurable DNS servers
    if args.dns:
        _DNS_SERVERS = [s.strip() for s in args.dns.split(",") if s.strip()]

    # Load extra provider fingerprints
    if args.providers_file:
        try:
            extra = load_providers_file(args.providers_file)
            PROVIDERS.extend(extra)
            for prov in extra:
                for pat in prov.cname_patterns:
                    _CNAME_INDEX[pat.lower()] = prov
            print(c(f"  [+] {len(extra)} externe Provider geladen aus {args.providers_file}", CYAN))
        except Exception as e:
            print(c(f"  [!] Provider-Datei konnte nicht geladen werden: {e}", YELLOW),
                  file=sys.stderr)

    if not args.domain and not args.list:
        parser.error("--domain oder --list (oder beides) angeben.")

    targets = build_targets(args)
    if not targets:
        print(c("[!] Keine Ziele gefunden. --domain / --list / --wordlist prüfen.", YELLOW),
              file=sys.stderr)
        sys.exit(2)

    http_timeout = args.timeout
    retries = args.retries
    enumerate_sans = args.tls_sans

    print(c(f"\n[*] Subdomain Takeover Scanner", BOLD + CYAN))
    print(c(f"[*] Ziele     : {len(targets)}", CYAN))
    print(c(f"[*] Worker    : {args.workers}", CYAN))
    print(c(f"[*] Provider  : {len(PROVIDERS)} Fingerprints geladen", CYAN))
    print(c(f"[*] DNS       : {', '.join(_DNS_SERVERS)}", CYAN))
    if enumerate_sans:
        print(c(f"[*] TLS SANs  : aktiviert", CYAN))

    _init_progress(len(targets))
    results: List[ScanResult] = []
    results_lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        future_map = {
            pool.submit(scan_subdomain, t, http_timeout, retries, enumerate_sans): t
            for t in targets
        }
        for future in as_completed(future_map):
            host = future_map[future]
            try:
                r = future.result()
            except Exception as exc:
                r = ScanResult(subdomain=host, severity=SEVERITY_INFO,
                               detail="", error=str(exc))
            with results_lock:
                results.append(r)
            _tick_progress(host)

    _finish_progress()

    SEV_ORDER = {
        SEVERITY_CRITICAL: 0,
        SEVERITY_HIGH:     1,
        SEVERITY_MEDIUM:   2,
        SEVERITY_INFO:     3,
        SEVERITY_SAFE:     4,
    }
    results.sort(key=lambda r: SEV_ORDER.get(r.severity, 99))

    print_table_header()
    for r in results:
        if args.only_vulnerable and r.severity not in (SEVERITY_CRITICAL, SEVERITY_HIGH):
            continue
        print_result_row(r)

    print_summary(results)

    if args.json:
        write_json(results, args.json)
    if args.csv:
        write_csv(results, args.csv)

    critical_high = [r for r in results
                     if r.severity in (SEVERITY_CRITICAL, SEVERITY_HIGH)]
    if critical_high:
        print(c(f"[!] {len(critical_high)} CRITICAL/HIGH Fund(e) erkannt. "
                "Exit-Code 1.", RED + BOLD))
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
