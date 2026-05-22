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
    cname: Optional[str]       = None
    ip: Optional[str]          = None
    provider: Optional[str]    = None
    nxdomain: bool             = False
    http_status: Optional[int] = None
    fingerprint_match: bool    = False
    severity: str              = SEVERITY_INFO
    detail: str                = ""
    error: Optional[str]       = None

# ---------------------------------------------------------------------------
# DNS helpers
# ---------------------------------------------------------------------------
def resolve_cname(host: str) -> Optional[str]:
    """Follow CNAME chain via getaddrinfo / manual query.
    Falls back to a raw DNS CNAME lookup using socket tricks."""
    try:
        # Try dnspython if available
        import dns.resolver  # type: ignore
        answers = dns.resolver.resolve(host, "CNAME")
        return str(answers[0].target).rstrip(".")
    except ImportError:
        pass
    except Exception:
        pass

    # stdlib fallback: socket cannot do CNAME, but we try anyway
    # via a raw UDP DNS packet (type CNAME = 5)
    try:
        return _raw_cname_query(host)
    except Exception:
        return None


def _raw_cname_query(host: str, timeout: float = 3.0) -> Optional[str]:
    """Minimalist raw DNS CNAME query over UDP."""
    import struct, random

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
            elif (length & 0xC0) == 0xC0:          # pointer
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
    # flags: standard query, recursion desired
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = qname + struct.pack(">HH", 5, 1)   # QTYPE=CNAME(5), QCLASS=IN(1)
    packet = header + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, ("8.8.8.8", 53))
        resp, _ = sock.recvfrom(512)
    finally:
        sock.close()

    # Parse answer count
    ancount = struct.unpack(">H", resp[6:8])[0]
    if ancount == 0:
        return None

    # Skip header (12 bytes) + question section
    pos = 12
    # Skip question name
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

    # Parse first answer RR
    _name, pos = decode_name(resp, pos)
    if pos + 10 > len(resp):
        return None
    rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", resp[pos:pos + 10])
    pos += 10
    if rtype == 5:   # CNAME
        cname_target, _ = decode_name(resp, pos)
        return cname_target
    return None


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
# HTTP helpers
# ---------------------------------------------------------------------------
_HTTP_TIMEOUT = 8
_UA = "Mozilla/5.0 (compatible; SubdomainTakeoverScanner/1.0)"


def http_get(url: str) -> Tuple[int, str]:
    """Return (status_code, body_text). Body is truncated to 8 KB."""
    req = Request(url, headers={"User-Agent": _UA})
    try:
        with urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
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


# ---------------------------------------------------------------------------
# Core scan logic
# ---------------------------------------------------------------------------
def scan_subdomain(subdomain: str) -> ScanResult:
    result = ScanResult(subdomain=subdomain)

    # 1. Resolve CNAME
    cname = resolve_cname(subdomain)
    result.cname = cname

    # 2. Resolve A record
    ip, nxdomain = resolve_a(subdomain)
    result.ip = ip
    result.nxdomain = nxdomain

    # 3. Match provider from CNAME
    provider: Optional[Provider] = None
    if cname:
        provider = match_provider_by_cname(cname)
        if provider:
            result.provider = provider.name

    # 4. Classify severity based on DNS state
    if nxdomain and cname:
        # Dangling CNAME → NXDOMAIN = almost certainly takeable
        result.severity = SEVERITY_CRITICAL
        result.detail = (
            f"CNAME '{cname}' resolves to NXDOMAIN. "
            f"Provider: {provider.name if provider else 'unknown'}. "
            "Subdomain is likely claimable."
        )
        return result

    if nxdomain and not cname:
        # Straight NXDOMAIN, no CNAME
        result.severity = SEVERITY_INFO
        result.detail = "Host does not exist (NXDOMAIN, no dangling CNAME)."
        return result

    if not ip and not nxdomain:
        result.severity = SEVERITY_INFO
        result.detail = "DNS resolution failed (timeout or other error)."
        result.error = "DNS timeout"
        return result

    # 5. If there's a provider match, fetch HTTP and check fingerprint
    if provider:
        for scheme in ("https", "http"):
            status, body = http_get(f"{scheme}://{subdomain}")
            if status > 0:
                result.http_status = status
                if check_fingerprint(provider, body):
                    result.fingerprint_match = True
                    result.severity = SEVERITY_HIGH
                    result.detail = (
                        f"HTTP {status}: fingerprint '{provider.http_fingerprint}' "
                        f"found. Provider: {provider.name}. "
                        "Subdomain may be claimable."
                    )
                    return result
                else:
                    result.severity = SEVERITY_MEDIUM
                    result.detail = (
                        f"CNAME points to {provider.name} ({cname}) but "
                        "fingerprint not matched. May still be vulnerable."
                    )
                    return result
        result.severity = SEVERITY_MEDIUM
        result.detail = (
            f"CNAME points to {provider.name} ({cname}) but "
            "HTTP request failed. Manual check recommended."
        )
        return result

    # 6. Resolved fine, no known provider
    result.severity = SEVERITY_SAFE
    result.detail = f"Resolved to {ip}. No known takeover provider detected."
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


def print_summary(results: List[ScanResult]):
    counts: Dict[str, int] = {}
    for r in results:
        counts[r.severity] = counts.get(r.severity, 0) + 1

    print(c("\n=== SCAN SUMMARY ===", BOLD + WHITE))
    total = len(results)
    print(f"  Total scanned : {total}")
    for sev in (SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_SAFE, SEVERITY_INFO):
        n = counts.get(sev, 0)
        if n:
            print(c(f"  {sev:<12}: {n}", SEV_COLORS.get(sev, "")))
    print()


def write_json(results: List[ScanResult], path: str):
    data = []
    for r in results:
        data.append({
            "subdomain":        r.subdomain,
            "severity":         r.severity,
            "provider":         r.provider,
            "cname":            r.cname,
            "ip":               r.ip,
            "nxdomain":         r.nxdomain,
            "http_status":      r.http_status,
            "fingerprint_match":r.fingerprint_match,
            "detail":           r.detail,
            "error":            r.error,
        })
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    print(c(f"  [+] JSON report written to {path}", CYAN))


def write_csv(results: List[ScanResult], path: str):
    fields = ["subdomain", "severity", "provider", "cname", "ip",
              "nxdomain", "http_status", "fingerprint_match", "detail", "error"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for r in results:
            w.writerow({
                "subdomain":         r.subdomain,
                "severity":          r.severity,
                "provider":          r.provider or "",
                "cname":             r.cname or "",
                "ip":                r.ip or "",
                "nxdomain":          r.nxdomain,
                "http_status":       r.http_status or "",
                "fingerprint_match": r.fingerprint_match,
                "detail":            r.detail,
                "error":             r.error or "",
            })
    print(c(f"  [+] CSV report written to {path}", CYAN))


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

    # Deduplicate while preserving order
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
            "Subdomain Takeover Scanner — checks 35+ provider fingerprints\n"
            "for dangling CNAMEs and unclaimed hosting slots."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python takeover.py --domain example.com --wordlist wordlist.txt
  python takeover.py --list subdomains.txt --json results.json --csv out.csv
  python takeover.py --domain example.com --wordlist wordlist.txt --workers 50
  python takeover.py --list targets.txt --no-color

Exit codes:
  0  — no CRITICAL or HIGH findings
  1  — at least one CRITICAL or HIGH finding
  2  — usage / file error
""",
    )
    p.add_argument("--domain", "-d", metavar="DOMAIN",
                   help="Base domain. Requires --wordlist for enumeration, "
                        "or scans the apex alone.")
    p.add_argument("--wordlist", "-w", metavar="FILE",
                   help="Wordlist file (one prefix per line). Used with --domain.")
    p.add_argument("--list", "-l", metavar="FILE",
                   help="File with full hostnames to scan (one per line).")
    p.add_argument("--workers", "-t", metavar="N", type=int, default=20,
                   help="Concurrent worker threads (default: 20).")
    p.add_argument("--json", metavar="FILE",
                   help="Write results as JSON to FILE.")
    p.add_argument("--csv", metavar="FILE",
                   help="Write results as CSV to FILE.")
    p.add_argument("--no-color", action="store_true",
                   help="Disable ANSI colour output.")
    p.add_argument("--only-vulnerable", action="store_true",
                   help="Print only CRITICAL and HIGH findings.")
    p.add_argument("--timeout", metavar="SEC", type=int, default=8,
                   help="HTTP request timeout in seconds (default: 8).")
    p.add_argument("--providers", action="store_true",
                   help="List all built-in provider fingerprints and exit.")
    return p


def list_providers():
    print(c("\nBuilt-in Provider Fingerprints", BOLD + WHITE))
    print(c("-" * 80, DIM))
    fmt = f"  {{:<25}} {{:<35}} {{}}"
    print(c(fmt.format("PROVIDER", "CNAME PATTERN(S)", "HTTP FINGERPRINT"), BOLD))
    print(c("-" * 80, DIM))
    for prov in PROVIDERS:
        patterns = ", ".join(prov.cname_patterns[:2])
        print(fmt.format(prov.name[:24], patterns[:34], prov.http_fingerprint[:45]))
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    global USE_COLOR, _HTTP_TIMEOUT

    parser = build_parser()
    args = parser.parse_args()

    if args.providers:
        list_providers()
        sys.exit(0)

    if args.no_color:
        USE_COLOR = False

    if args.timeout:
        _HTTP_TIMEOUT = args.timeout

    if not args.domain and not args.list:
        parser.error("Specify --domain or --list (or both).")

    targets = build_targets(args)
    if not targets:
        print(c("[!] No targets found. Check --domain / --list / --wordlist.", YELLOW),
              file=sys.stderr)
        sys.exit(2)

    print(c(f"\n[*] Subdomain Takeover Scanner", BOLD + CYAN))
    print(c(f"[*] Targets  : {len(targets)}", CYAN))
    print(c(f"[*] Workers  : {args.workers}", CYAN))
    print(c(f"[*] Providers: {len(PROVIDERS)} fingerprints loaded", CYAN))

    _init_progress(len(targets))
    results: List[ScanResult] = []
    results_lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        future_map = {pool.submit(scan_subdomain, t): t for t in targets}
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

    # Sort: CRITICAL first, then HIGH, MEDIUM, INFO, SAFE
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
        print(c(f"[!] {len(critical_high)} CRITICAL/HIGH finding(s) detected. "
                "Exit code 1.", RED + BOLD))
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
