# subdomain-takeover-scanner

A comprehensive, concurrent **subdomain takeover vulnerability scanner** written in pure Python 3 (stdlib only).  
Checks 35+ provider fingerprints, detects dangling CNAMEs, and classifies findings by severity.

> **Legal Disclaimer:** This tool is intended for authorized security assessments, bug bounty programs, and educational use only. Never use it against systems you do not own or have explicit written permission to test. The author accepts no liability for misuse.

---

## What Is Subdomain Takeover?

A **subdomain takeover** occurs when a DNS record (typically a CNAME) points to a third-party service (e.g. GitHub Pages, Heroku, AWS S3) whose account or resource has been deleted or never created — leaving the subdomain "dangling". An attacker can register that resource and serve arbitrary content from your subdomain.

### Impact

| Scenario | Risk |
|---|---|
| Full control of `shop.victim.com` | Phishing, credential harvesting |
| Cookie scope hijack | Session theft (cookies scoped to `*.victim.com`) |
| CSP / SRI bypass | Load attacker JS from trusted subdomain |
| Email spoofing | Send mail from the trusted domain |
| Reputation damage | Defacement, malware hosting |

### Further Reading
- [EdOverflow — can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) — the canonical reference for provider fingerprints
- [HackerOne — Subdomain Takeover](https://www.hackerone.com/blog/Guide-Subdomain-Takeovers)
- [OWASP Testing Guide — Subdomain Takeover](https://owasp.org/www-project-web-security-testing-guide/)

---

## Features

- **35+ provider fingerprints** (AWS S3, GitHub Pages, Heroku, Netlify, Azure, Vercel, …)
- **NXDOMAIN detection** — dangling CNAME + NXDOMAIN = CRITICAL
- **Concurrent scanning** — ThreadPoolExecutor, configurable worker count (default 20)
- **Severity classification** — CRITICAL / HIGH / MEDIUM / INFO / SAFE
- **Coloured terminal output** with progress bar
- **JSON and CSV export**
- **stdlib only** — no external dependencies required
- Optional `dnspython` for more reliable CNAME resolution (auto-detected)

---

## Supported Provider Fingerprints

| # | Provider | CNAME Pattern(s) | HTTP Fingerprint |
|---|---|---|---|
| 1 | AWS S3 | `s3.amazonaws.com`, `s3-website` | `NoSuchBucket` |
| 2 | GitHub Pages | `github.io`, `github.com` | `There isn't a GitHub Pages site here` |
| 3 | Heroku | `herokuapp.com`, `herokussl.com` | `No such app` |
| 4 | Netlify | `netlify.app`, `netlify.com` | `Not Found` |
| 5 | Shopify | `myshopify.com` | `Sorry, this shop is currently unavailable` |
| 6 | Tumblr | `tumblr.com` | `There's nothing here` |
| 7 | Fastly | `fastly.net` | `Fastly error: unknown domain` |
| 8 | Azure Web Apps | `azurewebsites.net` | `404 Web Site not found` |
| 9 | Azure Traffic Manager | `trafficmanager.net` | `404 Not Found` |
| 10 | Azure Cloud Services | `cloudapp.net`, `cloudapp.azure.com` | `404 - Web app not found` |
| 11 | Zendesk | `zendesk.com` | `Help Center Closed` |
| 12 | Acquia | `acquia-sites.com` | `Web Site Not Configured` |
| 13 | Campaign Monitor | `createsend.com`, `cmail1.com` | `Double check the URL` |
| 14 | Ghost | `ghost.io` | `The thing you were looking for is no longer here` |
| 15 | Pantheon | `pantheonsite.io`, `panth.io` | `The gods are wise, but do not know of the site` |
| 16 | ReadMe.io | `readme.io`, `readmessl.com` | `Project doesnt exist` |
| 17 | SmugMug | `smugmug.com` | `Page Not Found` |
| 18 | Squarespace | `squarespace.com` | `No Such Account` |
| 19 | StatusPage | `statuspage.io` | `page not found` |
| 20 | Surge.sh | `surge.sh` | `project not found` |
| 21 | WordPress.com | `wordpress.com`, `wp.com` | `Do you want to register` |
| 22 | Unbounce | `unbounce.com` | `The requested URL was not found` |
| 23 | Desk.com / Salesforce | `desk.com` | `Sorry, we couldn't find your desk.com site` |
| 24 | UserVoice | `uservoice.com` | `This UserVoice subdomain is currently available` |
| 25 | Intercom | `intercom.help` | `This page doesn't exist` |
| 26 | Webflow | `webflow.io` | `The page you are looking for doesn't exist` |
| 27 | Strikingly | `strikingly.com` | `But if you're looking to build your own website` |
| 28 | Tilda | `tilda.ws` | `Please renew your subscription` |
| 29 | HubSpot | `hs-sites.com`, `hubspotpagebuilder.com` | `Domain not configured` |
| 30 | JetBrains Space | `jetbrains.space` | `Page Not Found` |
| 31 | Vercel | `vercel.app`, `now.sh` | `The deployment could not be found` |
| 32 | Render | `onrender.com` | `Service Not Found` |
| 33 | Fly.io | `fly.dev`, `fly.io` | `404: Not Found` |
| 34 | Cargo Collective | `cargocollective.com` | `404 Not Found` |
| 35 | Agile CRM | `agilecrm.com` | `Sorry, this page is no longer available` |

---

## Installation

```bash
git clone https://github.com/G4MEOVER18/subdomain-takeover-scanner.git
cd subdomain-takeover-scanner

# No external dependencies required (stdlib only).
# Optional: install dnspython for better CNAME resolution:
pip install dnspython
```

---

## Usage

### Enumerate subdomains from a wordlist

```bash
python takeover.py --domain example.com --wordlist wordlist.txt
```

### Scan a pre-built list of hostnames

```bash
python takeover.py --list subdomains.txt
```

### Export results

```bash
python takeover.py --domain example.com --wordlist wordlist.txt \
  --json results.json \
  --csv  results.csv
```

### Show only critical/high findings (CI mode)

```bash
python takeover.py --list targets.txt --only-vulnerable
```

### Increase concurrency

```bash
python takeover.py --domain bigcorp.com --wordlist wordlist.txt --workers 50
```

### List all built-in provider fingerprints

```bash
python takeover.py --providers
```

### Full options

```
usage: takeover.py [-h] [--domain DOMAIN] [--wordlist FILE] [--list FILE]
                   [--workers N] [--json FILE] [--csv FILE] [--no-color]
                   [--only-vulnerable] [--timeout SEC] [--providers]

  --domain,    -d  Base domain (combine with --wordlist for enumeration)
  --wordlist,  -w  Wordlist file (one prefix per line)
  --list,      -l  File with full hostnames (one per line)
  --workers,   -t  Concurrent threads (default: 20)
  --json           Write JSON report to FILE
  --csv            Write CSV report to FILE
  --no-color       Disable ANSI colour output
  --only-vulnerable  Print only CRITICAL and HIGH findings
  --timeout        HTTP timeout in seconds (default: 8)
  --providers      Print provider fingerprint table and exit
```

---

## Severity Levels

| Severity | Meaning | Action |
|---|---|---|
| **CRITICAL** | Dangling CNAME + NXDOMAIN. The subdomain almost certainly can be claimed immediately. | Claim the resource NOW or remove the DNS record. |
| **HIGH** | HTTP fingerprint matched — service is configured to respond with "not found" message for unclaimed slot. | High confidence takeover possible. Claim or remove. |
| **MEDIUM** | CNAME points to a known provider but fingerprint not confirmed (may be protected or temporarily down). | Manual verification recommended. |
| **INFO** | DNS resolution failed, no CNAME, or NXDOMAIN without a dangling CNAME. | Low risk. |
| **SAFE** | Resolved to an IP, no known provider detected. | No action needed. |

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan completed, no CRITICAL or HIGH findings |
| `1` | At least one CRITICAL or HIGH finding detected |
| `2` | Usage error or file not found |

---

## CI/CD Integration

```yaml
# .github/workflows/takeover-check.yml
name: Subdomain Takeover Check

on:
  schedule:
    - cron: "0 6 * * 1"   # Every Monday at 06:00 UTC
  push:
    branches: [main]

jobs:
  takeover:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Run scanner
        run: |
          python takeover.py \
            --domain ${{ vars.TARGET_DOMAIN }} \
            --wordlist wordlist.txt \
            --only-vulnerable \
            --json results.json
        # Exit code 1 → CI fails when CRITICAL/HIGH found

      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: takeover-results
          path: results.json
```

---

## Donations

If this tool saved you time or helped you find a real bug, consider a donation:

**Bitcoin:** `39vZWmnUwDReQ15BwqQXzyqVQ6U8LardEf`

---

## License

MIT License — Copyright (c) 2026 G4MEOVER18

See [LICENSE](LICENSE) for full terms.
