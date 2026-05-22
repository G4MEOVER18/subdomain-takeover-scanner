# subdomain-takeover-scanner

Ein umfassender, parallelisierter **Subdomain-Takeover-Scanner** in reinem Python 3 — keine externen Abhängigkeiten nötig.  
Prüft über 35 Provider-Fingerprints, erkennt hängende CNAMEs und stuft Befunde nach Schweregrad ein.

> **Rechtlicher Hinweis:** Dieses Tool ist ausschließlich für autorisierte Sicherheitsanalysen, Bug-Bounty-Programme und Bildungszwecke gedacht. Niemals gegen Systeme einsetzen, für die keine ausdrückliche schriftliche Genehmigung vorliegt. Der Autor übernimmt keine Haftung für Missbrauch.

---

## Was ist ein Subdomain Takeover?

Ein **Subdomain Takeover** tritt auf, wenn ein DNS-Eintrag (typischerweise ein CNAME) auf einen Drittanbieter-Dienst zeigt (z. B. GitHub Pages, Heroku, AWS S3), dessen Account oder Ressource gelöscht wurde oder nie existiert hat — die Subdomain "hängt" damit ins Leere. Ein Angreifer kann diese Ressource registrieren und beliebige Inhalte über die betroffene Subdomain ausliefern.

### Mögliche Auswirkungen

| Szenario | Risiko |
|---|---|
| Vollständige Kontrolle über `shop.opfer.com` | Phishing, Credential Harvesting |
| Cookie-Scope-Hijacking | Session-Diebstahl (Cookies mit `*.opfer.com`-Scope) |
| CSP / SRI umgehen | Angreifer-JS von vertrauenswürdiger Subdomain nachladen |
| E-Mail-Spoofing | Mails von der vertrauenswürdigen Domain versenden |
| Reputationsschaden | Defacement, Malware-Hosting |

### Weiterführende Quellen
- [EdOverflow — can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) — die Referenzliste für Provider-Fingerprints
- [HackerOne — Subdomain Takeover](https://www.hackerone.com/blog/Guide-Subdomain-Takeovers)
- [OWASP Testing Guide — Subdomain Takeover](https://owasp.org/www-project-web-security-testing-guide/)

---

## Features

- **35+ Provider-Fingerprints** (AWS S3, GitHub Pages, Heroku, Netlify, Azure, Vercel, …)
- **NXDOMAIN-Erkennung** — hängender CNAME + NXDOMAIN = CRITICAL
- **Paralleles Scanning** — ThreadPoolExecutor, einstellbare Worker-Anzahl (Standard: 20)
- **Schweregrad-Klassifizierung** — CRITICAL / HIGH / MEDIUM / INFO / SAFE
- **Farbige Terminalausgabe** mit Fortschrittsbalken
- **JSON- und CSV-Export**
- **Nur stdlib** — keine externen Abhängigkeiten
- Optional `dnspython` für zuverlässigere CNAME-Auflösung (wird automatisch erkannt)

---

## Unterstützte Provider-Fingerprints

| # | Provider | CNAME-Pattern(s) | HTTP-Fingerprint |
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

# Keine externen Abhängigkeiten nötig (stdlib only).
# Optional: dnspython für bessere CNAME-Auflösung installieren:
pip install dnspython
```

---

## Verwendung

### Subdomains aus einer Wordlist enumerieren

```bash
python takeover.py --domain example.com --wordlist wordlist.txt
```

### Fertige Hostname-Liste scannen

```bash
python takeover.py --list subdomains.txt
```

### Ergebnisse exportieren

```bash
python takeover.py --domain example.com --wordlist wordlist.txt \
  --json results.json \
  --csv  results.csv
```

### Nur kritische/hohe Befunde anzeigen (CI-Modus)

```bash
python takeover.py --list targets.txt --only-vulnerable
```

### Parallelität erhöhen

```bash
python takeover.py --domain bigcorp.com --wordlist wordlist.txt --workers 50
```

### Alle integrierten Provider-Fingerprints auflisten

```bash
python takeover.py --providers
```

### Alle Optionen

```
usage: takeover.py [-h] [--domain DOMAIN] [--wordlist FILE] [--list FILE]
                   [--workers N] [--json FILE] [--csv FILE] [--no-color]
                   [--only-vulnerable] [--timeout SEC] [--providers]

  --domain,    -d  Basis-Domain (kombiniert mit --wordlist für Enumeration)
  --wordlist,  -w  Wordlist-Datei (ein Prefix pro Zeile)
  --list,      -l  Datei mit vollständigen Hostnamen (ein pro Zeile)
  --workers,   -t  Parallele Threads (Standard: 20)
  --json           JSON-Report in FILE schreiben
  --csv            CSV-Report in FILE schreiben
  --no-color       ANSI-Farbausgabe deaktivieren
  --only-vulnerable  Nur CRITICAL- und HIGH-Befunde ausgeben
  --timeout        HTTP-Timeout in Sekunden (Standard: 8)
  --providers      Provider-Fingerprint-Tabelle ausgeben und beenden
```

---

## Schweregrade

| Schweregrad | Bedeutung | Empfohlene Maßnahme |
|---|---|---|
| **CRITICAL** | Hängender CNAME + NXDOMAIN — die Subdomain kann mit hoher Wahrscheinlichkeit sofort übernommen werden. | Ressource jetzt registrieren oder DNS-Eintrag entfernen. |
| **HIGH** | HTTP-Fingerprint erkannt — Dienst antwortet mit "nicht gefunden"-Meldung für unbeanspruchten Slot. | Übernahme wahrscheinlich möglich. Registrieren oder entfernen. |
| **MEDIUM** | CNAME zeigt auf bekannten Provider, Fingerprint aber nicht bestätigt (ggf. geschützt oder vorübergehend offline). | Manuelle Überprüfung empfohlen. |
| **INFO** | DNS-Auflösung fehlgeschlagen, kein CNAME, oder NXDOMAIN ohne hängenden CNAME. | Geringes Risiko. |
| **SAFE** | Zu einer IP aufgelöst, kein bekannter Provider erkannt. | Kein Handlungsbedarf. |

---

## Exit-Codes

| Code | Bedeutung |
|---|---|
| `0` | Scan abgeschlossen, keine CRITICAL- oder HIGH-Befunde |
| `1` | Mindestens ein CRITICAL- oder HIGH-Befund gefunden |
| `2` | Nutzungsfehler oder Datei nicht gefunden |

---

## CI/CD-Integration

```yaml
# .github/workflows/takeover-check.yml
name: Subdomain Takeover Check

on:
  schedule:
    - cron: "0 6 * * 1"   # Jeden Montag um 06:00 UTC
  push:
    branches: [main]

jobs:
  takeover:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Python einrichten
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Scanner ausführen
        run: |
          python takeover.py \
            --domain ${{ vars.TARGET_DOMAIN }} \
            --wordlist wordlist.txt \
            --only-vulnerable \
            --json results.json
        # Exit-Code 1 → CI schlägt fehl, wenn CRITICAL/HIGH gefunden

      - name: Ergebnisse hochladen
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: takeover-results
          path: results.json
```

---

## Spenden

Wenn dir das Tool Zeit gespart oder einen echten Bug gebracht hat, freue ich mich über eine kleine Spende:

**Bitcoin:** `39vZWmnUwDReQ15BwqQXzyqVQ6U8LardEf`
**PayPal:** [paypal.me/Freakbank1](https://paypal.me/Freakbank1)

---

## Lizenz

MIT License — Copyright (c) 2026 G4MEOVER18

Vollständige Bedingungen: [LICENSE](LICENSE)
