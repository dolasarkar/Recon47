# Recon47

**Recon47** is a Python-based CLI tool for automated web reconnaissance and vulnerability scanning. It runs multiple intelligence-gathering modules against a target domain and produces a structured report.

---

## Features

| Module | What it does |
|--------|-------------|
| **DNS** | Queries A, AAAA, MX, NS, TXT, CNAME, SOA records; optional subdomain brute-force |
| **HTTP** | Analyses response status, server headers, security headers, cookies, and redirect chains |
| **Port Scan** | Threaded TCP connect scan across 26 common ports with banner grabbing |
| **SSL/TLS** | Inspects certificate expiry, subject/issuer, SANs, protocol version, and cipher suite |
| **Tech Detect** | Fingerprints web server, language, CMS, framework, CDN, and WAF from headers and body |
| **Vulnerability** | Probes sensitive paths (`.env`, `.git`, phpinfo, Swagger, etc.), CORS, clickjacking, open redirect |

---

## Installation

### From source

```bash
git clone https://github.com/dolasarkar/Recon47.git
cd Recon47
pip install .
```

### Development mode

```bash
pip install -e .
```

### Requirements

- Python 3.8+
- Dependencies are declared in `pyproject.toml` and `requirements.txt`:
  - `click` — CLI framework
  - `requests` — HTTP client
  - `dnspython` — DNS resolver
  - `colorama` — Coloured terminal output
  - `urllib3` — HTTP utilities

---

## Usage

### Full scan (all modules)

```bash
recon47 scan example.com
```

### Selective modules

```bash
recon47 scan example.com --modules dns,http,ssl
```

### Skip subdomain brute-force

```bash
recon47 scan example.com --no-bruteforce
```

### Custom port list

```bash
recon47 scan example.com --ports 80,443,8080,8443
```

### Save a JSON report

```bash
recon47 scan example.com --output report
# writes report.json
```

### Save a plain-text report

```bash
recon47 scan example.com --output report --format txt
# writes report.txt
```

### List available modules

```bash
recon47 modules
```

### Show version

```bash
recon47 --version
```

---

## Example output

```
  ____                      _  _  _____  ____
 |  _ \ ___  ___ ___  _ __ | || ||___  ||___  |
 ...

[*] Target   : example.com
[*] Modules  : all

──────────────────────────────────────────────────────────────
  DNS Reconnaissance
──────────────────────────────────────────────────────────────
[+] A      → 93.184.216.34
[+] MX     → 0 .
[+] NS     → a.iana-servers.net., b.iana-servers.net.
[*] Probing 50 common subdomains…
[+]   Subdomain found: www.example.com → 93.184.216.34

──────────────────────────────────────────────────────────────
  HTTP Reconnaissance
──────────────────────────────────────────────────────────────
[+] Status code : 200
[*] Server      : ECS (dcb/7F37)
[+]   ✔ Cache-Control
[!]   ✘ Missing: Strict-Transport-Security
...

──────────────────────────────────────────────────────────────
  SSL/TLS Certificate Inspection
──────────────────────────────────────────────────────────────
[*] Protocol    : TLSv1.3
[*] Cipher      : TLS_AES_256_GCM_SHA384 (256 bits)
[*] Common Name : www.example.com
[+] Certificate valid for 312 more day(s)

[+] Scan complete.
```

---

## Project structure

```
recon47/
├── cli.py                  # Click CLI entry point
├── scanner.py              # Orchestrator — runs all modules
├── modules/
│   ├── dns_recon.py        # DNS enumeration
│   ├── http_recon.py       # HTTP header analysis
│   ├── port_scan.py        # TCP port scanning
│   ├── ssl_check.py        # SSL/TLS certificate inspection
│   ├── tech_detect.py      # Technology fingerprinting
│   └── vuln_check.py       # Vulnerability / misconfiguration checks
└── utils/
    └── output.py           # Coloured output + report generation
tests/
├── test_cli.py
├── test_dns_recon.py
├── test_http_recon.py
├── test_port_scan.py
├── test_scanner.py
├── test_ssl_check.py
├── test_tech_detect.py
├── test_vuln_check.py
└── test_output.py
```

---

## Running tests

```bash
pip install pytest
pytest
```

---

## Disclaimer

Recon47 is intended for authorised security assessments and educational purposes only.  
**Do not scan systems you do not own or have explicit permission to test.**
