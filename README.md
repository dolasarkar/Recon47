# Recon47

Recon47 is a one-command, modular web reconnaissance and vulnerability scanning tool for bug bounty hunters, junior pentesters, security students, and SOC/red-teamers who need quick, repeatable recon workflows.

## 1. Vision & Scope

- Takes a single target (domain, subdomain, IP, or URL) as input  
- Automatically performs recon (DNS, subdomains, ports, tech stack, headers, JS, parameters)  
- Crawls and collects endpoints  
- Integrates Nikto and Nuclei for vulnerability scanning  
- Outputs structured findings in:
  - A modern, colorized CLI view  
  - A hacker-themed HTML report (dark, neon, terminal style)  

## 2. High-Level Features

### Input Handling

- Accepts:
  - Domain (example.com)
  - Subdomain (api.example.com)
  - Full URL (https://app.example.com/login)
  - IP address (192.168.1.10)
- Normalizes input (extract scheme, host, port, path)

### Reconnaissance

- DNS info: A, AAAA, CNAME, MX, NS, TXT (via `dnspython`)
- Subdomain discovery:
  - Passive wordlist brute force (DNS resolve + HTTP probe)
  - Optional custom wordlist from user
- Port scanning (lightweight):
  - TCP connect scan on common web ports (80, 443, 8080, 8443, 8000, 81)
- HTTP fingerprinting:
  - Server banner, status code, redirects, response length
  - HTTP headers extraction
- Technology detection:
  - Wappalyzer-like approach (python-Wappalyzer or header/body pattern matching)
- JS and assets:
  - Parse HTML for `<script src>`, `<link>`, etc.
  - Save JS and static asset URLs
- Parameters & forms:
  - Query parameters from URLs
  - HTML forms (action, method, inputs)
- Interesting endpoints:
  - From crawling (e.g. `/admin`, `/login`, `/api`, `/upload`)
  - Simple keyword-based heuristics

### Crawler

- Single-domain crawler (requests + BeautifulSoup)
- BFS/queue-based crawling
- Depth limit (default: 2–3)
- Smart URL deduplication (normalize, strip fragments, sort query params)
- Optional recursion controls:
  - Max pages
  - Rate limiting
  - Same-origin constraint

### Vulnerability Scanning

- **Nikto integration**
  - Call external `nikto` binary via `subprocess`
  - Target primary host/port
  - Parse JSON/text output into structured findings
- **Nuclei integration**
  - Run `nuclei` on collected URLs
  - Support default or custom template paths
  - Parse JSON output into findings
- **Custom mini-checks**
  - HTTP security headers (X-Frame-Options, CSP, HSTS, etc.)
  - Simple misconfig detection (default pages, dummy creds in JS, etc.)

### Reporting

- Central `ScanResult` model containing:
  - Target info & metadata
  - Recon results
  - Crawled endpoints
  - Technologies
  - Vulnerability findings (Nikto, Nuclei, custom)
  - Severity classification (info/low/medium/high/critical)
  - Timestamps (start/end)
- **Console output**
  - Modern layout using Rich/Colorama
  - Sections: Recon, Crawler, Vulns, Summary
- **HTML report**
  - Single-page, dark hacker theme (neon green/cyan, monospace)
  - Sections:
    - Overview / Target profile
    - Recon details (DNS, ports, subdomains)
    - Endpoints and parameters
    - Technology fingerprint
    - Vulnerabilities grouped by severity
  - File name: `recon47_report_<hostname>_<timestamp>.html`
- Optional “Executive Summary”:
  - Counts per severity and main risk areas

### Stealth & Performance

- Rate limiting and HTTP timeouts
- Optional random delay
- User-configurable:
  - `--max-requests-per-second`
  - `--timeout`

## 3. CLI Design

### Basic Usage

```bash
python3 recon47.py -t <target> [options]
```

Examples:

```bash
python3 recon47.py -t https://example.com
python3 recon47.py -t example.com --no-nikto --no-nuclei
python3 recon47.py -t 192.168.1.10 --depth 3 --output-dir reports
```

### Core Options

- Target:
  - `-t`, `--target` (required)
- Recon control:
  - `--no-subdomains`, `--no-dns`, `--no-portscan`
- Crawler:
  - `-d`, `--depth` (default 2)
  - `--max-pages` (default 100)
- Scanners:
  - `--nikto`, `--no-nikto`
  - `--nuclei`, `--no-nuclei`
  - `--nuclei-templates` (custom templates path)
- Output:
  - `-o`, `--output-dir` (default `./reports`)
  - `--no-html-report`
  - `--json` (machine-readable output)
- Performance:
  - `--threads`
  - `--rate-limit`
  - `--timeout`
- Misc:
  - `--version`
  - `--author` (shows 0xDO1d)
  - `--banner` (ASCII art)

## 4. Architecture
recon47/
recon47/
_init_.py
cli.py
core/
config.py
logger.py
models.py
recon/
resolver.py
subdomains.py
ports.py
http_finger.py
tech_detect.py
crawler.py
extractor.py
scanners/
nikto.py
nuclei.py
custom_checks.py
reporting/
console.py
html_report.py
json_export.py
utils/
url_utils.py
file_utils.py
time_utils.py
setup.py
requirements.txt
README.md
LICENSE
examples/
sample_target.txt
templates/
base_report.html
css/
hacker.css

- `cli.py` orchestrates:
  - Parse args → validate target → build config  
  - Run recon → crawl/extract → scanners → aggregate into `ScanResult`  
  - Output to console + HTML  

## 5. Data Models (Conceptual)

- `TargetInfo`: scheme, host, port, path, is_ip  
- `ReconResult`: DNS records, subdomains, ports, headers, server banner, tech stack, JS, assets  
- `CrawlResult`: endpoints with URL, status code, content type, params, forms  
- `VulnFinding`: id, title, description, severity, tool, reference, endpoint, timestamp  
- `ScanResult`: target_info, recon_result, crawl_result, vuln_findings, summary, started_at, finished_at  

## 6. Workflow

1. User runs: `python3 recon47.py -t https://example.com`
2. Tool prints banner and start time
3. Recon phase:
   - DNS, subdomains, ports
4. Crawling phase:
   - Queued/fetched URLs, interesting paths
5. Scanning phase:
   - Nikto, Nuclei, custom checks
   - Graceful handling if tools not found
6. Summary:
   - Recon stats, endpoint count, vuln breakdown, HTML report path

## 7. Error Handling & Reliability

- Argument validation (missing/invalid targets)
- Graceful handling when `nikto` / `nuclei` not in PATH
- Network errors:
  - Timeouts, DNS failures, SSL errors
- Robust JSON parsing with fallbacks
- Try/except around major stages
- HTML report generation even with partial data

## 8. Performance & Extras

- Multithreaded crawler and subdomain brute (ThreadPoolExecutor)
- URL deduplication and filtering (skip non-HTML where appropriate)
- Optional Dockerfile:
  - `python:3.11-slim` base
  - Install dependencies + nikto + nuclei
- Future optional GUI (Flask/Streamlit) using JSON reports

## 9. Security & Ethics

- Single target per run
- Light, safe recon by default
- No destructive HTTP methods or exploit payloads
- Startup disclaimer: use only on authorized targets
- Sensible default rate limits

## 10. Setup & Installation

### Requirements

- Python 3.9+ (recommended 3.10/3.11)

`requirements.txt` (core):

- `requests`
- `beautifulsoup4`
- `dnspython`
- `tldextract`
- `rich`
- `jinja2`
- `pyyaml` (optional for config)

### Packaging

`setup.py` will:

- Install the `recon47` package  
- Register a console script: `recon47` → `recon47.cli:main`  
- Allow usage via:

```bash
pip install .
recon47 -t https://example.com
```

### External Tools

- **Nikto**: install and ensure `nikto` is in `PATH`
- **Nuclei**: install and ensure `nuclei` + templates directory are available

---

> ⚠️ Use Recon47 only on targets you are explicitly authorized to test.
