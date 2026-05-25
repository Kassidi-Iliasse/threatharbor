# vuln-scanner

A small command-line web vulnerability scanner. Given a target URL, it runs
a handful of OWASP-style checks (security headers, cookie flags, redirect
behavior, form posture, optional reflected-XSS probe) and produces a
self-contained HTML report.

This is a learning / portfolio project — not a replacement for a real
scanner like ZAP or Burp.

---

## Installation

Python 3.10+ is required.

```bash
pip install -r requirements.txt
```

---

## Usage

Basic scan:

```bash
python main.py --url https://example.com
```

Custom report path:

```bash
python main.py --url https://example.com --output reports/example.html
```

Verbose (log each finding as it's produced):

```bash
python main.py --url https://example.com --verbose
```

Enable active checks (currently: reflected-XSS probe that submits forms).
Only run this against targets you are explicitly authorized to test.

```bash
python main.py --url http://testphp.vulnweb.com --unsafe
```

Tighter timeout (default is 5s, capped at 10s):

```bash
python main.py --url https://example.com --timeout 3
```

The CLI prints a one-line summary and writes an HTML file at the path
given by `--output` (default `report.html`). Exit code is `1` when any
High-severity findings were produced, `0` otherwise, `2` if the target
could not be fetched at all.

---

## What the report looks like

* Target URL and timestamp at the top.
* Four-cell summary grid: High / Medium / Low / Info totals.
* Each finding shown as a card with a colored severity badge:
  red (High), orange (Medium), yellow (Low), gray (Info), followed
  by a description and the raw evidence inside a `<code>` block.
* Fully self-contained: no external CSS or JS, no internet required to view.

---

## Checks implemented

| Module | What it does |
| --- | --- |
| `checks/headers.py` | Flags missing `X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`, `Strict-Transport-Security`, `Referrer-Policy`; reports leaky `Server` / `X-Powered-By`. |
| `checks/cookies.py` | Inspects each `Set-Cookie`; flags missing `HttpOnly`, `Secure`, `SameSite`. |
| `checks/redirects.py` | If you scanned an `http://` URL, checks whether it upgrades to HTTPS; also flags cross-host redirects (potential open-redirect). |
| `checks/forms.py` | Lists every `<form>`; flags HTTP submission targets and POST forms with no plausible CSRF token (Info, heuristic). |
| `checks/xss.py` | **Active.** Submits a probe payload through each text input and looks for raw, unescaped reflection in the response body. Only runs with `--unsafe`. |

---

## Honest limitations

* The XSS check matches raw reflection of angle brackets only. It will
  miss real XSS in attribute, JS, or URL contexts, and will not detect
  stored / DOM XSS.
* The CSRF check is a name-based heuristic and is reported as Info — many
  sites use cookie-based or header-based protection that this won't see.
* No authentication, no crawling, no JavaScript rendering. One page,
  one pass.

---

## Architecture

```
vulnerability_scanner/
├── main.py            # CLI: argparse, runs scanner, calls reporter
├── scanner.py         # Finding dataclass, ScanResult, run_scan()
├── reporter.py        # Renders ScanResult to HTML via Jinja2
├── checks/
│   ├── headers.py
│   ├── cookies.py
│   ├── redirects.py
│   ├── forms.py
│   └── xss.py
├── templates/
│   └── report.html    # Self-contained Jinja2 template
├── requirements.txt
└── README.md
```

* `scanner.run_scan` fetches the target once and hands the response to
  each check module, collecting `Finding`s. Per-check exceptions are
  caught and surfaced as warnings — one broken check never aborts a scan.
* Each check module exposes a single `run(url, response, session)` function
  so adding a new check is a matter of dropping a file into `checks/` and
  registering it in `scanner.run_scan`.

---

## Testing targets

* `http://testphp.vulnweb.com` — intentionally vulnerable, safe to scan.
* DVWA in Docker, on `http://localhost`.

**Do not scan systems you do not own or have written authorization to
test.** This tool exists for learning and authorized security review.
