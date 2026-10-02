# DNSProbe

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![Network](https://img.shields.io/badge/Network-Tool-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

**DNSProbe** is a DNS auditing tool for security professionals and network administrators. Point it at a domain and it queries A, AAAA, MX, TXT, NS, CNAME, SOA and CAA records, formats the answers so they are actually readable (MX priorities, SOA timers, joined TXT strings), and tells you whether the zone looks alive or misconfigured.

---

## Features

- **Multi-record audit**: A, AAAA, MX, TXT, NS, CNAME, SOA and CAA in one run
- **Readable output**: MX preference, SOA timers and long TXT strings are parsed into plain text instead of raw rdata dumps
- **Reverse DNS enrichment**: `--ptr` reverse-resolves every A/AAAA IP to its PTR hostname
- **JSON mode**: `--json` dumps the full result set for piping into other tools
- **Status detection**: flags dead or misconfigured domains when no A/AAAA/MX records exist
- **Rich terminal UI**: color-coded tables and panels via `rich`

---

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/mizazhaider-ceh/DNSProbe.git
   cd DNSProbe
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

```bash
python dnsprobe.py <domain>
```

**Options:**

- `--json`: print results as JSON instead of the rich table
- `--ptr`: reverse-resolve A/AAAA IPs to PTR hostnames
- `--timeout SECONDS`: per-query timeout (default: 5.0)
- `-h, --help`: show help message and exit

**Examples:**

```bash
python dnsprobe.py example.com
python dnsprobe.py example.com --ptr
python dnsprobe.py example.com --json | jq '.mx'
```

---

## Tests

```bash
pip install pytest
python -m pytest tests/ -q
```

The test suite mocks the DNS resolver, so no network access is needed.

---

## Credits

<p align="center">
  <b>Built By:</b> mizazhaider-ceh (Muhammad Izaz Haider)<br>
  <b>Powered by:</b> The PenTrix
</p>

---

*Disclaimer: This tool is for educational and network diagnostic purposes only.*
