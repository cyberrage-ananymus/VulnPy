# 🔒 VulnPy

**Professional Vulnerability Scanner for Security Professionals**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-brightgreen.svg)](https://github.com/cyberrage-ananymus/VulnPy)

---

## Features

- 🔍 **Port Scanning** - Advanced port scanning with service detection and banner grabbing
- 🛡️ **SQL Injection** - Error-based, Blind Boolean, and Time-based SQLi detection
- ⚡ **XSS Detection** - Reflected and DOM-based Cross-Site Scripting detection
- 📁 **Directory Traversal** - Path traversal and LFI detection
- 🔐 **SSL/TLS Analysis** - Certificate validation, protocol and cipher analysis
- 🔑 **Weak Credentials** - Default/weak password testing with wordlists
- 📊 **CVE Matching** - 30+ known vulnerabilities database (Apache, Nginx, OpenSSH, PHP, etc.)
- 🕷️ **Auto Crawler** - Automatic URL, form, and parameter discovery
- 📄 **Professional Reports** - HTML, JSON, CSV report generation with cyberpunk design

## Installation

```bash
# Clone the repository
git clone https://github.com/cyberrage-ananymus/VulnPy.git

# Navigate to directory
cd VulnPy

# Install dependencies
pip install -r requirements.txt

# Install VulnPy
pip install -e .

# Verify installation
vulnpy version
```

## Usage

```bash
# Basic scan
vulnpy scan 192.168.1.1

# Scan with specific ports
vulnpy scan example.com --ports 80,443,8080

# Run specific scanner
vulnpy scan target.com --scanner sqli --scanner xss

# Generate HTML report
vulnpy scan target.com --output report.html --format html

# Generate JSON report
vulnpy scan target.com --output results.json --format json

# Generate CSV report
vulnpy scan target.com --output results.csv --format csv

# Verbose mode
vulnpy scan target.com --verbose

# List all scanners
vulnpy list-scanners

# Show version
vulnpy version
```

## Available Scanners

| Scanner | Description | Severity |
|---------|-------------|----------|
| `port_scan` | Scan open ports and detect services | Info |
| `sqli` | SQL Injection (Error/Blind/Time-based) | Critical |
| `xss` | Cross-Site Scripting (Reflected/DOM) | High |
| `traversal` | Directory Traversal / LFI | High |
| `ssl_check` | SSL/TLS configuration analysis | Medium |
| `weak_cred` | Weak/default credential testing | Critical |
| `cve_match` | CVE database matching | Varies |
| `crawler` | Auto-discover URLs and forms | Info |

## Report Formats

| Format | Description | Best For |
|--------|-------------|----------|
| **HTML** | Beautiful cyberpunk-themed reports with animations | Sharing, Presentation |
| **JSON** | Machine-readable structured output | Automation, Integration |
| **CSV** | Spreadsheet compatible format | Analysis, Excel |

## CVE Database

VulnPy includes 30+ known vulnerabilities for:

- Apache HTTP Server
- Nginx
- OpenSSH
- MySQL / PostgreSQL
- PHP
- IIS / Tomcat
- WordPress
- Django / Spring
- ProFTPD / vsftpd

## Project Structure

```
VulnPy/
├── vulnpy/
│   ├── cli.py              # CLI interface (typer)
│   ├── core/
│   │   ├── scanner.py      # Core scanning engine
│   │   ├── report.py       # Report generator
│   │   ├── database.py     # CVE database
│   │   └── target.py       # Target parser
│   ├── scanners/
│   │   ├── base.py         # Base scanner class
│   │   ├── port_scan.py    # Port scanner
│   │   ├── sqli.py         # SQL injection
│   │   ├── xss.py          # XSS detection
│   │   ├── traversal.py    # Directory traversal
│   │   ├── ssl_check.py    # SSL/TLS checker
│   │   ├── weak_cred.py    # Weak credentials
│   │   ├── cve_match.py    # CVE matcher
│   │   └── crawler.py      # Auto crawler
│   └── utils/
│       ├── logger.py       # Logging
│       └── network.py      # Network utilities
├── templates/
│   └── report.html         # HTML report template
├── wordlists/
│   ├── common_passwords.txt
│   └── common_users.txt
├── tests/
│   └── test_scanner.py
├── requirements.txt
├── setup.py
└── README.md
```

## Community

Join our community for support, updates, and discussions:

- 🔗 [LinkedIn](https://www.linkedin.com/in/cyber-rage-green-eyes-801656416?utm_source=share_via&utm_content=profile&utm_medium=member_android)
- 💬 [Discord - Cyebr-Rage](https://discord.gg/9KhfPTqTg)
- 📱 Session: `05fd51ac639edc257133f9364529eff3af1d69c5c18b31f321ba466b3823a0a805`

## Author

**Cyebr-Rage** - Security Researcher & Developer

[![GitHub](https://img.shields.io/badge/GitHub-cyberrage--ananymus-181717?style=flat&logo=github)](https://github.com/cyberrage-ananymus)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

⚠️ **This tool is for authorized security testing only.** Always obtain proper authorization before scanning systems you do not own. The authors are not responsible for any misuse of this software.

---

<p align="center">Built with ❤️ by <a href="https://github.com/cyberrage-ananymus">Cyebr-Rage</a></p>
