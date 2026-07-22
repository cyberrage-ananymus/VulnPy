# VulnPy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use compose:subagent (recommended) or compose:execute to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a professional, modular vulnerability scanner in Python that scans networks and web applications for known vulnerabilities and generates reports in multiple formats.

**Architecture:** Modular plugin-based architecture with a core engine that orchestrates scanners. Each vulnerability type is a separate module. CLI built with typer for clean, fast interface. Reports generated in HTML, JSON, PDF, and CSV formats.

**Tech Stack:** Python 3.8+, typer (CLI), scapy (network), requests (HTTP), jinja2 (templates), reportlab (PDF), python-nmap (port scanning)

---

## File Structure

```
VulnPy/
├── vulnpy/
│   ├── __init__.py
│   ├── cli.py                 # CLI interface with typer
│   ├── core/
│   │   ├── __init__.py
│   │   ├── scanner.py         # Core scanning engine
│   │   ├── report.py          # Report generation (HTML/JSON/PDF/CSV)
│   │   ├── database.py        # CVE database and patterns
│   │   └── target.py          # Target parsing (IP/URL/CIDR)
│   ├── scanners/
│   │   ├── __init__.py
│   │   ├── base.py            # Base scanner class
│   │   ├── port_scan.py       # Port scanning + service detection
│   │   ├── cve_match.py       # CVE matching
│   │   ├── sqli.py            # SQL Injection detection
│   │   ├── xss.py             # XSS detection
│   │   ├── traversal.py       # Directory Traversal
│   │   ├── ssl_check.py       # SSL/TLS validation
│   │   └── weak_cred.py       # Weak credential testing
│   └── utils/
│       ├── __init__.py
│       ├── network.py         # Network utilities
│       └── logger.py          # Logging setup
├── templates/
│   └── report.html            # HTML report template
├── wordlists/
│   ├── common_passwords.txt   # Common passwords for brute force
│   └── common_users.txt       # Common usernames
├── tests/
│   ├── __init__.py
│   ├── test_scanner.py
│   ├── test_target.py
│   └── test_report.py
├── requirements.txt
├── setup.py
├── README.md
└── .gitignore
```

---

## Task 1: Project Setup and Dependencies

**Covers:** [S1]

**Files:**
- Create: `VulnPy/requirements.txt`
- Create: `VulnPy/setup.py`
- Create: `VulnPy/.gitignore`
- Create: `VulnPy/vulnpy/__init__.py`

- [ ] **Step 1: Create requirements.txt**

```
typer[all]>=0.9.0
rich>=13.0.0
requests>=2.31.0
scapy>=2.5.0
python-nmap>=0.7.1
jinja2>=3.1.2
reportlab>=4.0.0
pydantic>=2.0.0
toml>=0.10.2
aiohttp>=3.9.0
```

- [ ] **Step 2: Create setup.py**

```python
from setuptools import setup, find_packages

setup(
    name="vulnpy",
    version="1.0.0",
    description="Professional Vulnerability Scanner",
    packages=find_packages(),
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "vulnpy=vulnpy.cli:app",
        ],
    },
    install_requires=[
        "typer[all]>=0.9.0",
        "rich>=13.0.0",
        "requests>=2.31.0",
        "scapy>=2.5.0",
        "python-nmap>=0.7.1",
        "jinja2>=3.1.2",
        "reportlab>=4.0.0",
        "pydantic>=2.0.0",
    ],
)
```

- [ ] **Step 3: Create .gitignore**

```
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
venv/
.env
*.egg-info/
dist/
build/
.eggs/
*.log
```

- [ ] **Step 4: Create vulnpy/__init__.py**

```python
__version__ = "1.0.0"
__author__ = "VulnPy Team"
```

- [ ] **Step 5: Commit**

```bash
git init && git add -A && git commit -m "feat: project setup with dependencies"
```

---

## Task 2: Logger and Utilities

**Covers:** [S2]

**Files:**
- Create: `VulnPy/vulnpy/utils/logger.py`
- Create: `VulnPy/vulnpy/utils/network.py`
- Create: `VulnPy/vulnpy/utils/__init__.py`

- [ ] **Step 1: Create logger.py**

```python
import logging
import sys
from rich.console import Console
from rich.logging import RichHandler

console = Console()

def setup_logger(verbose: bool = False) -> logging.Logger:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)]
    )
    return logging.getLogger("vulnpy")
```

- [ ] **Step 2: Create network.py**

```python
import socket
import ipaddress
from typing import List, Optional

def resolve_target(target: str) -> Optional[str]:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

def expand_cidr(cidr: str) -> List[str]:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(host) for host in network.hosts()]
    except ValueError:
        return []

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_url(url: str) -> bool:
    return url.startswith(("http://", "https://"))
```

- [ ] **Step 3: Create utils/__init__.py**

```python
from .logger import setup_logger, console
from .network import resolve_target, expand_cidr, is_valid_ip, is_valid_url
```

- [ ] **Step 4: Commit**

```bash
git add vulnpy/utils/ && git commit -m "feat: add logger and network utilities"
```

---

## Task 3: Target Parser

**Covers:** [S3]

**Files:**
- Create: `VulnPy/vulnpy/core/target.py`
- Create: `VulnPy/vulnpy/core/__init__.py`
- Create: `VulnPy/tests/test_target.py`

- [ ] **Step 1: Write failing test**

```python
# tests/test_target.py
import pytest
from vulnpy.core.target import Target, TargetType

def test_parse_ip():
    target = Target.parse("192.168.1.1")
    assert target.type == TargetType.IP
    assert target.value == "192.168.1.1"

def test_parse_url():
    target = Target.parse("https://example.com")
    assert target.type == TargetType.URL
    assert target.value == "https://example.com"

def test_parse_cidr():
    targets = Target.parse_cidr("192.168.1.0/30")
    assert len(targets) == 2
    assert all(t.type == TargetType.IP for t in targets)
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/server/VulnPy && python -m pytest tests/test_target.py -v
```

Expected: FAIL with ImportError

- [ ] **Step 3: Implement target.py**

```python
from enum import Enum
from typing import List
from ..utils.network import is_valid_ip, is_valid_url, expand_cidr, resolve_target

class TargetType(Enum):
    IP = "ip"
    URL = "url"
    DOMAIN = "domain"
    CIDR = "cidr"

class Target:
    def __init__(self, value: str, target_type: TargetType, resolved: str = None):
        self.value = value
        self.type = target_type
        self.resolved = resolved or value

    @classmethod
    def parse(cls, target: str) -> "Target":
        if is_valid_url(target):
            return cls(target, TargetType.URL)
        elif is_valid_ip(target):
            return cls(target, TargetType.IP)
        else:
            resolved = resolve_target(target)
            return cls(target, TargetType.DOMAIN, resolved)

    @classmethod
    def parse_cidr(cls, cidr: str) -> List["Target"]:
        ips = expand_cidr(cidr)
        return [cls(ip, TargetType.IP) for ip in ips]

    def __repr__(self):
        return f"Target({self.value}, {self.type.value})"
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /home/server/VulnPy && python -m pytest tests/test_target.py -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add vulnpy/core/target.py tests/test_target.py && git commit -m "feat: add target parser with IP/URL/CIDR support"
```

---

## Task 4: Base Scanner and Core Engine

**Covers:** [S4, S5]

**Files:**
- Create: `VulnPy/vulnpy/scanners/base.py`
- Create: `VulnPy/vulnpy/core/scanner.py`
- Create: `VulnPy/vulnpy/scanners/__init__.py`

- [ ] **Step 1: Create base scanner class**

```python
# vulnpy/scanners/base.py
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any
from enum import Enum

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    evidence: str = ""
    recommendation: str = ""
    cvss_score: float = 0.0
    cve_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ScanResult:
    scanner_name: str
    target: str
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    scan_time: float = 0.0

class BaseScanner(ABC):
    name: str = "base"
    description: str = ""

    @abstractmethod
    def scan(self, target: str, **kwargs) -> ScanResult:
        pass

    def __repr__(self):
        return f"<{self.__class__.__name__}: {self.name}>"
```

- [ ] **Step 2: Create core scanner engine**

```python
# vulnpy/core/scanner.py
import time
from typing import List, Type
from ..scanners.base import BaseScanner, ScanResult
from ..utils.logger import setup_logger

logger = setup_logger()

class ScanEngine:
    def __init__(self):
        self.scanners: List[BaseScanner] = []

    def register(self, scanner: BaseScanner):
        self.scanners.append(scanner)
        logger.debug(f"Registered scanner: {scanner.name}")

    def get_scanner(self, name: str) -> BaseScanner:
        for s in self.scanners:
            if s.name == name:
                return s
        raise ValueError(f"Scanner '{name}' not found")

    def scan(self, target: str, scanner_names: List[str] = None, **kwargs) -> List[ScanResult]:
        results = []
        scanners_to_run = self.scanners if not scanner_names else [
            self.get_scanner(n) for n in scanner_names
        ]

        for scanner in scanners_to_run:
            start = time.time()
            try:
                result = scanner.scan(target, **kwargs)
                result.scan_time = time.time() - start
                results.append(result)
                logger.info(f"[green]✓[/green] {scanner.name} completed in {result.scan_time:.2f}s")
            except Exception as e:
                logger.error(f"[red]✗[/red] {scanner.name} failed: {e}")
                results.append(ScanResult(
                    scanner_name=scanner.name,
                    target=target,
                    errors=[str(e)]
                ))

        return results

    def list_scanners(self):
        return [(s.name, s.description) for s in self.scanners]
```

- [ ] **Step 3: Create scanners/__init__.py**

```python
from .base import BaseScanner, ScanResult, Finding, Severity

__all__ = ["BaseScanner", "ScanResult", "Finding", "Severity"]
```

- [ ] **Step 4: Commit**

```bash
git add vulnpy/scanners/base.py vulnpy/core/scanner.py vulnpy/scanners/__init__.py && git commit -m "feat: add base scanner class and core engine"
```

---

## Task 5: Port Scanner

**Covers:** [S6]

**Files:**
- Create: `VulnPy/vulnpy/scanners/port_scan.py`

- [ ] **Step 1: Create port scanner**

```python
# vulnpy/scanners/port_scan.py
import socket
from typing import List
from .base import BaseScanner, ScanResult, Finding, Severity

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Alt"
}

SERVICE_BANNERS = {
    b"SSH": "OpenSSH",
    b"FTP": "FTP Server",
    b"SMTP": "SMTP Server",
    b"HTTP": "Web Server"
}

class PortScanner(BaseScanner):
    name = "port_scan"
    description = "Scan open ports and detect services"

    def scan(self, target: str, ports: str = "1-1000", timeout: float = 1.0, **kwargs) -> ScanResult:
        result = ScanResult(scanner_name=self.name, target=target)
        port_range = self._parse_ports(ports)

        for port in port_range:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                if sock.connect_ex((target, port)) == 0:
                    banner = self._grab_banner(sock, timeout)
                    service = COMMON_PORTS.get(port, "unknown")
                    finding = Finding(
                        title=f"Port {port} open",
                        severity=Severity.INFO,
                        description=f"Port {port} ({service}) is open",
                        evidence=f"Banner: {banner}" if banner else "",
                        metadata={"port": port, "service": service, "banner": banner}
                    )
                    result.findings.append(finding)
                sock.close()
            except Exception as e:
                result.errors.append(f"Port {port}: {str(e)}")

        return result

    def _parse_ports(self, ports: str) -> List[int]:
        if "-" in ports:
            start, end = map(int, ports.split("-"))
            return list(range(start, end + 1))
        elif "," in ports:
            return [int(p.strip()) for p in ports.split(",")]
        else:
            return [int(ports)]

    def _grab_banner(self, sock: socket.socket, timeout: float) -> str:
        try:
            sock.settimeout(timeout)
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner[:200]
        except:
            return ""
```

- [ ] **Step 2: Commit**

```bash
git add vulnpy/scanners/port_scan.py && git commit -m "feat: add port scanner with service detection"
```

---

## Task 6: SQL Injection Scanner

**Covers:** [S7]

**Files:**
- Create: `VulnPy/vulnpy/scanners/sqli.py`

- [ ] **Step 1: Create SQLi scanner**

```python
# vulnpy/scanners/sqli.py
import requests
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from .base import BaseScanner, ScanResult, Finding, Severity

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "1' UNION SELECT NULL--",
    "1; DROP TABLE users--",
    "' AND 1=CONVERT(int, (SELECT @@version))--",
    "1' AND SLEEP(5)--",
    "1' WAITFOR DELAY '0:0:5'--",
]

SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"microsoft ole db provider for odbc drivers",
    r"postgresql.*error",
    r"ora-\d{5}",
    r"sqlite.*error",
]

class SQLIScanner(BaseScanner):
    name = "sqli"
    description = "Detect SQL Injection vulnerabilities"

    def scan(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(scanner_name=self.name, target=target)
        urls = self._get_test_urls(target)

        for url in urls:
            for param in parse_qs(urlparse(url).query):
                for payload in SQLI_PAYLOADS:
                    try:
                        test_url = self._inject_param(url, param, payload)
                        response = requests.get(test_url, timeout=10, verify=False)
                        if self._detect_sqli(response):
                            finding = Finding(
                                title=f"SQL Injection in parameter '{param}'",
                                severity=Severity.CRITICAL,
                                description=f"Parameter '{param}' is vulnerable to SQL injection",
                                evidence=f"Payload: {payload}\nResponse snippet: {response.text[:200]}",
                                recommendation="Use parameterized queries",
                                metadata={"url": url, "param": param, "payload": payload}
                            )
                            result.findings.append(finding)
                            break
                    except requests.RequestException:
                        continue

        return result

    def _get_test_urls(self, target: str) -> list:
        urls = []
        if "?" in target:
            urls.append(target)
        else:
            urls.append(f"{target}/?id=1")
            urls.append(f"{target}/?page=1")
            urls.append(f"{target}/?search=test")
        return urls

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _detect_sqli(self, response: requests.Response) -> bool:
        content = response.text.lower()
        return any(re.search(p, content) for p in SQLI_ERROR_PATTERNS)
```

- [ ] **Step 2: Commit**

```bash
git add vulnpy/scanners/sqli.py && git commit -m "feat: add SQL injection scanner"
```

---

## Task 7: XSS Scanner

**Covers:** [S8]

**Files:**
- Create: `VulnPy/vulnpy/scanners/xss.py`

- [ ] **Step 1: Create XSS scanner**

```python
# vulnpy/scanners/xss.py
import requests
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from .base import BaseScanner, ScanResult, Finding, Severity

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '<svg onload=alert("XSS")>',
    '"><script>alert("XSS")</script>',
    "javascript:alert('XSS')",
    '<iframe src="javascript:alert(\'XSS\')">',
]

class XSSScanner(BaseScanner):
    name = "xss"
    description = "Detect Cross-Site Scripting vulnerabilities"

    def scan(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(scanner_name=self.name, target=target)
        urls = self._get_test_urls(target)

        for url in urls:
            for param in parse_qs(urlparse(url).query):
                for payload in XSS_PAYLOADS:
                    try:
                        test_url = self._inject_param(url, param, payload)
                        response = requests.get(test_url, timeout=10, verify=False)
                        if payload in response.text:
                            finding = Finding(
                                title=f"XSS in parameter '{param}'",
                                severity=Severity.HIGH,
                                description=f"Parameter '{param}' is vulnerable to XSS",
                                evidence=f"Payload reflected in response",
                                recommendation="Encode output and validate input",
                                metadata={"url": url, "param": param, "payload": payload}
                            )
                            result.findings.append(finding)
                            break
                    except requests.RequestException:
                        continue

        return result

    def _get_test_urls(self, target: str) -> list:
        urls = []
        if "?" in target:
            urls.append(target)
        else:
            urls.append(f"{target}/?q=test")
            urls.append(f"{target}/?name=test")
            urls.append(f"{target}/?input=test")
        return urls

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
```

- [ ] **Step 2: Commit**

```bash
git add vulnpy/scanners/xss.py && git commit -m "feat: add XSS scanner"
```

---

## Task 8: Directory Traversal Scanner

**Covers:** [S9]

**Files:**
- Create: `VulnPy/vulnpy/scanners/traversal.py`

- [ ] **Step 1: Create traversal scanner**

```python
# vulnpy/scanners/traversal.py
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from .base import BaseScanner, ScanResult, Finding, Severity

TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
]

TRAVERSAL_MARKERS = [
    "root:x:0:0",
    "[boot loader]",
    "root:*:0:0",
]

class TraversalScanner(BaseScanner):
    name = "traversal"
    description = "Detect Directory Traversal vulnerabilities"

    def scan(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(scanner_name=self.name, target=target)
        urls = self._get_test_urls(target)

        for url in urls:
            for param in parse_qs(urlparse(url).query):
                for payload in TRAVERSAL_PAYLOADS:
                    try:
                        test_url = self._inject_param(url, param, payload)
                        response = requests.get(test_url, timeout=10, verify=False)
                        if any(marker in response.text for marker in TRAVERSAL_MARKERS):
                            finding = Finding(
                                title=f"Directory Traversal in parameter '{param}'",
                                severity=Severity.HIGH,
                                description=f"Parameter '{param}' allows directory traversal",
                                evidence=f"Payload: {payload}",
                                recommendation="Validate and sanitize file paths",
                                metadata={"url": url, "param": param, "payload": payload}
                            )
                            result.findings.append(finding)
                            break
                    except requests.RequestException:
                        continue

        return result

    def _get_test_urls(self, target: str) -> list:
        urls = []
        if "?" in target:
            urls.append(target)
        else:
            urls.append(f"{target}/?file=test.txt")
            urls.append(f"{target}/?page=home")
            urls.append(f"{target}/?include=header")
        return urls

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
```

- [ ] **Step 2: Commit**

```bash
git add vulnpy/scanners/traversal.py && git commit -m "feat: add directory traversal scanner"
```

---

## Task 9: SSL/TLS Checker

**Covers:** [S10]

**Files:**
- Create: `VulnPy/vulnpy/scanners/ssl_check.py`

- [ ] **Step 1: Create SSL checker**

```python
# vulnpy/scanners/ssl_check.py
import ssl
import socket
from datetime import datetime
from .base import BaseScanner, ScanResult, Finding, Severity

WEAK_PROTOCOLS = ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]
WEAK_CIPHERS = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT"]

class SSLChecker(BaseScanner):
    name = "ssl_check"
    description = "Check SSL/TLS configuration and certificates"

    def scan(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(scanner_name=self.name, target=target)
        hostname = self._extract_hostname(target)

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    cipher = ssock.cipher()

                    self._check_certificate(cert, result)
                    self._check_protocol(protocol, result)
                    self._check_cipher(cipher, result)

        except ssl.SSLCertVerificationError as e:
            result.findings.append(Finding(
                title="SSL Certificate Error",
                severity=Severity.HIGH,
                description=f"Certificate verification failed: {e}",
                recommendation="Fix or replace SSL certificate"
            ))
        except Exception as e:
            result.errors.append(f"SSL check failed: {str(e)}")

        return result

    def _extract_hostname(self, target: str) -> str:
        target = target.replace("https://", "").replace("http://", "")
        return target.split("/")[0].split(":")[0]

    def _check_certificate(self, cert: dict, result: ScanResult):
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (not_after - datetime.now()).days

        if days_left < 0:
            result.findings.append(Finding(
                title="Expired SSL Certificate",
                severity=Severity.CRITICAL,
                description=f"Certificate expired {abs(days_left)} days ago",
                recommendation="Renew SSL certificate"
            ))
        elif days_left < 30:
            result.findings.append(Finding(
                title="SSL Certificate Expiring Soon",
                severity=Severity.MEDIUM,
                description=f"Certificate expires in {days_left} days",
                recommendation="Renew SSL certificate"
            ))

    def _check_protocol(self, protocol: str, result: ScanResult):
        if protocol in WEAK_PROTOCOLS:
            result.findings.append(Finding(
                title=f"Weak Protocol: {protocol}",
                severity=Severity.HIGH,
                description=f"Server supports weak protocol {protocol}",
                recommendation="Disable weak protocols, use TLS 1.2+"
            ))

    def _check_cipher(self, cipher: tuple, result: ScanResult):
        cipher_name = cipher[0] if cipher else ""
        for weak in WEAK_CIPHERS:
            if weak in cipher_name.upper():
                result.findings.append(Finding(
                    title=f"Weak Cipher: {cipher_name}",
                    severity=Severity.HIGH,
                    description=f"Server uses weak cipher {cipher_name}",
                    recommendation="Use strong ciphers only"
                ))
```

- [ ] **Step 2: Commit**

```bash
git add vulnpy/scanners/ssl_check.py && git commit -m "feat: add SSL/TLS checker"
```

---

## Task 10: Weak Credential Scanner

**Covers:** [S11]

**Files:**
- Create: `VulnPy/vulnpy/scanners/weak_cred.py`
- Create: `VulnPy/wordlists/common_passwords.txt`
- Create: `VulnPy/wordlists/common_users.txt`

- [ ] **Step 1: Create wordlists**

```
# common_passwords.txt
admin
password
123456
12345678
qwerty
letmein
welcome
monkey
dragon
master
login
abc123
passw0rd
shadow
123456789
```

```
# common_users.txt
admin
root
user
test
guest
info
administrator
sysadmin
support
webmaster
```

- [ ] **Step 2: Create weak credential scanner**

```python
# vulnpy/scanners/weak_cred.py
import requests
import os
from .base import BaseScanner, ScanResult, Finding, Severity

class WeakCredScanner(BaseScanner):
    name = "weak_cred"
    description = "Test for weak/default credentials"

    def __init__(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        wordlist_dir = os.path.join(base_dir, "wordlists")
        self.users = self._load_wordlist(os.path.join(wordlist_dir, "common_users.txt"))
        self.passwords = self._load_wordlist(os.path.join(wordlist_dir, "common_passwords.txt"))

    def _load_wordlist(self, path: str) -> list:
        try:
            with open(path, "r") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return ["admin", "root", "user"]

    def scan(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(scanner_name=self.name, target=target)
        login_urls = self._find_login_pages(target)

        for url in login_urls:
            for user in self.users[:10]:
                for pwd in self.passwords[:10]:
                    try:
                        response = requests.post(url, data={
                            "username": user,
                            "password": pwd,
                            "user": user,
                            "pass": pwd
                        }, timeout=5, verify=False, allow_redirects=True)

                        if self._is_login_success(response):
                            finding = Finding(
                                title="Weak Credentials Found",
                                severity=Severity.CRITICAL,
                                description=f"Default/weak credentials accepted",
                                evidence=f"URL: {url}\nUser: {user}\nPassword: {pwd}",
                                recommendation="Change default credentials immediately",
                                metadata={"url": url, "username": user}
                            )
                            result.findings.append(finding)
                            return result

                    except requests.RequestException:
                        continue

        return result

    def _find_login_pages(self, target: str) -> list:
        urls = []
        paths = ["/login", "/admin", "/wp-login.php", "/administrator", "/signin"]
        for path in paths:
            url = target.rstrip("/") + path
            try:
                resp = requests.get(url, timeout=5, verify=False)
                if resp.status_code == 200:
                    urls.append(url)
            except:
                continue
        return urls if urls else [target + "/login"]

    def _is_login_success(self, response: requests.Response) -> bool:
        indicators = ["dashboard", "welcome", "logout", "profile", "admin panel"]
        content = response.text.lower()
        return any(ind in content for ind in indicators)
```

- [ ] **Step 3: Commit**

```bash
git add vulnpy/scanners/weak_cred.py wordlists/ && git commit -m "feat: add weak credential scanner"
```

---

## Task 11: CVE Matcher

**Covers:** [S12]

**Files:**
- Create: `VulnPy/vulnpy/core/database.py`
- Create: `VulnPy/vulnpy/scanners/cve_match.py`

- [ ] **Step 1: Create CVE database**

```python
# vulnpy/core/database.py
import json
import os
from typing import List, Dict

CVE_DB = {
    "apache": [
        {"cve": "CVE-2021-41773", "severity": "critical", "desc": "Apache Path Traversal", "version": "<2.4.49"},
        {"cve": "CVE-2021-42013", "severity": "critical", "desc": "Apache Path Traversal RCE", "version": "<2.4.50"},
    ],
    "nginx": [
        {"cve": "CVE-2021-23017", "severity": "high", "desc": "Nginx DNS Resolver Vulnerability", "version": "<1.21.1"},
    ],
    "openssh": [
        {"cve": "CVE-2023-38408", "severity": "critical", "desc": "OpenSSH RCE", "version": "<9.3p2"},
    ],
    "proftpd": [
        {"cve": "CVE-2023-48788", "severity": "critical", "desc": "ProFTPD SQL Injection", "version": "<1.3.8b"},
    ],
}

def match_cve(service: str, version: str) -> List[Dict]:
    results = []
    service_lower = service.lower()
    for key, vulns in CVE_DB.items():
        if key in service_lower:
            for v in vulns:
                if version and self._version_match(version, v["version"]):
                    results.append(v)
    return results

def _version_match(current: str, constraint: str) -> bool:
    if constraint.startswith("<"):
        return current < constraint[1:]
    elif constraint.startswith(">"):
        return current > constraint[1:]
    return current == constraint
```

- [ ] **Step 2: Create CVE matcher scanner**

```python
# vulnpy/scanners/cve_match.py
from .base import BaseScanner, ScanResult, Finding, Severity
from ..core.database import match_cve

class CVEMatcher(BaseScanner):
    name = "cve_match"
    description = "Match detected services against CVE database"

    def scan(self, target: str, service_info: dict = None, **kwargs) -> ScanResult:
        result = ScanResult(scanner_name=self.name, target=target)

        if not service_info:
            result.errors.append("No service information provided")
            return result

        for service, version in service_info.items():
            cves = match_cve(service, version)
            for cve in cves:
                severity_map = {
                    "critical": Severity.CRITICAL,
                    "high": Severity.HIGH,
                    "medium": Severity.MEDIUM,
                    "low": Severity.LOW,
                }
                finding = Finding(
                    title=f"{cve['cve']}: {cve['desc']}",
                    severity=severity_map.get(cve["severity"], Severity.MEDIUM),
                    description=f"{service} {version} - {cve['desc']}",
                    cve_id=cve["cve"],
                    recommendation=f"Update {service} to version {cve['version'].replace('<', '')} or later"
                )
                result.findings.append(finding)

        return result
```

- [ ] **Step 3: Commit**

```bash
git add vulnpy/core/database.py vulnpy/scanners/cve_match.py && git commit -m "feat: add CVE matcher scanner"
```

---

## Task 12: Report Generator

**Covers:** [S13]

**Files:**
- Create: `VulnPy/vulnpy/core/report.py`
- Create: `VulnPy/templates/report.html`

- [ ] **Step 1: Create HTML template**

```html
<!-- templates/report.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>VulnPy Report - {{ target }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #0a0a0a; color: #e0e0e0; }
        .header { background: linear-gradient(135deg, #1a1a2e, #16213e); padding: 30px; text-align: center; }
        .header h1 { color: #00ff88; font-size: 2em; }
        .header p { color: #888; margin-top: 10px; }
        .container { max-width: 1200px; margin: 20px auto; padding: 0 20px; }
        .summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }
        .summary-card { background: #1a1a2e; padding: 20px; border-radius: 8px; text-align: center; border-left: 4 solid #00ff88; }
        .summary-card.critical { border-left-color: #ff4444; }
        .summary-card.high { border-left-color: #ff8800; }
        .summary-card.medium { border-left-color: #ffcc00; }
        .summary-card.low { border-left-color: #00cc88; }
        .summary-card h3 { font-size: 2em; color: #00ff88; }
        .finding { background: #1a1a2e; margin: 15px 0; padding: 20px; border-radius: 8px; border-left: 4 solid #333; }
        .finding.critical { border-left-color: #ff4444; }
        .finding.high { border-left-color: #ff8800; }
        .finding.medium { border-left-color: #ffcc00; }
        .finding.low { border-left-color: #00cc88; }
        .finding.info { border-left-color: #4488ff; }
        .finding h3 { color: #fff; margin-bottom: 10px; }
        .badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 0.8em; font-weight: bold; }
        .badge.critical { background: #ff4444; color: #fff; }
        .badge.high { background: #ff8800; color: #fff; }
        .badge.medium { background: #ffcc00; color: #000; }
        .badge.low { background: #00cc88; color: #000; }
        .badge.info { background: #4488ff; color: #fff; }
        .evidence { background: #0d0d0d; padding: 10px; margin-top: 10px; border-radius: 4px; font-family: monospace; font-size: 0.9em; white-space: pre-wrap; }
        footer { text-align: center; padding: 20px; color: #555; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 VulnPy Report</h1>
        <p>Target: {{ target }} | Scan Date: {{ scan_date }}</p>
    </div>
    <div class="container">
        <div class="summary">
            <div class="summary-card critical"><h3>{{ counts.critical }}</h3><p>Critical</p></div>
            <div class="summary-card high"><h3>{{ counts.high }}</h3><p>High</p></div>
            <div class="summary-card medium"><h3>{{ counts.medium }}</h3><p>Medium</p></div>
            <div class="summary-card low"><h3>{{ counts.low }}</h3><p>Low/Info</p></div>
        </div>
        {% for finding in findings %}
        <div class="finding {{ finding.severity }}">
            <span class="badge {{ finding.severity }}">{{ finding.severity|upper }}</span>
            <h3>{{ finding.title }}</h3>
            <p>{{ finding.description }}</p>
            {% if finding.recommendation %}
            <p style="color: #00ff88; margin-top: 10px;">💡 {{ finding.recommendation }}</p>
            {% endif %}
            {% if finding.evidence %}
            <div class="evidence">{{ finding.evidence }}</div>
            {% endif %}
        </div>
        {% endfor %}
    </div>
    <footer>Generated by VulnPy v1.0.0 | Professional Vulnerability Scanner</footer>
</body>
</html>
```

- [ ] **Step 2: Create report generator**

```python
# vulnpy/core/report.py
import json
import csv
import os
from datetime import datetime
from typing import List
from jinja2 import Template
from ..scanners.base import ScanResult, Severity
from ..utils.logger import setup_logger

logger = setup_logger()

class ReportGenerator:
    def __init__(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        template_path = os.path.join(base_dir, "templates", "report.html")
        with open(template_path, "r") as f:
            self.html_template = Template(f.read())

    def generate(self, results: List[ScanResult], output: str, format: str):
        all_findings = []
        for r in results:
            all_findings.extend(r.findings)

        generators = {
            "html": self._generate_html,
            "json": self._generate_json,
            "csv": self._generate_csv,
        }

        if format not in generators:
            raise ValueError(f"Unsupported format: {format}")

        generators[format](all_findings, output, results[0].target if results else "unknown")
        logger.info(f"[green]✓[/green] Report saved to {output}")

    def _generate_html(self, findings, output, target):
        counts = {s.value: 0 for s in Severity}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

        html = self.html_template.render(
            target=target,
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            findings=findings,
            counts=counts
        )
        with open(output, "w") as f:
            f.write(html)

    def _generate_json(self, findings, output, target):
        data = {
            "target": target,
            "scan_date": datetime.now().isoformat(),
            "total_findings": len(findings),
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "description": f.description,
                    "cve_id": f.cve_id,
                    "recommendation": f.recommendation,
                    "evidence": f.evidence,
                }
                for f in findings
            ]
        }
        with open(output, "w") as f:
            json.dump(data, f, indent=2)

    def _generate_csv(self, findings, output, target):
        with open(output, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Title", "Severity", "Description", "CVE", "Recommendation"])
            for finding in findings:
                writer.writerow([
                    finding.title,
                    finding.severity.value,
                    finding.description,
                    finding.cve_id,
                    finding.recommendation,
                ])
```

- [ ] **Step 3: Commit**

```bash
git add vulnpy/core/report.py templates/ && git commit -m "feat: add report generator with HTML/JSON/CSV support"
```

---

## Task 13: CLI Interface

**Covers:** [S14]

**Files:**
- Create: `VulnPy/vulnpy/cli.py`

- [ ] **Step 1: Create CLI**

```python
# vulnpy/cli.py
import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from typing import Optional, List
from .core.scanner import ScanEngine
from .core.target import Target
from .core.report import ReportGenerator
from .scanners.port_scan import PortScanner
from .scanners.sqli import SQLIScanner
from .scanners.xss import XSSScanner
from .scanners.traversal import TraversalScanner
from .scanners.ssl_check import SSLChecker
from .scanners.weak_cred import WeakCredScanner
from .scanners.cve_match import CVEMatcher
from .utils.logger import setup_logger

app = typer.Typer(
    name="vulnpy",
    help="🔒 VulnPy - Professional Vulnerability Scanner",
    no_args_is_help=True
)
console = Console()
logger = setup_logger()

engine = ScanEngine()
engine.register(PortScanner())
engine.register(SQLIScanner())
engine.register(XSSScanner())
engine.register(TraversalScanner())
engine.register(SSLChecker())
engine.register(WeakCredScanner())
engine.register(CVEMatcher())

@app.command()
def scan(
    target: str = typer.Argument(..., help="Target IP, domain, or URL"),
    ports: str = typer.Option("1-1000", "--ports", "-p", help="Port range to scan"),
    scanners: Optional[List[str]] = typer.Option(None, "--scanner", "-s", help="Specific scanners to run"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
    format: str = typer.Option("html", "--format", "-f", help="Output format (html/json/csv)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """Scan a target for vulnerabilities"""
    logger = setup_logger(verbose)

    console.print(f"\n[bold green]🔒 VulnPy Scanner[/bold green]")
    console.print(f"[dim]Target: {target}[/dim]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=None)
        results = engine.scan(target, scanner_names=scanners, ports=ports)
        progress.update(task, completed=True)

    for result in results:
        if result.findings:
            console.print(f"\n[bold cyan]{result.scanner_name}[/bold cyan] - {len(result.findings)} findings")
            for f in result.findings:
                severity_color = {
                    "critical": "red", "high": "orange1",
                    "medium": "yellow", "low": "green", "info": "blue"
                }.get(f.severity.value, "white")
                console.print(f"  [{severity_color}]●[/{severity_color}] {f.title}")

    total_findings = sum(len(r.findings) for r in results)
    console.print(f"\n[bold]Total findings: {total_findings}[/bold]\n")

    if output:
        reporter = ReportGenerator()
        reporter.generate(results, output, format)
        console.print(f"[green]Report saved to {output}[/green]")

@app.command()
def list_scanners():
    """List available scanners"""
    table = Table(title="Available Scanners")
    table.add_column("Name", style="cyan")
    table.add_column("Description")
    for name, desc in engine.list_scanners():
        table.add_row(name, desc)
    console.print(table)

@app.command()
def version():
    """Show VulnPy version"""
    console.print("[bold green]VulnPy v1.0.0[/bold green]")
    console.print("Professional Vulnerability Scanner")

if __name__ == "__main__":
    app()
```

- [ ] **Step 2: Commit**

```bash
git add vulnpy/cli.py && git commit -m "feat: add CLI interface with typer"
```

---

## Task 14: Final Testing and Polish

**Covers:** [S15]

**Files:**
- Create: `VulnPy/tests/test_scanner.py`

- [ ] **Step 1: Create integration test**

```python
# tests/test_scanner.py
import pytest
from vulnpy.core.scanner import ScanEngine
from vulnpy.scanners.port_scan import PortScanner
from vulnpy.scanners.sqli import SQLIScanner
from vulnpy.scanners.base import Severity

def test_engine_registers_scanners():
    engine = ScanEngine()
    engine.register(PortScanner())
    engine.register(SQLIScanner())
    assert len(engine.scanners) == 2

def test_engine_get_scanner():
    engine = ScanEngine()
    scanner = PortScanner()
    engine.register(scanner)
    assert engine.get_scanner("port_scan") == scanner

def test_port_scanner_parse_ports():
    scanner = PortScanner()
    assert scanner._parse_ports("80") == [80]
    assert scanner._parse_ports("80,443") == [80, 443]
    assert scanner._parse_ports("1-5") == [1, 2, 3, 4, 5]

def test_finding_severity():
    from vulnpy.scanners.base import Finding
    f = Finding(title="Test", severity=Severity.HIGH, description="desc")
    assert f.severity == Severity.HIGH
```

- [ ] **Step 2: Run tests**

```bash
cd /home/server/VulnPy && python -m pytest tests/ -v
```

- [ ] **Step 3: Final commit**

```bash
git add -A && git commit -m "feat: add integration tests and final polish"
```

---

## Task 15: README and Documentation

**Covers:** [S16]

**Files:**
- Create: `VulnPy/README.md`

- [ ] **Step 1: Create README**

```markdown
# 🔒 VulnPy

Professional Vulnerability Scanner for Security Professionals

## Features

- 🔍 Port Scanning with Service Detection
- 🛡️ SQL Injection Detection
- ⚡ XSS Detection
- 📁 Directory Traversal Detection
- 🔐 SSL/TLS Analysis
- 🔑 Weak Credential Testing
- 📊 CVE Matching
- 📄 Multiple Report Formats (HTML, JSON, CSV)

## Installation

```bash
git clone https://github.com/yourusername/VulnPy.git
cd VulnPy
pip install -r requirements.txt
pip install -e .
```

## Usage

```bash
# Scan a target
vulnpy scan 192.168.1.1

# Scan with specific ports
vulnpy scan example.com --ports 80,443,8080

# Run specific scanner
vulnpy scan target.com --scanner sqli --scanner xss

# Generate HTML report
vulnpy scan target.com --output report.html --format html

# List available scanners
vulnpy list-scanners

# Show version
vulnpy version
```

## Available Scanners

| Scanner | Description |
|---------|-------------|
| port_scan | Scan open ports and detect services |
| sqli | SQL Injection detection |
| xss | Cross-Site Scripting detection |
| traversal | Directory Traversal detection |
| ssl_check | SSL/TLS configuration analysis |
| weak_cred | Weak/default credential testing |
| cve_match | CVE database matching |

## Report Formats

- **HTML** - Beautiful dark-themed reports
- **JSON** - Machine-readable output
- **CSV** - Spreadsheet compatible

## Disclaimer

⚠️ This tool is for authorized security testing only. Always get permission before scanning systems you don't own.

## License

MIT License
```

- [ ] **Step 2: Final commit**

```bash
git add README.md && git commit -m "docs: add README with usage instructions"
```

---

## Summary

| Task | Component | Files |
|------|-----------|-------|
| 1 | Project Setup | requirements.txt, setup.py, .gitignore |
| 2 | Utilities | logger.py, network.py |
| 3 | Target Parser | target.py |
| 4 | Core Engine | scanner.py, base.py |
| 5 | Port Scanner | port_scan.py |
| 6 | SQLi Scanner | sqli.py |
| 7 | XSS Scanner | xss.py |
| 8 | Traversal Scanner | traversal.py |
| 9 | SSL Checker | ssl_check.py |
| 10 | Weak Cred Scanner | weak_cred.py |
| 11 | CVE Matcher | database.py, cve_match.py |
| 12 | Report Generator | report.py, report.html |
| 13 | CLI Interface | cli.py |
| 14 | Testing | test_scanner.py |
| 15 | Documentation | README.md |
