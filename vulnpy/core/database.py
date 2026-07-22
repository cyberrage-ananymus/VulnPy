from typing import List, Dict

CVE_DB = {
    "apache": [
        {"cve": "CVE-2021-41773", "severity": "critical", "desc": "Apache Path Traversal", "version": "<2.4.49"},
        {"cve": "CVE-2021-42013", "severity": "critical", "desc": "Apache Path Traversal RCE", "version": "<2.4.50"},
        {"cve": "CVE-2021-44790", "severity": "critical", "desc": "Apache Buffer Overflow mod_lua", "version": "<2.4.52"},
        {"cve": "CVE-2022-22721", "severity": "critical", "desc": "Apache HTTP Request Smuggling", "version": "<2.4.53"},
        {"cve": "CVE-2023-25690", "severity": "critical", "desc": "Apache HTTP Request Smuggling", "version": "<2.4.58"},
        {"cve": "CVE-2024-38476", "severity": "critical", "desc": "Apache URL Rewrite Bypass", "version": "<2.4.59"},
    ],
    "nginx": [
        {"cve": "CVE-2021-23017", "severity": "high", "desc": "Nginx DNS Resolver Vulnerability", "version": "<1.21.1"},
        {"cve": "CVE-2022-41741", "severity": "high", "desc": "Nginx mp4 Module Memory Corruption", "version": "<1.23.2"},
        {"cve": "CVE-2024-7347", "severity": "high", "desc": "Nginx HTTP/3 QUIC Memory Corruption", "version": "<1.27.1"},
        {"cve": "CVE-2021-23017", "severity": "medium", "desc": "Nginx DNS Resolver Off-By-One", "version": "<1.21.1"},
    ],
    "openssh": [
        {"cve": "CVE-2023-38408", "severity": "critical", "desc": "OpenSSH RCE via ssh-agent", "version": "<9.3p2"},
        {"cve": "CVE-2023-51385", "severity": "medium", "desc": "OpenSSH OS Command Injection", "version": "<9.6p1"},
        {"cve": "CVE-2024-6387", "severity": "high", "desc": "OpenSSH Race Condition (regreSSHion)", "version": "<9.8p1"},
    ],
    "proftpd": [
        {"cve": "CVE-2023-48788", "severity": "critical", "desc": "ProFTPD SQL Injection", "version": "<1.3.8b"},
        {"cve": "CVE-2022-37313", "severity": "critical", "desc": "ProFTPD Remote Code Execution", "version": "<1.3.8"},
    ],
    "vsftpd": [
        {"cve": "CVE-2021-36934", "severity": "critical", "desc": "vsftpd Backdoor (2.3.4)", "version": "==2.3.4"},
    ],
    "mysql": [
        {"cve": "CVE-2023-21977", "severity": "high", "desc": "MySQL Server Vulnerability", "version": "<8.0.33"},
        {"cve": "CVE-2024-21096", "severity": "high", "desc": "MySQL Server Crash", "version": "<8.0.37"},
    ],
    "postgresql": [
        {"cve": "CVE-2024-0567", "severity": "medium", "desc": "PostgreSQL libpq Security Bypass", "version": "<16.1"},
        {"cve": "CVE-2023-50494", "severity": "high", "desc": "PostgreSQL Privilege Escalation", "version": "<16.1"},
    ],
    "iis": [
        {"cve": "CVE-2024-30088", "severity": "high", "desc": "Windows SMB Elevation of Privilege", "version": "<10.0.19041"},
        {"cve": "CVE-2023-36884", "severity": "critical", "desc": "Microsoft Office/Windows HTML RCE", "version": "*"},
    ],
    "tomcat": [
        {"cve": "CVE-2024-21733", "severity": "medium", "desc": "Apache Tomcat Information Disclosure", "version": "<10.1.18"},
        {"cve": "CVE-2023-46589", "severity": "high", "desc": "Apache Tomcat Request Smuggling", "version": "<9.0.82"},
        {"cve": "CVE-2023-45648", "severity": "high", "desc": "Apache Tomcat Request Smuggling", "version": "<9.0.80"},
    ],
    "lighttpd": [
        {"cve": "CVE-2024-33592", "severity": "medium", "desc": "Lighttpd Memory Leak", "version": "<1.4.76"},
    ],
    "node.js": [
        {"cve": "CVE-2024-27982", "severity": "high", "desc": "Node.js HTTP Request Smuggling", "version": "<20.12.1"},
    ],
    "php": [
        {"cve": "CVE-2024-4577", "severity": "critical", "desc": "PHP CGI Argument Injection", "version": "<8.1.29"},
        {"cve": "CVE-2024-2961", "severity": "critical", "desc": "PHP iconv Buffer Overflow", "version": "<8.3.7"},
    ],
    "wordpress": [
        {"cve": "CVE-2024-28000", "severity": "high", "desc": "WordPress Brute Force Protection Bypass", "version": "<6.6.1"},
        {"cve": "CVE-2024-24549", "severity": "high", "desc": "WordPress Directory Traversal", "version": "<6.4.3"},
    ],
    "django": [
        {"cve": "CVE-2024-24680", "severity": "medium", "desc": "Django Denial of Service", "version": "<4.2.9"},
        {"cve": "CVE-2024-27351", "severity": "high", "desc": "Django SQL Injection", "version": "<4.2.9"},
    ],
    "spring": [
        {"cve": "CVE-2024-22234", "severity": "high", "desc": "Spring Security Authorization Bypass", "version": "<6.2.4"},
        {"cve": "CVE-2024-22243", "severity": "critical", "desc": "Spring Framework URL Parsing Vulnerability", "version": "<6.1.5"},
    ],
}

SERVICE_VERSION_PATTERNS = [
    r"Server:\s*(\S+)/(\S+)",
    r"X-Powered-By:\s*(\S+)/(\S+)",
    r"Apache/(\S+)",
    r"nginx/(\S+)",
    r"OpenSSH[_ ](\S+)",
    r"ProFTPD (\S+)",
    r"vsftpd (\S+)",
    r"Microsoft-IIS/(\S+)",
    r"Tomcat/(\S+)",
    r"PHP/(\S+)",
]

def match_cve(service: str, version: str) -> List[Dict]:
    results = []
    service_lower = service.lower()
    for key, vulns in CVE_DB.items():
        if key in service_lower:
            for v in vulns:
                if version and _version_match(version, v["version"]):
                    results.append(v)
    return results

def _version_match(current: str, constraint: str) -> bool:
    if constraint.startswith("<"):
        return current < constraint[1:]
    elif constraint.startswith(">"):
        return current > constraint[1:]
    elif constraint.startswith("=="):
        return current == constraint[2:]
    return current == constraint

def detect_services_from_banner(banner: str) -> List[Dict]:
    import re
    services = []
    for pattern in SERVICE_VERSION_PATTERNS:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            groups = match.groups()
            if len(groups) == 2:
                services.append({"name": groups[0], "version": groups[1]})
            elif len(groups) == 1:
                services.append({"name": "service", "version": groups[0]})
    return services
