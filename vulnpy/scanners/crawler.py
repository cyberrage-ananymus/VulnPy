import requests
import re
from urllib.parse import urljoin, urlparse, parse_qs
from .base import BaseScanner, ScanResult, Finding, Severity
from ..utils.logger import setup_logger

logger = setup_logger()

class Crawler(BaseScanner):
    name = "crawler"
    description = "Auto-discover URLs, forms, and parameters"

    def scan(self, target: str, depth: int = 2, **kwargs) -> ScanResult:
        result = ScanResult(scanner_name=self.name, target=target)
        visited = set()
        discovered = {"urls": [], "forms": [], "params": []}

        self._crawl(target, target, depth, visited, discovered)

        result.findings.append(Finding(
            title=f"Discovered {len(discovered['urls'])} URLs",
            severity=Severity.INFO,
            description=f"Crawler found {len(discovered['urls'])} URLs, {len(discovered['forms'])} forms, {len(discovered['params'])} unique parameters",
            evidence="\n".join(discovered['urls'][:20]),
            metadata=discovered
        ))

        return result

    def _crawl(self, base_url: str, url: str, depth: int, visited: set, discovered: dict):
        if depth <= 0 or url in visited or len(visited) > 50:
            return

        visited.add(url)

        try:
            response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            content = response.text

            urls = re.findall(r'href=["\']([^"\'#]+)["\']', content)
            for u in urls:
                full_url = urljoin(url, u)
                if full_url.startswith(base_url) and full_url not in visited:
                    discovered['urls'].append(full_url)

            forms = re.findall(r'<form[^>]*>(.*?)</form>', content, re.DOTALL | re.IGNORECASE)
            for form in forms:
                action = re.search(r'action=["\']([^"\']*)["\']', form)
                inputs = re.findall(r'name=["\']([^"\']*)["\']', form)
                if inputs:
                    discovered['forms'].append({
                        'action': action.group(1) if action else url,
                        'params': inputs
                    })
                    discovered['params'].extend(inputs)

            links = list(set(discovered['urls']))
            for link in links[:10]:
                self._crawl(base_url, link, depth - 1, visited, discovered)

        except requests.RequestException:
            pass
