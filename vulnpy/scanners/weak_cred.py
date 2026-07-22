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
