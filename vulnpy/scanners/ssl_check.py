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
