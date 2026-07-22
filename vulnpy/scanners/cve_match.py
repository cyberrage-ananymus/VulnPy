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
