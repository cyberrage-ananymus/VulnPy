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
