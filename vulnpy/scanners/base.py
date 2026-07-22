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
