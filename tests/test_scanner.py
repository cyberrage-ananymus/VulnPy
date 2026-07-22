import pytest
from vulnpy.core.scanner import ScanEngine
from vulnpy.scanners.port_scan import PortScanner
from vulnpy.scanners.sqli import SQLIScanner
from vulnpy.scanners.xss import XSSScanner
from vulnpy.scanners.traversal import TraversalScanner
from vulnpy.scanners.ssl_check import SSLChecker
from vulnpy.scanners.weak_cred import WeakCredScanner
from vulnpy.scanners.cve_match import CVEMatcher
from vulnpy.scanners.base import Severity, Finding, ScanResult
from vulnpy.core.target import Target, TargetType

def test_engine_registers_scanners():
    engine = ScanEngine()
    engine.register(PortScanner())
    engine.register(SQLIScanner())
    assert len(engine.scanners) == 2

def test_engine_get_scanner():
    engine = ScanEngine()
    scanner = PortScanner()
    engine.register(scanner)
    assert engine.get_scanner("port_scan") == scanner

def test_engine_get_scanner_not_found():
    engine = ScanEngine()
    with pytest.raises(ValueError):
        engine.get_scanner("nonexistent")

def test_port_scanner_parse_ports():
    scanner = PortScanner()
    assert scanner._parse_ports("80") == [80]
    assert scanner._parse_ports("80,443") == [80, 443]
    assert scanner._parse_ports("1-5") == [1, 2, 3, 4, 5]

def test_finding_severity():
    f = Finding(title="Test", severity=Severity.HIGH, description="desc")
    assert f.severity == Severity.HIGH
    assert f.title == "Test"

def test_scan_result():
    result = ScanResult(scanner_name="test", target="127.0.0.1")
    assert result.scanner_name == "test"
    assert len(result.findings) == 0

def test_target_parse_ip():
    target = Target.parse("192.168.1.1")
    assert target.type == TargetType.IP
    assert target.value == "192.168.1.1"

def test_target_parse_url():
    target = Target.parse("https://example.com")
    assert target.type == TargetType.URL
    assert target.value == "https://example.com"

def test_scanner_list():
    engine = ScanEngine()
    engine.register(PortScanner())
    engine.register(SQLIScanner())
    scanners = engine.list_scanners()
    assert len(scanners) == 2
    assert scanners[0][0] == "port_scan"
