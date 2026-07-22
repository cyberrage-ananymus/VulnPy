import time
from typing import List, Type
from ..scanners.base import BaseScanner, ScanResult
from ..utils.logger import setup_logger

logger = setup_logger()

class ScanEngine:
    def __init__(self):
        self.scanners: List[BaseScanner] = []

    def register(self, scanner: BaseScanner):
        self.scanners.append(scanner)
        logger.debug(f"Registered scanner: {scanner.name}")

    def get_scanner(self, name: str) -> BaseScanner:
        for s in self.scanners:
            if s.name == name:
                return s
        raise ValueError(f"Scanner '{name}' not found")

    def scan(self, target: str, scanner_names: List[str] = None, **kwargs) -> List[ScanResult]:
        results = []
        scanners_to_run = self.scanners if not scanner_names else [
            self.get_scanner(n) for n in scanner_names
        ]

        for scanner in scanners_to_run:
            start = time.time()
            try:
                result = scanner.scan(target, **kwargs)
                result.scan_time = time.time() - start
                results.append(result)
                logger.info(f"[green]✓[/green] {scanner.name} completed in {result.scan_time:.2f}s")
            except Exception as e:
                logger.error(f"[red]✗[/red] {scanner.name} failed: {e}")
                results.append(ScanResult(
                    scanner_name=scanner.name,
                    target=target,
                    errors=[str(e)]
                ))

        return results

    def list_scanners(self):
        return [(s.name, s.description) for s in self.scanners]
