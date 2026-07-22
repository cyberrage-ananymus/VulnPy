import socket
from typing import List
from .base import BaseScanner, ScanResult, Finding, Severity

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Alt"
}

class PortScanner(BaseScanner):
    name = "port_scan"
    description = "Scan open ports and detect services"

    def scan(self, target: str, ports: str = "1-1000", timeout: float = 1.0, **kwargs) -> ScanResult:
        result = ScanResult(scanner_name=self.name, target=target)
        port_range = self._parse_ports(ports)

        for port in port_range:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                if sock.connect_ex((target, port)) == 0:
                    banner = self._grab_banner(sock, timeout)
                    service = COMMON_PORTS.get(port, "unknown")
                    finding = Finding(
                        title=f"Port {port} open",
                        severity=Severity.INFO,
                        description=f"Port {port} ({service}) is open",
                        evidence=f"Banner: {banner}" if banner else "",
                        metadata={"port": port, "service": service, "banner": banner}
                    )
                    result.findings.append(finding)
                sock.close()
            except Exception as e:
                result.errors.append(f"Port {port}: {str(e)}")

        return result

    def _parse_ports(self, ports: str) -> List[int]:
        if "-" in ports:
            start, end = map(int, ports.split("-"))
            return list(range(start, end + 1))
        elif "," in ports:
            return [int(p.strip()) for p in ports.split(",")]
        else:
            return [int(ports)]

    def _grab_banner(self, sock: socket.socket, timeout: float) -> str:
        try:
            sock.settimeout(timeout)
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner[:200]
        except:
            return ""
