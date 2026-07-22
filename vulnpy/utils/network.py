import socket
import ipaddress
from typing import List, Optional

def resolve_target(target: str) -> Optional[str]:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

def expand_cidr(cidr: str) -> List[str]:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(host) for host in network.hosts()]
    except ValueError:
        return []

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_url(url: str) -> bool:
    return url.startswith(("http://", "https://"))
