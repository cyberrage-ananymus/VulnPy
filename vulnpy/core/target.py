from enum import Enum
from typing import List
from ..utils.network import is_valid_ip, is_valid_url, expand_cidr, resolve_target

class TargetType(Enum):
    IP = "ip"
    URL = "url"
    DOMAIN = "domain"
    CIDR = "cidr"

class Target:
    def __init__(self, value: str, target_type: TargetType, resolved: str = None):
        self.value = value
        self.type = target_type
        self.resolved = resolved or value

    @classmethod
    def parse(cls, target: str) -> "Target":
        if is_valid_url(target):
            return cls(target, TargetType.URL)
        elif is_valid_ip(target):
            return cls(target, TargetType.IP)
        else:
            resolved = resolve_target(target)
            return cls(target, TargetType.DOMAIN, resolved)

    @classmethod
    def parse_cidr(cls, cidr: str) -> List["Target"]:
        ips = expand_cidr(cidr)
        return [cls(ip, TargetType.IP) for ip in ips]

    def __repr__(self):
        return f"Target({self.value}, {self.type.value})"
