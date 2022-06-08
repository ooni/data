from typing import Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ASInfo:
    asn: int

    as_org_name: str
    as_cc: str


@dataclass
class IPInfo:
    as_info: ASInfo
    cc: str
    is_bogon: bool


class NetinfoDB:
    def lookup_asn(self, day: datetime, asn: int) -> Optional[ASInfo]:
        """
        Returns information about a particular ASN on a given day, if known.
        """
        return None

    def lookup_ip(self, day: datetime, ip: str) -> Optional[IPInfo]:
        return None
