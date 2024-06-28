from dataclasses import dataclass
from typing import Dict, List, Optional

from ...compat import add_slots

from ..base import BaseModel
from ..dataformats import (
    DNSQuery,
    Failure,
    HTTPTransaction,
    NetworkEvent,
    TCPConnect,
    TLSHandshake,
)

from .base_measurement import BaseMeasurement


@add_slots
@dataclass
class TorTestTarget(BaseModel):
    target_address: str
    target_protocol: str

    network_events: Optional[List[NetworkEvent]] = None
    queries: Optional[List[DNSQuery]] = None
    requests: Optional[List[HTTPTransaction]] = None
    tls_handshakes: Optional[List[TLSHandshake]] = None
    tcp_connect: Optional[List[TCPConnect]] = None
    target_name: Optional[str] = None
    failure: Failure = None


@add_slots
@dataclass
class TorTestKeys(BaseModel):
    targets: Dict[str, TorTestTarget]


@add_slots
@dataclass
class Tor(BaseMeasurement):
    __test_name__ = "tor"

    test_keys: TorTestKeys
