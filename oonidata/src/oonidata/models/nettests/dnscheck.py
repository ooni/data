from dataclasses import dataclass
from typing import Dict, List, Optional
from oonidata.compat import add_slots
from oonidata.models.dataformats import (
    BaseTestKeys,
    DNSQuery,
    Failure,
    HTTPTransaction,
    NetworkEvent,
    TCPConnect,
    TLSHandshake,
)
from oonidata.models.nettests.base_measurement import BaseMeasurement


@add_slots
@dataclass
class URLGetterTestKeys(BaseTestKeys):
    failure: Failure = None
    socksproxy: Optional[str] = None
    tls_handshakes: Optional[List[TLSHandshake]] = None
    network_events: Optional[List[NetworkEvent]] = None
    queries: Optional[List[DNSQuery]] = None
    tcp_connect: Optional[List[TCPConnect]] = None
    requests: Optional[List[HTTPTransaction]] = None


@add_slots
@dataclass
class DNSCheckTestKeys(BaseTestKeys):
    lookups: Optional[Dict[str, URLGetterTestKeys]] = None
    bootstrap: Optional[URLGetterTestKeys] = None
    bootstrap_failure: Optional[str] = None


@add_slots
@dataclass
class DNSCheck(BaseMeasurement):
    __test_name__ = "dnscheck"

    test_keys: DNSCheckTestKeys
