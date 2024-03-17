from dataclasses import dataclass
from typing import List, Optional
from oonidata.compat import add_slots
from oonidata.models.dataformats import (
    BaseTestKeys,
    DNSQuery,
    NetworkEvent,
    TCPConnect,
    TLSHandshake,
    HTTPTransaction,
    Failure,
)
from oonidata.models.nettests.base_measurement import BaseMeasurement


@add_slots
@dataclass
class UrlGetterTestKeys(BaseTestKeys):
    failure: Failure = None
    failed_operation: Optional[str] = None
    agent: Optional[str] = None

    socksproxy: Optional[str] = None
    network_events: Optional[List[NetworkEvent]] = None
    queries: Optional[List[DNSQuery]] = None
    requests: Optional[List[HTTPTransaction]] = None
    tcp_connect: Optional[List[TCPConnect]] = None
    tls_handshakes: Optional[List[TLSHandshake]] = None


@add_slots
@dataclass
class UrlGetter(BaseMeasurement):
    __test_name__ = "urlgetter"

    test_keys: UrlGetterTestKeys
