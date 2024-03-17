from dataclasses import dataclass
from typing import List, Optional
from oonidata.compat import add_slots
from oonidata.models.dataformats import (
    BaseTestKeys,
    DNSQuery,
    HTTPTransaction,
    NetworkEvent,
    TCPConnect,
    Failure,
    TLSHandshake,
)
from oonidata.models.nettests.base_measurement import BaseMeasurement


@add_slots
@dataclass
class SignalTestKeys(BaseTestKeys):
    failure: Failure = None
    failed_operation: Optional[str] = None

    network_events: Optional[List[NetworkEvent]] = None
    tls_handshakes: Optional[List[TLSHandshake]] = None
    queries: Optional[List[DNSQuery]] = None
    tcp_connect: Optional[List[TCPConnect]] = None
    requests: Optional[List[HTTPTransaction]] = None

    signal_backend_status: Optional[str] = None
    signal_backend_failure: Optional[str] = None


@add_slots
@dataclass
class Signal(BaseMeasurement):
    __test_name__ = "signal"

    test_keys: SignalTestKeys
