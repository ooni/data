from dataclasses import dataclass
from typing import List, Optional

from oonidata.models.nettests.web_connectivity import WebConnectivityControl

from ...compat import add_slots
from ..dataformats import (
    BaseTestKeys,
    DNSQuery,
    NetworkEvent,
    TCPConnect,
    TLSHandshake,
)
from oonidata.models.nettests.base_measurement import BaseMeasurement


@add_slots
@dataclass
class ECHCheckTestKeys(BaseTestKeys):
    tls_handshakes: Optional[List[TLSHandshake]] = None
    control: Optional[TLSHandshake] = None
    target: Optional[TLSHandshake] = None
    network_events: Optional[List[NetworkEvent]] = None
    queries: Optional[List[DNSQuery]] = None
    tcp_connect: Optional[List[TCPConnect]] = None


@add_slots
@dataclass
class ECHCheck(BaseMeasurement):
    __test_name__ = "echcheck"

    test_keys: ECHCheckTestKeys
