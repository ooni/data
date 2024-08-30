from dataclasses import dataclass
from typing import List, Optional
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
class WhatsappTestKeys(BaseTestKeys):
    failure: Failure = None
    failed_operation: Optional[str] = None

    network_events: Optional[List[NetworkEvent]] = None
    tls_handshakes: Optional[List[TLSHandshake]] = None
    queries: Optional[List[DNSQuery]] = None
    tcp_connect: Optional[List[TCPConnect]] = None
    requests: Optional[List[HTTPTransaction]] = None

    registration_server_failure: Optional[str] = None
    registration_server_status: Optional[str] = None
    whatsapp_endpoints_status: Optional[str] = None
    whatsapp_endpoints_blocked: Optional[List[str]] = None
    whatsapp_endpoints_dns_inconsistent: Optional[List[str]] = None

    whatsapp_web_failure: Optional[str] = None
    whatsapp_web_status: Optional[str] = None


@add_slots
@dataclass
class Whatsapp(BaseMeasurement):
    __test_name__ = "whatsapp"

    test_keys: WhatsappTestKeys
