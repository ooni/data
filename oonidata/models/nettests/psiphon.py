from dataclass import dataclass
from typing import List, Optional
from oonidata.compat import add_slots
from oonidata.models.base_model import BaseModel
from oonidata.models.dataformats import (
    DNSQuery,
    Failure,
    HTTPTransaction,
    NetworkEvent,
    TLSHandshake,
)

from .base_measurement import BaseMeasurement


@add_slots
@dataclass
class PsiphonTestKeys(BaseModel):
    failure: Failure = None
    max_runtime: Optional[int] = None
    bootstrap_time: Optional[int] = None

    socksproxy: Optional[str] = None
    network_events: Optional[List[NetworkEvent]] = None
    tls_handshakes: Optional[List[TLSHandshake]] = None
    queries: Optional[List[DNSQuery]] = None
    requests = Optional[List[HTTPTransaction]] = None


@add_slots
@dataclass
class Psiphon(BaseMeasurement):
    __test_name__ = "psiphon"

    test_keys: PsiphonTestKeys
