from dataclasses import dataclass
from typing import List, Optional
from oonidata.compat import add_slots
from oonidata.models.dataformats import (
    BaseTestKeys,
    DNSQuery,
    NetworkEvent,
    Failure,
)
from oonidata.models.nettests.base_measurement import BaseMeasurement


@add_slots
@dataclass
class StunReachabilityTestKeys(BaseTestKeys):
    failure: Failure = None 
    endpoint: Optional[str] = None

    network_events: Optional[List[NetworkEvent]] = None
    queries: Optional[List[DNSQuery]] = None


@add_slots
@dataclass
class StunReachability(BaseMeasurement):
    __test_name__ = "stunreachability"

    test_keys: StunReachabilityTestKeys
