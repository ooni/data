from dataclasses import dataclass
from typing import List, Optional
from oonidata.compat import add_slots
from oonidata.models.dataformats import (
    BaseTestKeys,
)
from oonidata.models.nettests.base_measurement import BaseMeasurement


@add_slots
@dataclass
class HTTPInvalidRequestLineTestKeys(BaseTestKeys):
    received: Optional[List[str]] = None
    sent: Optional[List[str]] = None
    tampering: Optional[bool] = None


@add_slots
@dataclass
class HTTPInvalidRequestLine(BaseMeasurement):
    __test_name__ = "http_invalid_request_line"

    test_keys: HTTPInvalidRequestLineTestKeys
