from dataclasses import dataclass
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
class VanillaTorTestKeys(BaseModel):
    failure: Failure = None
    error: Optional[str] = None
    success: Optional[bool] = None
    bootstrap_time: Optional[int] = None
    timeout: Optional[int] = None

    tor_logs: Optional[List[str]] = None
    tor_progress: Optional[int] = None
    tor_progress_tag: Optional[str] = None
    tor_progress_summary: Optional[str] = None
    tor_version: Optional[str] = None
    transport_name: Optional[str] = None


@add_slots
@dataclass
class VanillaTor(BaseMeasurement):
    __test_name__ = "vanila_tor"

    test_keys: VanillaTorTestKeys
