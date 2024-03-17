from dataclasses import dataclass
from typing import List, Optional
from oonidata.compat import add_slots
from oonidata.models.dataformats import (
    BaseTestKeys,
    HTTPTransaction,
)
from oonidata.models.base_model import BaseModel
from oonidata.models.nettests.base_measurement import BaseMeasurement


@add_slots
@dataclass
class HHFMTampering(BaseModel):
    header_field_name: Optional[bool] = None
    header_field_number: Optional[bool] = None
    header_field_value: Optional[bool] = None
    header_name_capitalization: Optional[bool] = None
    header_name_diff: Optional[List[str]] = None
    request_line_capitalization: Optional[bool] = None
    total: Optional[bool] = None


@add_slots
@dataclass
class HTTPHeaderFieldManipulationTestKeys(BaseTestKeys):
    requests: Optional[List[HTTPTransaction]] = None
    tampering: Optional[HHFMTampering] = None


@add_slots
@dataclass
class HTTPHeaderFieldManipulation(BaseMeasurement):
    __test_name__ = "http_header_field_manipulation"

    test_keys: HTTPHeaderFieldManipulationTestKeys
