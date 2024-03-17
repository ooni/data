from dataclasses import dataclass
from typing import List, Optional
from oonidata.compat import add_slots
from oonidata.models.dataformats import (
    BaseTestKeys,
)
from oonidata.models.nettests.base_measurement import BaseMeasurement


@add_slots
@dataclass
class BrowserWebTestKeys(BaseTestKeys):
    result: str = None
    load_time_ms: Optional[float] = None
    browser: Optional[str] = None


@add_slots
@dataclass
class BrowserWeb(BaseMeasurement):
    __test_name__ = "browser_web"

    test_keys: BrowserWebTestKeys
