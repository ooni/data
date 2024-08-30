from dataclasses import dataclass
from typing import Dict, List, Optional, Union


from ...compat import add_slots

from ..base import BaseModel
from ..dataformats import BaseTestKeys

@add_slots
@dataclass
class BaseMeasurement(BaseModel):
    """
    See: https://github.com/ooni/spec/blob/master/data-formats/df-000-base.md
    """

    __test_name__ = "generic"

    input: Union[str, List[str], None]
    report_id: str

    measurement_start_time: str
    test_start_time: str

    probe_asn: str
    probe_cc: str

    test_name: str
    test_version: str
    test_runtime: float

    software_name: str
    software_version: str

    test_keys: BaseTestKeys

    probe_ip: Optional[str] = None
    annotations: Optional[Dict[str, str]] = None
    resolver_asn: Optional[str] = None
    resolver_ip: Optional[str] = None
    resolver_network_name: Optional[str] = None

    probe_network_name: Optional[str] = None

    test_helpers: Optional[Dict] = None
    data_format_version: Optional[str] = None
    measurement_uid: Optional[str] = None
