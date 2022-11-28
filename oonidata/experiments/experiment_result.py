import logging
from typing import Any, Generator, List, Optional, NamedTuple, Mapping, Tuple
from enum import Enum
from datetime import datetime
import dataclasses
from dataclasses import dataclass, field

from oonidata.compat import add_slots
from oonidata.observations import (
    MeasurementMeta,
)

log = logging.getLogger("oonidata.events")


class BlockingScope(Enum):
    # n: national level blocking
    NATIONAL_BLOCK = "n"
    # i: isp level blocking
    ISP_BLOCK = "i"
    # l: local blocking (school, office, home network)
    LOCAL_BLOCK = "l"
    # s: server-side blocking
    SERVER_SIDE_BLOCK = "s"
    # t: this is a signal indicating some form of network throttling
    THROTTLING = "t"
    # u: unknown blocking scope
    UNKNOWN = "u"


class BlockingStatus(Enum):
    # k: everything is OK
    OK = "k"
    # b: blocking is happening with an unknown scope
    BLOCKED = "b"
    # d: the subject is down
    DOWN = "d"


def fp_scope_to_status_scope(
    scope: Optional[str],
) -> Tuple[BlockingStatus, BlockingScope]:
    # "nat" national level blockpage
    # "isp" ISP level blockpage
    # "prod" text pattern related to a middlebox product
    # "inst" text pattern related to a voluntary instition blockpage (school, office)
    # "vbw" vague blocking word
    # "fp" fingerprint for false positives
    if scope == "nat":
        return BlockingStatus.BLOCKED, BlockingScope.NATIONAL_BLOCK
    elif scope == "isp":
        return BlockingStatus.BLOCKED, BlockingScope.ISP_BLOCK
    elif scope == "inst":
        return BlockingStatus.DOWN, BlockingScope.LOCAL_BLOCK
    elif scope == "fp":
        return BlockingStatus.DOWN, BlockingScope.SERVER_SIDE_BLOCK

    return BlockingStatus.BLOCKED, BlockingScope.UNKNOWN


class BlockingEvent(NamedTuple):
    blocking_status: BlockingStatus
    blocking_scope: BlockingScope
    blocking_subject: str
    blocking_detail: str
    blocking_meta: Mapping[str, str]
    confidence: float


@add_slots
@dataclass
class ExperimentResult:
    __table_name__ = "experiment_result"

    measurement_uid: str
    report_id: str
    input: str
    timestamp: datetime

    probe_asn: int
    probe_cc: str

    probe_as_org_name: str
    probe_as_cc: str

    network_type: str

    resolver_ip: Optional[str]
    resolver_asn: Optional[int]
    resolver_as_org_name: Optional[str]
    resolver_as_cc: Optional[str]
    resolver_cc: Optional[str]

    observation_ids: List[str]

    ok_confidence: float

    anomaly: bool
    confirmed: bool

    blocking_meta: Mapping[str, str] = field(default_factory=dict)
    blocking_status: str = "d"
    blocking_scope: str = "u"
    blocking_subject: str = ""
    blocking_detail: str = ""
    confidence: float = 0

    experiment_result_id: str = ""
    experiment_group: str = "generic"
    domain_name: str = ""
    website_name: str = ""

    def with_blocking_events(
        self, be_list: List[BlockingEvent]
    ) -> Generator["ExperimentResult", None, None]:
        for idx, be in enumerate(be_list):
            yield dataclasses.replace(
                self,
                experiment_result_id=f"{self.measurement_uid}_{idx}",
                blocking_meta=be.blocking_meta,
                blocking_status=be.blocking_status.value,
                blocking_scope=be.blocking_scope.value,
                blocking_subject=be.blocking_subject,
                blocking_detail=be.blocking_detail,
            )


def make_base_result_meta(obs: MeasurementMeta) -> dict:
    return dict(
        measurement_uid=obs.measurement_uid,
        report_id=obs.report_id,
        input=obs.input,
        timestamp=obs.measurement_start_time,
        probe_asn=obs.probe_asn,
        probe_cc=obs.probe_cc,
        probe_as_org_name=obs.probe_as_org_name,
        probe_as_cc=obs.probe_as_cc,
        network_type=obs.network_type,
        resolver_ip=obs.resolver_ip,
        resolver_asn=obs.resolver_asn,
        resolver_as_org_name=obs.resolver_as_org_name,
        resolver_as_cc=obs.resolver_as_cc,
        resolver_cc=obs.resolver_cc,
    )
