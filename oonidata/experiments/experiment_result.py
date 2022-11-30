import logging
from typing import Any, Dict, Generator, List, Optional, NamedTuple, Mapping, Tuple
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


class ExperimentResult(NamedTuple):
    __table_name__ = "experiment_result"

    measurement_uid: str
    report_id: str
    input: Optional[str]
    timestamp: datetime
    created_at: datetime

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

    anomaly: bool
    confirmed: bool

    blocking_meta: Mapping[str, str]
    blocking_status: str
    blocking_scope: str
    blocking_subject: str
    blocking_detail: str
    blocking_confidence: float

    experiment_result_id: str
    experiment_group: str
    domain_name: str
    target_name: str


def iter_experiment_results(
    obs: MeasurementMeta,
    experiment_group: str,
    anomaly: bool,
    confirmed: bool,
    domain_name: str,
    target_name: str,
    observation_ids: List[str],
    be_list: List[BlockingEvent],
) -> Generator[ExperimentResult, None, None]:
    created_at = datetime.utcnow()
    for idx, be in enumerate(be_list):
        yield ExperimentResult(
            measurement_uid=obs.measurement_uid,
            created_at=created_at,
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
            experiment_result_id=f"{obs.measurement_uid}_{idx}",
            experiment_group=experiment_group,
            anomaly=anomaly,
            confirmed=confirmed,
            domain_name=domain_name,
            target_name=target_name,
            observation_ids=observation_ids,
            blocking_meta=be.blocking_meta,
            blocking_confidence=be.confidence,
            blocking_status=be.blocking_status.value,
            blocking_scope=be.blocking_scope.value,
            blocking_subject=be.blocking_subject,
            blocking_detail=be.blocking_detail,
        )
