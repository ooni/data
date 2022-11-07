import logging
from typing import List, Optional, NamedTuple
from enum import Enum
from datetime import datetime
from dataclasses import dataclass


from oonidata.observations import (
    Observation,
)

log = logging.getLogger("oonidata.events")


class BlockingType(Enum):
    # k: everything is OK
    OK = "k"
    # b: blocking is happening with an unknown scope
    BLOCKED = "b"
    # n: national level blocking
    NATIONAL_BLOCK = "n"
    # i: isp level blocking
    ISP_BLOCK = "i"
    # l: local blocking (school, office, home network)
    LOCAL_BLOCK = "l"
    # s: server-side blocking
    SERVER_SIDE_BLOCK = "s"
    # d: the subject is down
    DOWN = "d"
    # t: this is a signal indicating some form of network throttling
    THROTTLING = "t"


def fp_scope_to_outcome(scope: Optional[str]) -> BlockingType:
    # "nat" national level blockpage
    # "isp" ISP level blockpage
    # "prod" text pattern related to a middlebox product
    # "inst" text pattern related to a voluntary instition blockpage (school, office)
    # "vbw" vague blocking word
    # "fp" fingerprint for false positives
    if scope == "nat":
        return BlockingType.NATIONAL_BLOCK
    elif scope == "isp":
        return BlockingType.ISP_BLOCK
    elif scope == "inst":
        return BlockingType.LOCAL_BLOCK
    elif scope == "fp":
        return BlockingType.SERVER_SIDE_BLOCK
    return BlockingType.BLOCKED


class BlockingEvent(NamedTuple):
    blocking_type: BlockingType
    blocking_subject: str
    blocking_detail: str
    blocking_meta: dict
    confidence: float


@dataclass
class ExperimentResult:
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
    blocking_events: List[BlockingEvent]
    ok_confidence: float

    anomaly: bool
    confirmed: bool


def make_base_result_meta(obs: Observation) -> dict:
    return dict(
        measurement_uid=obs.measurement_uid,
        report_id=obs.report_id,
        input=obs.input,
        timestamp=obs.timestamp,
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
