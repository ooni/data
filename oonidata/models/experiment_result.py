import logging
from typing import Any, Dict, Generator, List, Optional, NamedTuple, Mapping, Tuple
from enum import Enum
from datetime import datetime

from oonidata.models.observations import MeasurementMeta

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


def fp_to_scope(
    scope: Optional[str],
) -> BlockingScope:
    # "nat" national level blockpage
    # "isp" ISP level blockpage
    # "prod" text pattern related to a middlebox product
    # "inst" text pattern related to a voluntary instition blockpage (school, office)
    # "vbw" vague blocking word
    # "fp" fingerprint for false positives
    if scope == "nat":
        return BlockingScope.NATIONAL_BLOCK
    elif scope == "isp":
        return BlockingScope.ISP_BLOCK
    elif scope == "inst":
        return BlockingScope.LOCAL_BLOCK
    elif scope == "fp":
        return BlockingScope.SERVER_SIDE_BLOCK

    return BlockingScope.UNKNOWN


class Scores(NamedTuple):
    ok: float
    down: float
    blocked: float


class Outcome(NamedTuple):
    observation_id: str
    subject: str
    scope: BlockingScope
    category: str
    detail: str
    meta: Mapping[str, str]
    label: str

    ok_score: float
    down_score: float
    blocked_score: float


class ExperimentResult(NamedTuple):
    __table_name__ = "experiment_result"

    measurement_uid: str
    observation_id: str
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

    anomaly: bool
    confirmed: bool

    ## These fields will be shared by multiple experiment results in a given
    ## measurement
    # Indicates the experiment group for this particular result, ex. im,
    # websites, circumvention
    experiment_group: str
    # The domain name for the specified target
    domain_name: str
    # A string indicating the name of the target, ex. Signal, Facebook website
    target_name: str

    ## These fields are unique to a particular experiment result
    # A string indicating the subject of this experiment result, for example an
    # IP:port combination.
    subject: str
    # In the event of blocking, indicates to what extent the blocking is
    # happening: ISP, National, Local, Server Side, Throttling, Unknown
    outcome_scope: str
    # Specifies the category of the outcome, usually indicating the protocol for
    # which we saw the block, ex. dns, tcp, tls, http, https
    outcome_category: str
    # Specifies, within the given class, what were the details of the outcome, ex. connection_reset, timeout, etc.
    outcome_detail: str
    # Additional metadata which can be used by an analyst to understand why the
    # analysis engine came to a certain conclusion
    outcome_meta: Mapping[str, str]

    # An additional label useful for assessing the metrics of the analysis
    # engine.
    # For example it can be used to include the blocking fingerprint flag.
    outcome_label: str

    # These are scores which estimate the likelyhood of this particular subject
    # being reachable, down or blocked.
    # The sum of all the scores for a given outcome will be 1.0
    ok_score: float
    down_score: float
    blocked_score: float

    experiment_result_id: str


def iter_experiment_results(
    obs: MeasurementMeta,
    experiment_group: str,
    anomaly: bool,
    confirmed: bool,
    domain_name: str,
    target_name: str,
    outcomes: List[Outcome],
) -> Generator[ExperimentResult, None, None]:
    created_at = datetime.utcnow()
    for idx, outcome in enumerate(outcomes):
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
            observation_id=outcome.observation_id,
            subject=outcome.subject,
            outcome_scope=outcome.scope.value,
            outcome_category=outcome.category,
            outcome_detail=outcome.detail,
            outcome_meta=outcome.meta,
            outcome_label=outcome.label,
            ok_score=outcome.ok_score,
            down_score=outcome.down_score,
            blocked_score=outcome.blocked_score,
        )
