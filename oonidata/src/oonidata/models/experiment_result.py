import dataclasses
from dataclasses import dataclass
import logging
from typing import Any, Dict, Generator, List, Optional, NamedTuple, Mapping, Tuple
from enum import Enum
from datetime import datetime, timezone

from tabulate import tabulate

from ..datautils import maybe_elipse

from .base import table_model
from .observations import ProbeMeta, MeasurementMeta, WebObservation

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


@table_model(
    table_name="measurement_experiment_result",
    table_index=(
        "measurement_uid",
        "timeofday",
    ),
)
@dataclass
class MeasurementExperimentResult:
    measurement_meta: MeasurementMeta
    probe_meta: ProbeMeta

    # The list of observations used to generate this experiment result
    observation_id_list: List[str]

    # The timeofday for which this experiment result is relevant. We use the
    # timeofday convention to differentiate it from the timestamp which is an
    # instant, while experiment results might indicate a range
    timeofday: datetime

    # When this experiment result was created
    created_at: datetime

    # Location attributes are relevant to qualify the location for which an
    # experiment result is relevant
    # The primary key for the location is the tuple:
    # (location_network_type, location_network_asn, location_network_cc, location_resolver_asn)

    # Maybe in the future we have this when we get geoip through other menas
    # location_region_cc: str
    # location_region_name: str
    location_network_type: str

    location_network_asn: int
    location_network_cc: str

    location_network_as_org_name: str
    location_network_as_cc: str

    # Maybe this should be dropped, as it would make the dimension potentially explode.
    # location_resolver_ip: Optional[str]
    location_resolver_asn: Optional[int]
    location_resolver_as_org_name: Optional[str]
    location_resolver_as_cc: Optional[str]
    location_resolver_cc: Optional[str]

    # The blocking scope signifies at which level we believe the blocking to be
    # implemented.
    # We put it in the location keys, since effectively the location definition
    # is relevant to map where in the network and space the blocking is
    # happening and is not necessarily a descriptor of the location of the
    # vantage points used to determine this.
    #
    # The scope can be: nat, isp, inst, fp to indicate national level blocking,
    # isp level blocking, local blocking (eg. university or comporate network)
    # or server-side blocking.
    location_blocking_scope: Optional[str]

    # Should we include this or not? Benefit of dropping it is that it collapses
    # the dimension when we do non-instant experiment results.
    # platform_name: Optional[str]

    # Target nettest group is the high level experiment group taxonomy, but may
    # in the future include also other more high level groupings.
    target_nettest_group: str
    # Target Category can be a citizenlab category code. Ex. GRP for social
    # networking
    target_category: str
    # This is a more granular, yet high level definition of the target. Ex.
    # facebook for all endpoints related to facebook
    target_name: str
    # This is the domain name associated with the target, for example for
    # facebook it will be www.facebook.com, but also edge-mqtt.facebook.com
    target_domain_name: str
    # This is the more granular level associated with a target, for example the IP, port tuple
    target_detail: str

    # Likelyhood of network interference values which define a probability space
    loni_ok_value: float

    # These are key value mappings that define how likely a certain class of
    # outcome is. Effectively it's an encoding of a dictionary, but in a way
    # where it's more efficient to peform operations on them.
    # Example: {"ok": 0.1, "down": 0.2, "blocked.dns": 0.3, "blocked.tls": 0.4}
    # would be encoded as:
    #
    # loni_ok_value: 0.1
    # loni_down_keys: ["down"]
    # loni_down_values: [0.2]
    # loni_blocked_keys: ["blocked.dns", "blocked.tls"]
    # loni_blocked_values: [0.3, 0.4]
    loni_down_keys: List[str]
    loni_down_values: List[float]

    loni_blocked_keys: List[str]
    loni_blocked_values: List[float]

    loni_ok_keys: List[str]
    loni_ok_values: List[float]

    # Encoded as JSON
    loni_list: List[Dict]

    # Inside this string we include a representation of the logic that lead us
    # to produce the above loni values
    analysis_transcript_list: List[List[str]]

    # Number of measurements used to produce this experiment result
    measurement_count: int
    # Number of observations used to produce this experiment result
    observation_count: int
    # Number of vantage points used to produce this experiment result
    vp_count: int

    # Backward compatible anomaly/confirmed flags
    anomaly: Optional[bool]
    confirmed: Optional[bool]


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
    obs: WebObservation,
    experiment_group: str,
    anomaly: bool,
    confirmed: bool,
    domain_name: str,
    target_name: str,
    outcomes: List[Outcome],
) -> Generator[ExperimentResult, None, None]:
    created_at = datetime.now(timezone.utc).replace(tzinfo=None)
    for idx, outcome in enumerate(outcomes):
        yield ExperimentResult(
            measurement_uid=obs.measurement_meta.measurement_uid,
            created_at=created_at,
            report_id=obs.measurement_meta.report_id,
            input=obs.measurement_meta.input,
            timestamp=obs.measurement_meta.measurement_start_time,
            probe_asn=obs.probe_meta.probe_asn,
            probe_cc=obs.probe_meta.probe_cc,
            probe_as_org_name=obs.probe_meta.probe_as_org_name,
            probe_as_cc=obs.probe_meta.probe_as_cc,
            network_type=obs.probe_meta.network_type,
            resolver_ip=obs.probe_meta.resolver_ip,
            resolver_asn=obs.probe_meta.resolver_asn,
            resolver_as_org_name=obs.probe_meta.resolver_as_org_name,
            resolver_as_cc=obs.probe_meta.resolver_as_cc,
            resolver_cc=obs.probe_meta.resolver_cc,
            experiment_result_id=f"{obs.measurement_meta.measurement_uid}_{idx}",
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
