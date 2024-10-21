import dataclasses

from typing import TypedDict
from dataclasses import asdict, dataclass
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


class Loni(TypedDict):
    ok: float
    down: float
    blocked: float
    label: str
    target: str


class ExperimentResult(NamedTuple):
    __table_name__ = "experiment_result"

    created_at: datetime

    measurement_uid: str
    report_id: str

    input: str
    input_options: Dict[str, Any]
    domain: str
    domain_category_code: str

    probe_cc: str
    probe_asn: int

    probe_as_org_name: str
    probe_as_cc: str

    network_type: str

    resolver_ip: Optional[str]
    resolver_asn: Optional[int]
    resolver_as_org_name: Optional[str]
    resolver_as_cc: Optional[str]
    resolver_cc: Optional[str]

    test_name: str
    test_version: str
    nettest_group: str

    software_name: str
    software_version: str

    architecture: Optional[str]
    engine_name: Optional[str]
    engine_version: Optional[str]

    measurement_start_time: datetime

    test_runtime: float

    test_helper_address: Optional[str]
    test_helper_type: Optional[str]
    ooni_run_link_id: Optional[str]

    anomaly: bool
    confirmed: bool
    msm_failure: bool

    probe_analysis: Optional[str]

    blocking_scope: Optional[str]

    # Likelyhood of network interference values which define a probability space
    loni_down_value: float
    loni_blocked_value: float
    loni_ok_value: float
    loni_label: str

    # Encoded as JSON
    loni_list: List[Loni]

    # Inside this string we include a representation of the logic that lead us
    # to produce the above loni values
    analysis_transcript_list: List[List[str]]


def make_experiment_result(
    obs: WebObservation,
    domain: str,
    test_helper_address: Optional[str],
    test_runtime: float,
    ooni_run_link_id: Optional[str],
    nettest_group: str,
    probe_analysis: Optional[str],
    blocking_scope: Optional[str],
    msm_failure: bool,
    loni_list: List[Loni],
    analysis_transcript_list: List[List[str]],
) -> ExperimentResult:
    created_at = datetime.now(timezone.utc).replace(tzinfo=None)
    test_helper_type = None
    if test_helper_address and test_helper_address.startswith("https://"):
        test_helper_type = "https"

    confirmed = False
    anomaly = False
    loni_ok_value = 0.0
    loni_down_value = 0.0
    loni_blocked_value = 0.0
    blocked, down, ok = [], [], []
    for loni in loni_list:
        blocked.append((loni["blocked"], loni["label"]))
        down.append((loni["down"], loni["label"]))
        ok.append((loni["ok"], loni["label"]))
    loni_blocked = max(blocked, key=lambda x: x[0])
    loni_down = max(down, key=lambda x: x[0])
    loni_blocked_value = loni_blocked[0]
    loni_down_value = loni_down[0]
    loni_ok_value = 1 - (loni_blocked_value + loni_down_value)
    loni_label = ""
    if loni_ok_value > 0.5:
        loni_label = "ok"
    elif loni_blocked_value > loni_down_value:
        if loni_blocked_value == 1:
            confirmed = True
        loni_label = f"{loni_blocked[1]}"
        anomaly = True
    else:
        loni_label = f"{loni_down[1]}"

    assert loni_label != "", "unable to set loni_label"

    return ExperimentResult(
        created_at=created_at,
        measurement_uid=obs.measurement_meta.measurement_uid,
        report_id=obs.measurement_meta.report_id,
        input=obs.measurement_meta.input if obs.measurement_meta.input else "",
        input_options={},
        domain=domain,
        domain_category_code="",
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
        test_name=obs.measurement_meta.test_name,
        test_version=obs.measurement_meta.test_version,
        nettest_group=nettest_group,
        software_name=obs.measurement_meta.software_name,
        software_version=obs.measurement_meta.software_version,
        architecture=obs.probe_meta.architecture,
        engine_name=obs.probe_meta.engine_name,
        engine_version=obs.probe_meta.engine_version,
        measurement_start_time=obs.measurement_meta.measurement_start_time,
        test_runtime=test_runtime,
        test_helper_address=test_helper_address,
        test_helper_type=test_helper_type,
        ooni_run_link_id=ooni_run_link_id,
        anomaly=anomaly,
        confirmed=confirmed,
        msm_failure=msm_failure,
        probe_analysis=probe_analysis,
        blocking_scope=blocking_scope,
        loni_ok_value=loni_ok_value,
        loni_blocked_value=loni_blocked_value,
        loni_down_value=loni_down_value,
        loni_label=loni_label,
        loni_list=loni_list,
        analysis_transcript_list=analysis_transcript_list,
    )
