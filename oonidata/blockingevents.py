import logging
from typing import List, Optional, NamedTuple
from enum import Enum
from datetime import datetime
from dataclasses import dataclass
from oonidata.dataformat import SIGNAL_PEM_STORE
from oonidata.fingerprintdb import FingerprintDB
from oonidata.netinfo import NetinfoDB
from oonidata.datautils import (
    TLSCertStore,
    InvalidCertificateChain,
)

from oonidata.observations import (
    DNSObservation,
    HTTPObservation,
    NettestObservation,
    Observation,
    TCPObservation,
    TLSObservation,
)

log = logging.getLogger("oonidata.events")


class OutcomeType(Enum):
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


def fp_scope_to_outcome(scope: Optional[str]) -> OutcomeType:
    # "nat" national level blockpage
    # "isp" ISP level blockpage
    # "prod" text pattern related to a middlebox product
    # "inst" text pattern related to a voluntary instition blockpage (school, office)
    # "vbw" vague blocking word
    # "fp" fingerprint for false positives
    if scope == "nat":
        return OutcomeType.NATIONAL_BLOCK
    elif scope == "isp":
        return OutcomeType.ISP_BLOCK
    elif scope == "inst":
        return OutcomeType.LOCAL_BLOCK
    elif scope == "fp":
        return OutcomeType.SERVER_SIDE_BLOCK
    return OutcomeType.BLOCKED


class Outcome(NamedTuple):
    outcome_type: OutcomeType
    outcome_subject: str
    outcome_detail: str
    outcome_meta: dict
    confidence: float


@dataclass
class BlockingEvent:
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
    outcomes: List[Outcome]
    ok_confidence: float

    anomaly: bool
    confirmed: bool


@dataclass
class WebsiteBlockingEvent(BlockingEvent):
    domain_name: str
    website_name: str


class SignalBlockingEvent(BlockingEvent):
    pass


def make_base_event_meta(obs: Observation) -> dict:
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


def make_signal_blocking_event(
    nt_obs: NettestObservation,
    dns_o_list: List[DNSObservation],
    tcp_o_list: List[TCPObservation],
    tls_o_list: List[TLSObservation],
    http_o_list: List[HTTPObservation],
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
) -> SignalBlockingEvent:
    # We got nothin', we can't do nothin'
    assert len(dns_o_list) > 0, "empty DNS observation list"

    confirmed = False
    anomaly = False

    signal_is_down = False

    outcomes = []
    observation_ids = []
    inconsistent_dns_answers = set()

    for dns_o in dns_o_list:
        observation_ids.append(dns_o.observation_id)
        if dns_o.domain_name == "uptime.signal.org":
            # This DNS query is used by signal to figure out if some of it's
            # services are down.
            # see: https://github.com/signalapp/Signal-Android/blob/c4bc2162f23e0fd6bc25941af8fb7454d91a4a35/app/src/main/java/org/thoughtcrime/securesms/jobs/ServiceOutageDetectionJob.java#L25
            # TODO: should we do something in the case in which we can't tell
            # because DNS blocking is going on (ex. in Iran)?
            if dns_o.answer == "127.0.0.2":
                signal_is_down = True
            continue

        if dns_o.failure:
            anomaly = True
            outcomes.append(
                Outcome(
                    outcome_type=OutcomeType.BLOCKED,
                    outcome_subject=f"{dns_o.domain_name}",
                    outcome_detail=f"dns.{dns_o.failure}",
                    outcome_meta={},
                    confidence=0.8,
                )
            )
            continue

        if not dns_o.is_tls_consistent:
            # We don't set the anomaly flag, because this logic is very
            # susceptible to false positives
            # anomaly = True
            outcome_meta = {"why": "tls_inconsistent", "ip": dns_o.answer}
            outcome_type = OutcomeType.BLOCKED
            fp = fingerprintdb.match_dns(dns_o.answer)
            if fp:
                outcome_type = fp_scope_to_outcome(fp.scope)
                if outcome_type != OutcomeType.SERVER_SIDE_BLOCK:
                    confirmed = True
                    anomaly = True
                outcome_meta["fp_name"] = fp.name

            confidence = 0.3
            # Having a TLS inconsistency is a much stronger indication than not
            # knowing.
            if dns_o.is_tls_consistent == False:
                inconsistent_dns_answers.add(dns_o.answer)
                # Only set the anomaly here
                anomaly = True
                confidence = 0.8

            outcomes.append(
                Outcome(
                    outcome_type=outcome_type,
                    outcome_detail="dns.inconsistent",
                    outcome_subject=f"{dns_o.domain_name}",
                    outcome_meta=outcome_meta,
                    confidence=confidence,
                )
            )
            continue

    if signal_is_down:
        # The service is down. No point in going on with the analysis
        # It's still possible for the service to be down, yet there to be DNS
        # level interference, so we still count the other outcomes if they were
        # present.
        outcomes.append(
            Outcome(
                outcome_type=OutcomeType.DOWN,
                outcome_subject="Signal Messenger",
                outcome_detail="down",
                outcome_meta={},
                confidence=0.9,
            )
        )
        return SignalBlockingEvent(
            outcomes=outcomes,
            observation_ids=observation_ids,
            anomaly=anomaly,
            confirmed=confirmed,
            **make_base_event_meta(nt_obs),
        )

    for tcp_o in tcp_o_list:
        observation_ids.append(tcp_o.observation_id)
        if tcp_o.failure and tcp_o.ip not in inconsistent_dns_answers:
            anomaly = True
            outcomes.append(
                Outcome(
                    outcome_type=OutcomeType.BLOCKED,
                    outcome_subject=f"{tcp_o.ip}:{tcp_o.port}",
                    outcome_detail=f"tcp.{tcp_o.failure}",
                    outcome_meta={},
                    confidence=0.7,
                )
            )

    cert_store = TLSCertStore(pem_cert_store=SIGNAL_PEM_STORE)
    for tls_o in tls_o_list:
        observation_ids.append(tls_o.observation_id)
        # We skip analyzing TLS handshakes that are the result of an
        # inconsistent DNS resolution.
        if tls_o.ip in inconsistent_dns_answers:
            continue

        if tls_o.failure and not tls_o.failure.startswith("ssl_"):
            anomaly = True
            outcomes.append(
                Outcome(
                    outcome_type=OutcomeType.BLOCKED,
                    outcome_subject=f"{tls_o.server_name}",
                    outcome_detail=f"tls.{tls_o.failure}",
                    outcome_meta={},
                    confidence=0.7,
                )
            )

        if tls_o.peer_certificates:
            try:
                _, _ = cert_store.validate_cert_chain(
                    tls_o.timestamp, tls_o.peer_certificates
                )
                # The server_name is listed in the SAN only for the older certs.
                # Since we are pinning to only the two known signal CAs it's
                # probably safe to just ignore.
            except InvalidCertificateChain as exc:
                anomaly = True
                outcomes.append(
                    Outcome(
                        outcome_type=OutcomeType.BLOCKED,
                        outcome_subject=f"{tls_o.server_name}",
                        outcome_detail=f"tls.ssl_invalid_certificate",
                        outcome_meta={"cert_error": str(exc)},
                        confidence=0.9,
                    )
                )

    # This is an upper bound, which means we might be over-estimating blocking
    ok_confidence = 1 - max(map(lambda o: o.confidence, outcomes), default=0)
    outcomes.append(
        Outcome(
            outcome_type=OutcomeType.OK,
            outcome_subject=f"Signal Messenger",
            outcome_detail=f"ok",
            outcome_meta={},
            confidence=ok_confidence,
        )
    )

    # TODO: add support for validating if the HTTP responses are also consistent
    return SignalBlockingEvent(
        outcomes=outcomes,
        observation_ids=observation_ids,
        anomaly=anomaly,
        confirmed=confirmed,
        ok_confidence=ok_confidence,
        **make_base_event_meta(nt_obs),
    )
