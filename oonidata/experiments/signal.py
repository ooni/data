from typing import List, Generator

from oonidata.dataformat import SIGNAL_PEM_STORE
from oonidata.datautils import InvalidCertificateChain, TLSCertStore
from oonidata.experiments.experiment_result import (
    BlockingEvent,
    BlockingStatus,
    BlockingScope,
    ExperimentResult,
    fp_scope_to_status_scope,
    make_base_result_meta,
)
from oonidata.fingerprintdb import FingerprintDB
from oonidata.netinfo import NetinfoDB
from oonidata.observations import (
    WebObservation,
)


def make_signal_experiment_result(
    web_observations: List[WebObservation],
    fingerprintdb: FingerprintDB,
) -> Generator[ExperimentResult, None, None]:
    confirmed = False
    anomaly = False

    base_er = ExperimentResult(
        observation_ids=[],
        anomaly=anomaly,
        confirmed=confirmed,
        ok_confidence=0,
        **make_base_result_meta(web_observations[0]),
    )

    blocking_events = []
    observation_ids = []

    # This DNS query is used by signal to figure out if some of it's
    # services are down.
    # see: https://github.com/signalapp/Signal-Android/blob/c4bc2162f23e0fd6bc25941af8fb7454d91a4a35/app/src/main/java/org/thoughtcrime/securesms/jobs/ServiceOutageDetectionJob.java#L25
    # TODO: should we do something in the case in which we can't tell
    # because DNS blocking is going on (ex. in Iran)?
    signal_is_down = (
        len(
            list(
                filter(
                    lambda o: (
                        o.hostname == "uptime.signal.org"
                        and o.dns_answer == "127.0.0.2"
                    ),
                    web_observations,
                )
            )
        )
        > 0
    )
    if signal_is_down:
        # The service is down. No point in going on with the analysis
        # It's still possible for the service to be down, yet there to be DNS
        # level interference, so we still count the other blocking_events if they were
        # present.
        blocking_events.append(
            BlockingEvent(
                blocking_status=BlockingStatus.DOWN,
                blocking_scope=BlockingScope.UNKNOWN,
                blocking_subject="Signal Messenger",
                blocking_detail="down",
                blocking_meta={},
                confidence=0.9,
            )
        )
        return base_er.with_blocking_events(blocking_events)

    for web_o in web_observations:
        dns_blocked = False

        observation_ids.append(web_o.observation_id)
        if web_o.hostname == "uptime.signal.org":
            # we don't care about the signal uptime query results
            continue

        if web_o.dns_failure:
            anomaly = True
            blocking_events.append(
                BlockingEvent(
                    blocking_status=BlockingStatus.BLOCKED,
                    blocking_scope=BlockingScope.UNKNOWN,
                    blocking_subject=f"{web_o.hostname}",
                    blocking_detail=f"dns.{web_o.dns_failure}",
                    blocking_meta={},
                    confidence=0.8,
                )
            )
            continue

        if web_o.dns_answer and not web_o.tls_is_certificate_valid:
            # We don't set the anomaly flag, because this logic is very
            # susceptible to false positives
            # anomaly = True
            blocking_meta = {"why": "tls_inconsistent", "ip": web_o.dns_answer}
            blocking_status = BlockingStatus.BLOCKED
            blocking_scope = BlockingScope.UNKNOWN
            fp = fingerprintdb.match_dns(web_o.dns_answer)
            if fp:
                blocking_status, blocking_scope = fp_scope_to_status_scope(fp.scope)
                if blocking_status == BlockingStatus.BLOCKED:
                    dns_blocked = True
                    confirmed = True
                    anomaly = True
                blocking_meta["fp_name"] = fp.name

            confidence = 0.3

            # Having a TLS inconsistency is a much stronger indication than not
            # knowing.
            if web_o.tls_is_certificate_valid == False:
                # In these case we ignore TCP failures, since it's very likely
                # to be DNS based.
                dns_blocked = True
                anomaly = True
                confidence = 0.8

            blocking_events.append(
                BlockingEvent(
                    blocking_status=blocking_status,
                    blocking_scope=blocking_scope,
                    blocking_detail="dns.inconsistent",
                    blocking_subject=f"{web_o.hostname}",
                    blocking_meta=blocking_meta,
                    confidence=confidence,
                )
            )

        if not dns_blocked and web_o.tcp_failure:
            anomaly = True
            blocking_events.append(
                BlockingEvent(
                    blocking_status=BlockingStatus.BLOCKED,
                    blocking_scope=BlockingScope.UNKNOWN,
                    blocking_subject=f"{web_o.ip}:{web_o.port}",
                    blocking_detail=f"tcp.{web_o.tcp_failure}",
                    blocking_meta={},
                    confidence=0.7,
                )
            )

        if (
            not dns_blocked
            and web_o.tls_failure
            and not web_o.tls_failure.startswith("ssl_")
        ):
            anomaly = True
            blocking_events.append(
                BlockingEvent(
                    blocking_status=BlockingStatus.BLOCKED,
                    blocking_scope=BlockingScope.UNKNOWN,
                    blocking_subject=f"{web_o.hostname}",
                    blocking_detail=f"tls.{web_o.tls_failure}",
                    blocking_meta={},
                    confidence=0.7,
                )
            )

        # TODO: to do this properly we need to rule out cases in which the
        # certificate is invalid due to bad DNS vs it being invalid due to TLS
        # MITM. Doing so requires a ground truth which we should eventually add.
        if web_o.tls_is_certificate_valid == False:
            anomaly = True
            blocking_events.append(
                BlockingEvent(
                    blocking_status=BlockingStatus.BLOCKED,
                    blocking_scope=BlockingScope.UNKNOWN,
                    blocking_subject=f"{web_o.hostname}",
                    blocking_detail=f"tls.ssl_invalid_certificate",
                    blocking_meta={},
                    confidence=0.9,
                )
            )

    # This is an upper bound, which means we might be over-estimating blocking
    ok_confidence = 1 - max(map(lambda o: o.confidence, blocking_events), default=0)
    blocking_events.append(
        BlockingEvent(
            blocking_status=BlockingStatus.OK,
            blocking_scope=BlockingScope.UNKNOWN,
            blocking_subject=f"Signal Messenger",
            blocking_detail=f"ok",
            blocking_meta={},
            confidence=ok_confidence,
        )
    )

    base_er.ok_confidence = ok_confidence
    base_er.anomaly = anomaly
    base_er.confirmed = confirmed
    # TODO: move the observation_ids into the blocking_events row that they pertain to
    base_er.observation_ids = observation_ids
    return base_er.with_blocking_events(blocking_events)
