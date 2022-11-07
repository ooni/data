from typing import List
from oonidata.dataformat import SIGNAL_PEM_STORE
from oonidata.datautils import InvalidCertificateChain, TLSCertStore
from oonidata.experiments.experiment_result import (
    BlockingEvent,
    BlockingType,
    ExperimentResult,
    fp_scope_to_outcome,
    make_base_result_meta,
)
from oonidata.fingerprintdb import FingerprintDB
from oonidata.netinfo import NetinfoDB
from oonidata.observations import (
    DNSObservation,
    HTTPObservation,
    NettestObservation,
    TCPObservation,
    TLSObservation,
)


class SignalExperimentResult(ExperimentResult):
    pass


def make_signal_experiment_result(
    nt_obs: NettestObservation,
    dns_o_list: List[DNSObservation],
    tcp_o_list: List[TCPObservation],
    tls_o_list: List[TLSObservation],
    http_o_list: List[HTTPObservation],
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
) -> SignalExperimentResult:
    # We got nothin', we can't do nothin'
    assert len(dns_o_list) > 0, "empty DNS observation list"

    confirmed = False
    anomaly = False

    signal_is_down = False

    blocking_events = []
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
            blocking_events.append(
                BlockingEvent(
                    blocking_type=BlockingType.BLOCKED,
                    blocking_subject=f"{dns_o.domain_name}",
                    blocking_detail=f"dns.{dns_o.failure}",
                    blocking_meta={},
                    confidence=0.8,
                )
            )
            continue

        if not dns_o.is_tls_consistent:
            # We don't set the anomaly flag, because this logic is very
            # susceptible to false positives
            # anomaly = True
            blocking_meta = {"why": "tls_inconsistent", "ip": dns_o.answer}
            blocking_type = BlockingType.BLOCKED
            fp = fingerprintdb.match_dns(dns_o.answer)
            if fp:
                blocking_type = fp_scope_to_outcome(fp.scope)
                if blocking_type != BlockingType.SERVER_SIDE_BLOCK:
                    confirmed = True
                    anomaly = True
                blocking_meta["fp_name"] = fp.name

            confidence = 0.3
            # Having a TLS inconsistency is a much stronger indication than not
            # knowing.
            if dns_o.is_tls_consistent == False:
                inconsistent_dns_answers.add(dns_o.answer)
                # Only set the anomaly here
                anomaly = True
                confidence = 0.8

            blocking_events.append(
                BlockingEvent(
                    blocking_type=blocking_type,
                    blocking_detail="dns.inconsistent",
                    blocking_subject=f"{dns_o.domain_name}",
                    blocking_meta=blocking_meta,
                    confidence=confidence,
                )
            )
            continue

    if signal_is_down:
        # The service is down. No point in going on with the analysis
        # It's still possible for the service to be down, yet there to be DNS
        # level interference, so we still count the other blocking_events if they were
        # present.
        blocking_events.append(
            BlockingEvent(
                blocking_type=BlockingType.DOWN,
                blocking_subject="Signal Messenger",
                blocking_detail="down",
                blocking_meta={},
                confidence=0.9,
            )
        )
        return SignalExperimentResult(
            blocking_events=blocking_events,
            observation_ids=observation_ids,
            anomaly=anomaly,
            confirmed=confirmed,
            **make_base_result_meta(nt_obs),
        )

    for tcp_o in tcp_o_list:
        observation_ids.append(tcp_o.observation_id)
        if tcp_o.failure and tcp_o.ip not in inconsistent_dns_answers:
            anomaly = True
            blocking_events.append(
                BlockingEvent(
                    blocking_type=BlockingType.BLOCKED,
                    blocking_subject=f"{tcp_o.ip}:{tcp_o.port}",
                    blocking_detail=f"tcp.{tcp_o.failure}",
                    blocking_meta={},
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
            blocking_events.append(
                BlockingEvent(
                    blocking_type=BlockingType.BLOCKED,
                    blocking_subject=f"{tls_o.server_name}",
                    blocking_detail=f"tls.{tls_o.failure}",
                    blocking_meta={},
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
                blocking_events.append(
                    BlockingEvent(
                        blocking_type=BlockingType.BLOCKED,
                        blocking_subject=f"{tls_o.server_name}",
                        blocking_detail=f"tls.ssl_invalid_certificate",
                        blocking_meta={"cert_error": str(exc)},
                        confidence=0.9,
                    )
                )

    # This is an upper bound, which means we might be over-estimating blocking
    ok_confidence = 1 - max(map(lambda o: o.confidence, blocking_events), default=0)
    blocking_events.append(
        BlockingEvent(
            blocking_type=BlockingType.OK,
            blocking_subject=f"Signal Messenger",
            blocking_detail=f"ok",
            blocking_meta={},
            confidence=ok_confidence,
        )
    )

    # TODO: add support for validating if the HTTP responses are also consistent
    return SignalExperimentResult(
        blocking_events=blocking_events,
        observation_ids=observation_ids,
        anomaly=anomaly,
        confirmed=confirmed,
        ok_confidence=ok_confidence,
        **make_base_result_meta(nt_obs),
    )
