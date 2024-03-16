from typing import List, Generator

from oonidata.models.experiment_result import (
    BlockingScope,
    ExperimentResult,
    Outcome,
    fp_to_scope,
    iter_experiment_results,
)
from oonidata.fingerprintdb import FingerprintDB
from oonidata.models.observations import WebObservation


def make_signal_experiment_result(
    web_observations: List[WebObservation],
    fingerprintdb: FingerprintDB,
) -> Generator[ExperimentResult, None, None]:
    confirmed = False
    anomaly = False
    experiment_group = "im"
    target_name = "signal"
    outcome_label = ""

    outcomes = []
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

    for web_o in web_observations:
        dns_blocked = False
        tcp_blocked = False

        if web_o.hostname == "uptime.signal.org":
            # we don't care about the signal uptime query results
            continue

        if web_o.dns_failure:
            anomaly = True
            outcome_meta = {}
            outcome_meta["why"] = "dns failure"
            outcomes.append(
                Outcome(
                    observation_id=web_o.observation_id,
                    scope=BlockingScope.UNKNOWN,
                    subject=f"{web_o.hostname}",
                    category="dns",
                    label="",
                    detail=f"{web_o.dns_failure}",
                    meta={},
                    blocked_score=0.8,
                    down_score=0.2,
                    ok_score=0.0,
                )
            )
            continue

        if web_o.dns_answer and not web_o.tls_is_certificate_valid:
            # We don't set the anomaly flag, because this logic is very
            # susceptible to false positives
            # anomaly = True
            outcome_meta = {}
            outcome_meta["why"] = "tls is inconsistent"
            outcome_meta["ip"] = web_o.dns_answer

            blocked_score = 0.6
            down_score = 0.0
            blocking_scope = BlockingScope.UNKNOWN
            fp = fingerprintdb.match_dns(web_o.dns_answer)
            if fp:
                blocking_scope = fp_to_scope(fp.scope)
                if blocking_scope != BlockingScope.SERVER_SIDE_BLOCK:
                    dns_blocked = True
                    confirmed = True
                    anomaly = True
                    outcome_label = "blocked"
                outcome_meta["fingerprint"] = fp.name
                # TODO: add country consistency checks

            # Having a TLS inconsistency is a much stronger indication than not
            # knowing.
            if web_o.tls_is_certificate_valid == False:
                # In these case we ignore TCP failures, since it's very likely
                # to be DNS based.
                dns_blocked = True
                anomaly = True
                blocked_score = 0.8

            # TODO: Is this reasonable?
            if signal_is_down == True and confirmed == False:
                down_score = 0.8
                blocked_score = 0.0

            outcomes.append(
                Outcome(
                    observation_id=web_o.observation_id,
                    scope=BlockingScope.UNKNOWN,
                    subject=f"{web_o.hostname}",
                    category="dns",
                    label=outcome_label,
                    detail=f"{web_o.dns_failure}",
                    meta={},
                    blocked_score=blocked_score,
                    down_score=down_score,
                    ok_score=1 - (blocked_score + down_score),
                )
            )
        else:
            outcomes.append(
                Outcome(
                    observation_id=web_o.observation_id,
                    scope=BlockingScope.UNKNOWN,
                    subject=f"{web_o.hostname}",
                    category="dns",
                    label=outcome_label,
                    detail=f"{web_o.dns_failure}",
                    meta={"why": "TLS consistent answer"},
                    blocked_score=0.2,
                    down_score=0.0,
                    ok_score=0.8,
                )
            )

        if not dns_blocked and web_o.tcp_failure:
            down_score = 0.0
            blocked_score = 0.7
            anomaly = True
            tcp_blocked = True
            if signal_is_down == True:
                down_score = 0.9
                blocked_score = 0.0
                anomaly = False

            outcomes.append(
                Outcome(
                    observation_id=web_o.observation_id,
                    scope=BlockingScope.UNKNOWN,
                    subject=f"{web_o.ip}:{web_o.port}",
                    category="tcp",
                    label="",
                    detail=f"{web_o.tcp_failure}",
                    meta={"why": "tcp failure"},
                    blocked_score=blocked_score,
                    down_score=down_score,
                    ok_score=1 - (blocked_score + down_score),
                )
            )

        elif not dns_blocked and web_o.tcp_success:
            outcomes.append(
                Outcome(
                    observation_id=web_o.observation_id,
                    scope=BlockingScope.UNKNOWN,
                    subject=f"{web_o.ip}:{web_o.port}",
                    category="tcp",
                    label=outcome_label,
                    detail=f"ok",
                    meta={},
                    blocked_score=0.0,
                    down_score=0.0,
                    ok_score=1.0,
                )
            )

        if (
            not dns_blocked
            and not tcp_blocked
            and web_o.tls_failure
            and not web_o.tls_failure.startswith("ssl_")
        ):
            down_score = 0.3
            blocked_score = 0.7
            anomaly = True
            if signal_is_down == True:
                down_score = 0.9
                blocked_score = 0.1
                anomaly = False

            outcomes.append(
                Outcome(
                    observation_id=web_o.observation_id,
                    scope=BlockingScope.UNKNOWN,
                    subject=f"{web_o.hostname}",
                    category="tls",
                    label="",
                    detail=f"{web_o.tls_failure}",
                    meta={},
                    blocked_score=blocked_score,
                    down_score=down_score,
                    ok_score=1 - (blocked_score + down_score),
                )
            )

        # TODO: to do this properly we need to rule out cases in which the
        # certificate is invalid due to bad DNS vs it being invalid due to TLS
        # MITM. Doing so requires a ground truth which we should eventually add.
        elif web_o.tls_is_certificate_valid == False:
            # TODO: maybe refactor this with the above switch case
            down_score = 0.1
            blocked_score = 0.9
            anomaly = True
            if signal_is_down == True:
                down_score = 0.9
                blocked_score = 0.1
                anomaly = False

            outcomes.append(
                Outcome(
                    observation_id=web_o.observation_id,
                    scope=BlockingScope.UNKNOWN,
                    subject=f"{web_o.hostname}",
                    category="tls",
                    label="",
                    detail=f"ssl_invalid_certificate",
                    meta={},
                    blocked_score=blocked_score,
                    down_score=down_score,
                    ok_score=1 - (blocked_score + down_score),
                )
            )
        elif not dns_blocked and not tcp_blocked and web_o.tls_cipher_suite is not None:
            outcomes.append(
                Outcome(
                    observation_id=web_o.observation_id,
                    scope=BlockingScope.UNKNOWN,
                    subject=f"{web_o.hostname}",
                    category="tls",
                    label="",
                    detail="ok",
                    meta={},
                    blocked_score=0.0,
                    down_score=0.0,
                    ok_score=1.0,
                )
            )

    return iter_experiment_results(
        obs=web_observations[0],
        experiment_group=experiment_group,
        domain_name=target_name,
        target_name=target_name,
        anomaly=anomaly,
        confirmed=confirmed,
        outcomes=outcomes,
    )
