import logging
from typing import List, Generator

from oonidata.models.experiment_result import (
    BlockingScope,
    ExperimentResult,
    Outcome,
    fp_to_scope,
    make_experiment_result,
    Loni,
)
from oonidata.models.nettests import Signal
from ..netinfo import NetinfoDB
from ..transforms.observations import measurement_to_observations

from ..fingerprintdb import FingerprintDB


log = logging.getLogger("oonidata.analysis")


def make_signal_experiment_result(
    msmt: Signal,
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
) -> ExperimentResult:

    web_observations = measurement_to_observations(
        msmt, netinfodb=netinfodb, bucket_date=""
    )[0]
    blocking_scope = BlockingScope.UNKNOWN
    msm_failure = False

    analysis_transcript = []
    loni_list = []
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
            analysis_transcript.append(f"dns_failure is not None")
            loni_list.append(
                Loni(
                    target=f"{web_o.hostname}",
                    label=f"dns.{web_o.dns_failure}",
                    blocked=0.8,
                    down=0.2,
                    ok=0.0,
                )
            )
            continue

        if web_o.dns_answer and not web_o.tls_is_certificate_valid:
            analysis_transcript.append(f"not tls_is_certificate_valid")

            blocked, down, ok = (0.3, 0.3, 0.3)
            outcome_label = f"tls.{web_o.tls_failure}"
            fp = fingerprintdb.match_dns(web_o.dns_answer)
            if fp:
                dns_blocked = True
                outcome_label = f"dns.inconsistent_answer"
                blocking_scope = fp_to_scope(fp.scope)
                analysis_transcript.append(f"fingerprint_name == '{fp.name}'")
                if blocking_scope != BlockingScope.SERVER_SIDE_BLOCK:
                    analysis_transcript.append(
                        f"fingerprint_scope != 'server_side_block'"
                    )
                    blocked, down, ok = (0.8, 0.2, 0.0)
                    outcome_label = f"dns.inconsistent_answer.network_block"
                    if (
                        fp.expected_countries
                        and web_o.probe_meta.probe_cc in fp.expected_countries
                    ):
                        analysis_transcript.append(f"probe_cc in expected_countries")
                        outcome_label = f"dns.inconsistent_answer.country_consistent"
                        blocked, down, ok = (1.0, 0.0, 0.0)
                else:
                    analysis_transcript.append(
                        f"fingerprint_scope == 'server_side_block'"
                    )
                    blocked, down, ok = (0.9, 0.0, 0.1)
                    outcome_label = f"dns.inconsistent_answer.server_side_block"

                # outcome_meta["fingerprint"] = fp.name

            # Having a TLS inconsistency is a much stronger indication than not
            # knowing.
            elif web_o.tls_is_certificate_valid == False:
                # In these case we ignore TCP failures, since it's very likely
                # to be DNS based.
                analysis_transcript.append(f"tls_is_certificate_valid == False")
                blocked, down, ok = (0.8, 0.0, 0.2)
                outcome_label = f"dns.invalid_answer.{web_o.tls_failure}"
                dns_blocked = True

            # TODO: Is this reasonable?
            elif signal_is_down == True:
                analysis_transcript.append(f"signal_is_down == True")
                blocked, down, ok = (0.0, 0.8, 0.2)

            loni_list.append(
                Loni(
                    target=f"{web_o.ip}@{web_o.hostname}",
                    label=outcome_label,
                    blocked=blocked,
                    down=down,
                    ok=ok,
                )
            )
        else:
            analysis_transcript.append(f"is_tls_certificate_valid == True")
            blocked, down, ok = (0.2, 0.0, 0.8)
            loni_list.append(
                Loni(
                    target=f"{web_o.ip}@{web_o.hostname}",
                    label="ok",
                    blocked=blocked,
                    down=down,
                    ok=ok,
                )
            )

        if not dns_blocked and web_o.tcp_failure:
            analysis_transcript.append(f"not dns_blocked and tcp_failure is not None")
            blocked, down, ok = (0.7, 0.0, 0.3)
            tcp_blocked = True
            outcome_label = f"tcp.{web_o.tcp_failure}"
            if signal_is_down == True:
                analysis_transcript.append(f"signal_is_down == True")
                blocked, down, ok = (0.0, 0.9, 0.1)

            loni_list.append(
                Loni(
                    target=f"{web_o.ip}:{web_o.port}@{web_o.hostname}",
                    label=outcome_label,
                    blocked=blocked,
                    down=down,
                    ok=ok,
                )
            )

        elif not dns_blocked and web_o.tcp_success:
            blocked, down, ok = (0.0, 0.0, 1.0)

            loni_list.append(
                Loni(
                    target=f"{web_o.ip}:{web_o.port}@{web_o.hostname}",
                    label="ok",
                    blocked=blocked,
                    down=down,
                    ok=ok,
                )
            )

        if (
            not dns_blocked
            and not tcp_blocked
            and web_o.tls_failure
            and not web_o.tls_failure.startswith("ssl_")
        ):
            blocked, down, ok = (0.7, 0.3, 0.0)
            if signal_is_down == True:
                blocked, down, ok = (0.1, 0.9, 0.0)

            outcome_label = f"tls.{web_o.tls_failure}"

            loni_list.append(
                Loni(
                    target=f"{web_o.ip}@{web_o.hostname}",
                    label=outcome_label,
                    blocked=blocked,
                    down=down,
                    ok=ok,
                )
            )

        # TODO: to do this properly we need to rule out cases in which the
        # certificate is invalid due to bad DNS vs it being invalid due to TLS
        # MITM. Doing so requires a ground truth which we should eventually add.
        elif web_o.tls_is_certificate_valid == False:
            # TODO: maybe refactor this with the above switch case
            blocked, down, ok = (0.9, 0.1, 0.0)
            if signal_is_down == True:
                blocked, down, ok = (0.1, 0.9, 0.0)

            outcome_label = f"tls.bad_certificate"
            loni_list.append(
                Loni(
                    target=f"{web_o.ip}@{web_o.hostname}",
                    label=outcome_label,
                    blocked=blocked,
                    down=down,
                    ok=ok,
                )
            )
        elif not dns_blocked and not tcp_blocked and web_o.tls_cipher_suite is not None:
            blocked, down, ok = (0.0, 0.0, 1.0)
            loni_list.append(
                Loni(
                    target=f"{web_o.ip}@{web_o.hostname}",
                    label="ok",
                    blocked=blocked,
                    down=down,
                    ok=ok,
                )
            )

    return make_experiment_result(
        obs=web_observations[0],
        domain="signal",
        test_helper_address=None,
        test_runtime=0,
        ooni_run_link_id="",
        nettest_group="im",
        probe_analysis=msmt.test_keys.signal_backend_status,
        blocking_scope=blocking_scope.value,
        msm_failure=msm_failure,
        loni_list=loni_list,
        analysis_transcript_list=analysis_transcript,
    )
