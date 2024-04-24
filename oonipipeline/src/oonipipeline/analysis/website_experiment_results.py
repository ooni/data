from dataclasses import dataclass
from datetime import datetime, timezone
import logging
from typing import Dict, Generator, List, Optional, Tuple

from oonidata.models.analysis import WebAnalysis
from oonidata.models.experiment_result import MeasurementExperimentResult

log = logging.getLogger("oonidata.analysis")


def map_analysis_to_target_name(analysis):
    # Poormans mapping to target name
    # TODO(arturo) we eventually want to look these up in some sort of database that groups together related domains
    return analysis.target_domain_name.lstrip("www.")


NXDOMAIN_FAILURES = ["android_dns_cache_no_data", "dns_nxdomain_error"]


@dataclass
class OutcomeStatus:
    key: str
    value: float
    scope: Optional[str] = None


@dataclass
class OutcomeSpace:
    dns: Optional[OutcomeStatus] = None
    tcp: Optional[OutcomeStatus] = None
    tls: Optional[OutcomeStatus] = None
    http: Optional[OutcomeStatus] = None
    https: Optional[OutcomeStatus] = None

    def to_dict(self) -> Dict[str, float]:
        d = {}
        if self.dns:
            d[self.dns.key] = self.dns.value
        if self.tcp:
            d[self.tcp.key] = self.tcp.value
        if self.tls:
            d[self.tls.key] = self.tls.value
        if self.http:
            d[self.http.key] = self.http.value
        if self.https:
            d[self.https.key] = self.https.value
        return d

    def sum(self) -> float:
        s = 0
        for _, val in self.to_dict().items():
            s += val
        return s


@dataclass
class LoNI:
    ok_final: float

    ok: OutcomeSpace
    down: OutcomeSpace
    blocked: OutcomeSpace
    blocking_scope: Optional[str]

    def to_dict(self):
        return {
            "ok": self.ok.to_dict(),
            "down": self.down.to_dict(),
            "blocked": self.blocked.to_dict(),
            "blocking_scope": self.blocking_scope,
            "ok_final": self.ok_final,
        }


def calculate_web_loni(
    web_analysis: WebAnalysis,
) -> Tuple[LoNI, List[str]]:
    ok_value = 0
    ok = OutcomeSpace()
    down = OutcomeSpace()
    blocked = OutcomeSpace()

    # TODO(arturo): make this not nullable
    blocking_scope = None
    analysis_transcript = []

    # We start off not knowing anything.
    # So basically without any additional information we may as well be rolling
    # a 3 sided dice.
    # Yes, you can make a 3 sided dice: https://upload.wikimedia.org/wikipedia/commons/3/3b/04ds3.JPG
    blocked_key, down_key = None, None
    ok_value, down_value, blocked_value = 0.33, 0.33, 0.33
    # We are in the case of a DNS query failing, i.e. we got no answer.
    if web_analysis.dns_consistency_system_failure is not None:
        """
        Relevant keys for this section of the analysis:

        web_analysis.dns_ground_truth_failure_cc_asn_count
        web_analysis.dns_ground_truth_failure_count
        web_analysis.dns_ground_truth_nxdomain_count
        web_analysis.dns_ground_truth_nxdomain_cc_asn_count
        web_analysis.dns_ground_truth_ok_count
        web_analysis.dns_ground_truth_ok_cc_asn_count
        """
        # For sure, no matter what, the target is having some issue.
        ok_value = 0.0
        # We now need to figure out if the failure is because of the target
        # being down or if it's blocked.
        blocked_key, down_key = "dns", "dns"
        blocked_value, down_value = 0.5, 0.5
        dns_ground_truth_failure_count = (
            web_analysis.dns_ground_truth_failure_count or 0
        )
        dns_ground_truth_ok_count = web_analysis.dns_ground_truth_ok_count or 0
        dns_ground_truth_failure_cc_asn_count = (
            web_analysis.dns_ground_truth_failure_cc_asn_count or 0
        )
        dns_ground_truth_ok_cc_asn_count = (
            web_analysis.dns_ground_truth_ok_cc_asn_count or 0
        )

        # Without any additional information, it could be 50/50
        if web_analysis.dns_consistency_system_failure in NXDOMAIN_FAILURES:
            # NXDOMAIN errors are more commonly associated with censorship, let's bump up the blocked_value
            blocked_key, down_key = "dns.nxdomain", "dns.nxdomain"
            blocked_value = 0.6
            down_value = 1 - blocked_value
            analysis_transcript.append(
                "web_analysis.dns_consistency_system_failure in NXDOMAIN_FAILURES"
            )
            if dns_ground_truth_failure_count > dns_ground_truth_ok_count:
                # It's failing more than it's succeeding. This smells like an unreliable site.
                blocked_value = 0.3
                down_value = 1 - blocked_value
                analysis_transcript.append(
                    "dns_ground_truth_failure_count > dns_ground_truth_ok_count"
                )
                if (
                    dns_ground_truth_failure_cc_asn_count
                    > dns_ground_truth_ok_cc_asn_count
                ):
                    # Even more if that is happening globally
                    blocked_value = 0.2
                    down_value = 1 - blocked_value
                    analysis_transcript.append(
                        "dns_ground_truth_failure_cc_asn_count > dns_ground_truth_ok_cc_asn_count"
                    )
            elif (
                dns_ground_truth_ok_count > 0
                and web_analysis.dns_ground_truth_nxdomain_count == 0
                and web_analysis.dns_ground_truth_nxdomain_cc_asn_count == 0
            ):
                # If we never saw a single NXDOMAIN in our ground truth, then
                # it's really fishy. Let's bump up the blocking reason.
                # TODO(arturo): when we introduce web_obs based ground truthing,
                # we should use a threshold here based on the number of metrics
                analysis_transcript.append(
                    "dns_ground_truth_ok_count > 0 and web_analysis.dns_ground_truth_nxdomain_count == 0 and web_analysis.dns_ground_truth_nxdomain_cc_asn_count == 0"
                )
                blocked_value = 0.75
                down_value = 1 - blocked_value
        else:
            analysis_transcript.append(
                "web_analysis.dns_consistency_system_failure not in NXDOMAIN_FAILURES"
            )
            if dns_ground_truth_failure_count > dns_ground_truth_ok_count:
                analysis_transcript.append(
                    "dns_ground_truth_failure_count > dns_ground_truth_ok_count"
                )
                # it's failing more than it's succeeding, more likely to be blocked.
                blocked_key, down_key = "dns.failure", "dns.failure"
                blocked_value = 0.6
                down_value = 1 - blocked_value

    elif len(web_analysis.dns_consistency_system_answers) > 0:
        analysis_transcript.append(
            "len(web_analysis.dns_consistency_system_answers) > 0"
        )
        # Ok we got some answers. Now we need to figure out if what we got is a
        # good answer.
        blocked_key = "dns"
        down_key = "dns"
        blocked_value = 0.5
        ok_value = 0.5
        # No matter what happens, it's not gonna be flagged as down
        down_value = 0
        if web_analysis.dns_consistency_system_is_answer_tls_consistent == True:
            # "easy" case: we got a TLS consistent answer we can flag it as good
            # and move on with our business.
            #
            # XXX(arturo): there is an important caveat here. We have seen
            # cases where you get a surely wrong answer via DNS (eg. a bogon),
            # but for some reason you are then still establishing a good TLS
            # handshake. Technically it's probably OK to mark these as unblocked
            # since eventually you do get the content, but it's worth pointing
            # it out.
            # Here is a sample measurement for this case: https://explorer.ooni.org/m/20230101013014.694846_AE_webconnectivity_f9f1078ce75936a1
            analysis_transcript.append(
                "web_analysis.dns_consistency_system_is_answer_tls_consistent == True"
            )
            blocked_value = 0
            down_value = 0
            ok_value = 1
        elif (
            web_analysis.dns_consistency_system_is_answer_fp_match == True
            and web_analysis.dns_consistency_system_is_answer_fp_false_positive == False
        ):
            # TODO(arturo): will we eventually have false positives in the DNS? If so how do we handle them?
            # We matched a signature known to be used to implemented censorship. We can mark this as confirmed blocked.
            analysis_transcript.append(
                "web_analysis.dns_consistency_system_is_answer_fp_match == True and web_analysis.dns_consistency_system_is_answer_fp_false_positive == False"
            )
            blocked_key = "dns.confirmed"
            blocking_scope = web_analysis.dns_consistency_system_answer_fp_scope
            blocked_value = 0.9
            if (
                web_analysis.dns_consistency_system_is_answer_fp_country_consistent
                == True
            ):
                blocked_key = "dns.confirmed.country_consistent"
                blocked_value = 1.0
            elif (
                web_analysis.dns_consistency_system_is_answer_fp_country_consistent
                == False
            ):
                # We let the blocked value be slightly less for cases where the fingerprint is not country consistent
                blocked_key = "dns.confirmed.not_country_consistent"
                blocked_value = 0.8
            ok_value = 0
            down_value = 0
        elif web_analysis.dns_consistency_system_is_answer_bogon == True:
            # Bogons are always fishy, yet we don't know if we see it because
            # the site is misconfigured.
            # In any case a bogon is not a routable IP, so the target is either
            # down or blocked.
            analysis_transcript.append(
                "web_analysis.dns_consistency_system_is_answer_bogon == True"
            )
            blocked_key, down_key = "dns.bogon", "dns.bogon"
            blocked_value = 0.5
            down_value = 0.5
            ok_value = 0
            if (
                web_analysis.dns_consistency_system_is_answer_ip_in_trusted_answers
                == False
            ):
                # If we didn't see the bogon in the trusted answers, then it's probably censorship
                analysis_transcript.append(
                    "web_analysis.dns_consistency_system_is_answer_ip_in_trusted_answers == False"
                )
                blocked_value = 0.8
                down_value = 1 - blocked_value
                ok_value = 0
            elif (
                web_analysis.dns_consistency_system_is_answer_ip_in_trusted_answers
                == True
            ):
                analysis_transcript.append(
                    "web_analysis.dns_consistency_system_is_answer_ip_in_trusted_answers == True"
                )
                # If we did see it in the trusted answers, then we should actually ignore this case and mark the target as down.
                blocked_value = 0.2
                down_value = 1 - blocked_value
                ok_value = 0
        elif (
            web_analysis.dns_consistency_system_is_answer_ip_in_trusted_answers == True
        ):
            # Direct hit of the IP in the trusted answers. We nothing to see here.
            analysis_transcript.append(
                "web_analysis.dns_consistency_system_is_answer_ip_in_trusted_answers == True"
            )
            blocked_value = 0.1
            ok_value = 1 - blocked_value
            down_value = 0
        elif (
            web_analysis.dns_consistency_system_is_answer_asn_in_trusted_answers == True
            or web_analysis.dns_consistency_system_is_answer_asorg_in_trusted_answers
            == True
        ):
            # The ASN or AS org name of the observation matches that of our control. Most likely this is not a case of blocking.
            analysis_transcript.append(
                "web_analysis.dns_consistency_system_is_answer_asn_in_trusted_answers == True"
            )
            blocked_value = 0.2
            ok_value = 1 - blocked_value
            down_value = 0
            if web_analysis.dns_consistency_other_is_answer_cloud_provider == True:
                # We are even more confident about it not being blocked if it's a cloud provider
                analysis_transcript.append(
                    "web_analysis.dns_consistency_other_is_answer_cloud_provider == True"
                )
                blocked_value = 0.1
                ok_value = 1 - blocked_value
                down_value = 0
        else:
            # We are done with all the simpler cases. We can now move into the
            # more sketchy dubious analysis strategies.
            # We assume that if we weren't able to determine consistency through
            # the several previous methods, we will air on the side of saying
            # it's blocked, but marginally.
            analysis_transcript.append("not a_simple_case")
            blocked_value = 0.6
            ok_value = 1 - blocked_value
            down_value = 0
            # TODO(arturo): if we ever add false positive fingerprints to DNS we
            # should add case for them here.
            if web_analysis.dns_consistency_system_is_answer_probe_cc_match == True:
                analysis_transcript.append(
                    "web_analysis.dns_consistency_system_is_answer_probe_cc_match == True"
                )
                # It's common for blockpages to be hosted in the country of where the blocking is happening, let's bump up the blocking score.
                blocked_key = "dns.inconsistent"
                blocked_value = 0.65
                ok_value = 1 - blocked_value
                if (
                    web_analysis.dns_consistency_system_is_answer_cloud_provider
                    == False
                ):
                    # If it's not a cloud provider, even more a reason to believe that's the case.
                    # TODO(arturo): add a new metric which tells us if the
                    # target domain is being hosted on a cloud provider and use
                    # that instead since this metric here will actually never be set to false
                    analysis_transcript.append(
                        "web_analysis.dns_consistency_system_is_answer_cloud_provider == False"
                    )
                    blocked_value = 0.75
                    ok_value = 1 - blocked_value
                elif (
                    web_analysis.dns_consistency_system_is_answer_cloud_provider == True
                ):
                    # If it's a cloud provider, this is probably a false positive.
                    analysis_transcript.append(
                        "web_analysis.dns_consistency_system_is_answer_cloud_provider == True"
                    )
                    blocked_key = "dns.cloud"
                    blocked_value = 0.3
                    ok_value = 1 - blocked_value
                elif (
                    web_analysis.dns_consistency_system_is_answer_probe_asn_match
                    == True
                ):
                    # It's not a cloud provider, but it's in the same network. Somethings up.
                    analysis_transcript.append(
                        "web_analysis.dns_consistency_system_is_answer_probe_asn_match == True"
                    )
                    blocked_value = 0.7
                    ok_value = 1 - blocked_value

    if blocked_key and down_key:
        # We have finished the DNS analysis. We can store the
        # final analysis to blocked and down dictionaries.
        blocked.dns = OutcomeStatus(
            key=blocked_key, value=blocked_value, scope=blocking_scope
        )
        down.dns = OutcomeStatus(key=down_key, value=down_value)
        ok.dns = OutcomeStatus(key="dns", value=ok_value)
        assert (
            round(blocked.sum() + down.sum() + ok_value) == 1
        ), f"{blocked} + {down} + {ok_value} != 1"
        if ok_value < 0.5:
            # If the DNS analysis is leading us to believe the target is more down
            # or blocked, than OK, we better off just call it day and return early.
            # If we don't know if the answer we got was DNS consistent, we can't
            # really trust the TCP and TLS analysis results.
            # TODO(arturo): do we want to have different thresholds here?
            analysis_transcript.append(f"ok_value < 0.5 # OK is {ok_value} after DNS")
            return (
                LoNI(
                    ok_final=ok_value,
                    ok=ok,
                    blocked=blocked,
                    down=down,
                    blocking_scope=blocking_scope,
                ),
                analysis_transcript,
            )

    # TODO(arturo): convert paper notes into proof to go in here
    if web_analysis.tcp_success == True:
        # We succeeded via TCP, no matter what there are no TCP level issues
        blocked_key, down_key = "tcp", "tcp"
        down_value, blocked_value = 0.0, 0.0
        blocked.tcp = OutcomeStatus(key=blocked_key, value=blocked_value)
        down.tcp = OutcomeStatus(key=down_key, value=down_value)
        ok.tcp = OutcomeStatus(key="tcp", value=1 - (blocked.sum() + down.sum()))

    elif web_analysis.tcp_success == False:
        analysis_transcript.append("web_analysis.tcp_success == False")
        # No matter what the target is
        blocked_key, down_key = "tcp.failure", "tcp.failure"

        down_value, blocked_value = 0.5, 0.5
        tcp_ground_truth_failure_count = (
            web_analysis.tcp_ground_truth_trusted_failure_count or 0
        )
        # TODO(arturo): Here we are only using the trusted ground truths (i.e. the control measurements)
        # eventually we want to switch to using other OONI measurements too.
        tcp_ground_truth_ok_count = web_analysis.tcp_ground_truth_trusted_ok_count or 0
        tcp_ground_truth_failure_asn_cc_count = (
            web_analysis.tcp_ground_truth_failure_asn_cc_count or 0
        )
        tcp_ground_truth_ok_asn_cc_count = (
            web_analysis.tcp_ground_truth_ok_asn_cc_count or 0
        )
        if tcp_ground_truth_failure_count > tcp_ground_truth_ok_count:
            analysis_transcript.append(
                "tcp_ground_truth_failure_count > tcp_ground_truth_ok_count"
            )
            # It's failing more than it's succeeding. Probably the site is unreliable
            blocked_value = 0.3
            down_value = 1 - blocked_value
            if tcp_ground_truth_failure_asn_cc_count > tcp_ground_truth_ok_asn_cc_count:
                analysis_transcript.append(
                    "tcp_ground_truth_failure_asn_cc_count > tcp_ground_truth_ok_asn_cc_count"
                )

                # Even more if it's happening globally
                blocked_value = 0.2
                down_value = 1 - blocked_value
        elif tcp_ground_truth_ok_count > tcp_ground_truth_failure_count:
            analysis_transcript.append(
                "tcp_ground_truth_ok_count > tcp_ground_truth_failure_count"
            )
            # OTOH, if it's mostly working, then this is a sign of blocking
            blocked_value = 0.7
            down_value = 1 - blocked_value
            if web_analysis.tcp_failure == "connection_reset":
                analysis_transcript.append(
                    'web_analysis.tcp_failure == "connection_reset"'
                )
                # Connection reset is very fishy. Let's bump up the blocking value.
                blocked_value = 0.8
                down_value = 1 - blocked_value
        elif web_analysis.tcp_failure == "connection_reset":
            analysis_transcript.append('web_analysis.tcp_failure == "connection_reset"')
            # Connection reset is very fishy. Let's bump up the blocking value.
            blocked_value = 0.7
            down_value = 1 - blocked_value

        # Let's set some nice blocking keys
        if web_analysis.tcp_failure in ["generic_timeout_error", "timed_out"]:
            blocked_key, down_key = "tcp.timeout", "tcp.timeout"
        elif web_analysis.tcp_failure == "connection_reset":
            blocked_key, down_key = "tcp.connection_reset", "tcp.connection_reset"
        else:
            blocked_key = f"{blocked_key}.{web_analysis.tcp_failure}"
            down_key = f"{down_key}.{web_analysis.tcp_failure}"

        blocked.tcp = OutcomeStatus(key=blocked_key, value=blocked_value * ok_value)
        down.tcp = OutcomeStatus(key=down_key, value=down_value * ok_value)
        # TODO(arturo): double check this is correct
        ok.tcp = OutcomeStatus(key="tcp", value=1 - (blocked.sum() + down.sum()))

    if blocked_key and down_key:
        old_ok_value = ok_value
        ok_value = 1 - (blocked.sum() + down.sum())
        assert (
            round(blocked.sum() + down.sum() + ok_value) == 1
        ), f"{blocked} + {down} + {ok_value} != 1"

        if ok_value < 0.5:
            # If the TCP analysis is leading us to believe the target is more down
            # or blocked, than OK, we better off just call it day and return early.
            # TODO(arturo): How should we map multiple failure types? This is OK for
            # web 0.4, but doesn't apply to wc 0.5
            analysis_transcript.append(
                f"ok_value < 0.5 # OK went after TCP from {old_ok_value} -> {ok_value}"
            )
            return (
                LoNI(
                    ok_final=ok_value,
                    ok=ok,
                    blocked=blocked,
                    down=down,
                    blocking_scope=blocking_scope,
                ),
                analysis_transcript,
            )

    if web_analysis.tls_success == True:
        blocked_key, down_key = "tls", "tls"
        down_value, blocked_value = 0.0, 0.0
        blocked.tls = OutcomeStatus(key=blocked_key, value=blocked_value)
        down.tls = OutcomeStatus(key=down_key, value=down_value)

    elif web_analysis.tls_success == False:
        analysis_transcript.append("web_analysis.tls_success == False")
        # No matter what we are in a tls failure case
        blocked_key, down_key = "tls.failure", "tls.failure"

        down_value, blocked_value = 0.5, 0.5

        # TODO(arturo): Here we are only using the trusted ground truths (i.e.
        # the control measurements) eventually we want to switch to using other
        # OONI measurements too.
        tls_ground_truth_failure_count = (
            web_analysis.tls_ground_truth_trusted_failure_count or 0
        )
        tls_ground_truth_ok_count = web_analysis.tls_ground_truth_trusted_ok_count or 0
        tls_ground_truth_failure_asn_cc_count = (
            web_analysis.tls_ground_truth_failure_asn_cc_count or 0
        )
        tls_ground_truth_ok_asn_cc_count = (
            web_analysis.tls_ground_truth_ok_asn_cc_count or 0
        )
        if tls_ground_truth_failure_count > tls_ground_truth_ok_count:
            analysis_transcript.append(
                "tls_ground_truth_failure_count > tls_ground_truth_ok_count"
            )
            # It's failing more than it's succeeding. Probably the site is unreliable
            blocked_value = 0.3
            down_value = 1 - blocked_value
            if tls_ground_truth_failure_asn_cc_count > tls_ground_truth_ok_asn_cc_count:
                analysis_transcript.append(
                    "tls_ground_truth_failure_asn_cc_count > tls_ground_truth_ok_asn_cc_count"
                )
                # Even more if it's happening globally
                blocked_value = 0.2
                down_value = 1 - blocked_value
        elif tls_ground_truth_ok_count > tls_ground_truth_failure_count:
            analysis_transcript.append(
                "tls_ground_truth_ok_count > tls_ground_truth_failure_count"
            )
            # OTOH, if it's mostly working, then this is a sign of blocking
            blocked_value = 0.7
            down_value = 1 - blocked_value
            if web_analysis.tls_is_tls_certificate_invalid == True:
                analysis_transcript.append(
                    "web_analysis.tls_is_tls_certificate_invalid == True"
                )
                # bad certificate is very fishy. Let's bump up the blocking value.
                blocked_value = 0.9
                down_value = 1 - blocked_value
            elif web_analysis.tls_failure == "connection_reset":
                # bad certificate is very fishy. Let's bump up the blocking value.
                analysis_transcript.append(
                    "web_analysis.tls_failure == 'connection_reset'"
                )
                blocked_value = 0.8
                down_value = 1 - blocked_value

        elif web_analysis.tls_is_tls_certificate_invalid == True:
            analysis_transcript.append(
                "web_analysis.tls_is_tls_certificate_invalid == True"
            )
            # bad certificate is very fishy. Let's bump up the blocking value.
            blocked_value = 0.8
            down_value = 1 - blocked_value
        elif web_analysis.tls_failure == "connection_reset":
            # connection_reset very fishy. Let's bump up the blocking value.
            analysis_transcript.append("web_analysis.tls_failure == 'connection_reset'")
            blocked_value = 0.7
            down_value = 1 - blocked_value

        # Let's set some nice blocking keys
        if web_analysis.tls_failure in ["generic_timeout_error", "timed_out"]:
            blocked_key, down_key = "tls.timeout", "tls.timeout"
        elif web_analysis.tls_failure == "connection_reset":
            blocked_key, down_key = "tls.connection_reset", "tls.connection_reset"
        else:
            blocked_key = f"{blocked_key}.{web_analysis.tls_failure}"
            down_key = f"{down_key}.{web_analysis.tls_failure}"

        blocked.tls = OutcomeStatus(key=blocked_key, value=blocked_value * ok_value)
        down.tls = OutcomeStatus(key=down_key, value=down_value * ok_value)
        # TODO(arturo): double check this is correct
        ok.tls = OutcomeStatus(key="tls", value=1 - (blocked.sum() + down.sum()))

    if blocked_key and down_key:
        old_ok_value = ok_value
        ok_value = 1 - (blocked.sum() + down.sum())
        assert (
            round(blocked.sum() + down.sum() + ok_value)
        ) == 1, f"{blocked} + {down} + {ok_value} != 1"

        if ok_value < 0.5:
            # If the TLS analysis is leading us to believe the target is more down
            # or blocked, than OK, we better off just call it day and return early.
            analysis_transcript.append(
                f"ok_value < 0.5 # OK went after TLS from {old_ok_value} -> {ok_value}"
            )
            return (
                LoNI(
                    ok_final=ok_value,
                    ok=ok,
                    blocked=blocked,
                    down=down,
                    blocking_scope=blocking_scope,
                ),
                analysis_transcript,
            )

    if web_analysis.http_is_http_request_encrypted is not None:
        # If the connection is encrypted we will map these to TLS failures,
        # since they are equivalent to the TLS level anomalies.
        prefix = "http"
        if web_analysis.http_is_http_request_encrypted == True:
            prefix = "tls"

        # This is the special case to handle the situation where the HTTP
        # analysis happens on it's own. Our prior is set to 1.0
        # TODO(arturo): add more details on why this works
        if not blocked_key and not down_key:
            ok_value = 1.0

        blocked_key, down_key = prefix, prefix

        if (
            web_analysis.http_is_http_request_encrypted == True
            and web_analysis.http_success == True
        ):
            analysis_transcript.append(
                "web_analysis.http_is_http_request_encrypted == True and web_analysis.http_success == True"
            )
            down_value, blocked_value = 0.0, 0.0

        elif (
            web_analysis.http_is_http_request_encrypted == False
            and web_analysis.http_success == True
        ):
            down_value = 0.0
            # We got an answer via HTTP, yet we don't know if the answer is correct.
            analysis_transcript.append(
                "web_analysis.http_is_http_request_encrypted == False and web_analysis.http_success == True"
            )
            if web_analysis.http_is_http_fp_match == True:
                # It matches a known fingerprint, we can say stuff
                analysis_transcript.append("web_analysis.http_is_http_fp_match == True")
                if web_analysis.http_is_http_fp_false_positive == False:
                    # We matched a signature known to be used to implemented censorship. We can mark this as confirmed blocked.
                    analysis_transcript.append(
                        "web_analysis.http_is_http_fp_false_positive == False"
                    )
                    blocked_key = "http.confirmed"
                    blocking_scope = web_analysis.http_fp_scope
                    blocked_value = 0.9
                    if web_analysis.http_is_http_fp_country_consistent == True:
                        analysis_transcript.append(
                            "web_analysis.http_is_http_fp_country_consistent == True"
                        )
                        blocked_key = "http.confirmed.country_consistent"
                        blocked_value = 1.0
                    elif web_analysis.http_is_http_fp_country_consistent == False:
                        # We let the blocked value be slightly less for cases where the fingerprint is not country consistent
                        analysis_transcript.append(
                            "web_analysis.dns_consistency_system_is_answer_fp_country_consistent == False"
                        )
                        blocked_key = "http.confirmed.not_country_consistent"
                        blocked_value = 0.8
                elif web_analysis.http_is_http_fp_false_positive == True:
                    blocked_value = 0.0
            elif (
                web_analysis.http_response_body_length is not None
                and web_analysis.http_ground_truth_body_length is not None
            ):
                # We need to apply some fuzzy logic to fingerprint it
                # TODO(arturo): in the future can use more features, such as the following
                """
                web_analysis.http_response_status_code
                web_analysis.http_response_body_proportion
                web_analysis.http_response_body_length
                web_analysis.http_ground_truth_body_length
                """
                http_response_body_length = web_analysis.http_response_body_length or 0
                http_ground_truth_body_length = (
                    web_analysis.http_ground_truth_body_length or 0
                )
                body_proportion = (http_response_body_length + 1) / (
                    http_ground_truth_body_length + 1
                )
                if body_proportion < 0.7:
                    analysis_transcript.append(
                        "(http_response_body_length + 1)/ (http_ground_truth_body_length + 1) < 0.7"
                    )
                    blocked_key = "http.inconsistent.body_length_mismatch"
                    blocked_value = 0.7
                    # TODO(arturo): check if this indeed has the desired effect.
                    down_value = 0

        elif web_analysis.http_failure:
            analysis_transcript.append(f"web_analysis.http_failure # ok: {ok_value}")
            # No matter what we are in a failure case

            blocked_key, down_key = f"{prefix}.failure", f"{prefix}.failure"
            down_value, blocked_value = 0.5, 0.5

            # TODO(arturo): Here we are only using the trusted ground truths (i.e.
            # the control measurements) eventually we want to switch to using other
            # OONI measurements too.
            https_ground_truth_failure_count = (
                web_analysis.http_ground_truth_trusted_failure_count or 0
            )
            https_ground_truth_ok_count = (
                web_analysis.http_ground_truth_trusted_ok_count or 0
            )
            https_ground_truth_failure_asn_cc_count = (
                web_analysis.http_ground_truth_failure_asn_cc_count or 0
            )
            https_ground_truth_ok_asn_cc_count = (
                web_analysis.http_ground_truth_ok_asn_cc_count or 0
            )
            if https_ground_truth_failure_count > https_ground_truth_ok_count:
                analysis_transcript.append(
                    "https_ground_truth_failure_count > https_ground_truth_ok_count"
                )
                # It's failing more than it's succeeding. Probably the site is unreliable
                blocked_value = 0.3
                down_value = 0.7
                if (
                    https_ground_truth_failure_asn_cc_count
                    > https_ground_truth_ok_asn_cc_count
                ):
                    analysis_transcript.append(
                        "https_ground_truth_failure_asn_cc_count > https_ground_truth_ok_asn_cc_count"
                    )
                    # Even more if it's happening globally
                    blocked_value = 0.2
                    down_value = 0.8
            elif https_ground_truth_ok_count > https_ground_truth_failure_count:
                analysis_transcript.append(
                    "https_ground_truth_ok_count > https_ground_truth_failure_count"
                )
                # OTOH, if it's mostly working, then this is a sign of blocking
                blocked_value = 0.7
                down_value = 0.3
                if "ssl_" in web_analysis.http_failure:
                    analysis_transcript.append('"ssl_" in web_analysis.http_failure')
                    # bad certificate is very fishy. Let's bump up the blocking value.
                    blocked_value = 0.9
                    down_value = 0.1
                elif web_analysis.http_failure == "connection_reset":
                    # connection reset is very fishy. Let's bump up the blocking value.
                    analysis_transcript.append(
                        'web_analysis.http_failure == "connection_reset"'
                    )
                    blocked_value = 0.8
                    down_value = 0.2

            elif web_analysis.http_failure == "connection_reset":
                # connection_reset very fishy. Let's bump up the blocking value.
                analysis_transcript.append(
                    "web_analysis.http_failure == 'connection_reset'"
                )
                blocked_value = 0.7
                down_value = 0.3

            # Let's set some nice blocking keys
            if web_analysis.http_failure in ["generic_timeout_error", "timed_out"]:
                blocked_key, down_key = f"{prefix}.timeout", f"{prefix}.timeout"
            elif web_analysis.http_failure == "connection_reset":
                blocked_key, down_key = (
                    f"{prefix}.connection_reset",
                    f"{prefix}.connection_reset",
                )
            else:
                blocked_key = f"{blocked_key}.{web_analysis.http_failure}"
                down_key = f"{down_key}.{web_analysis.http_failure}"

        if prefix == "tls":
            if blocked.tls is not None:
                log.info(
                    f"Overwriting previous TLS blocking status {blocked.tls} - {down.tls} with {blocked_value} {down_value} ({web_analysis.measurement_uid})"
                )
            blocked.tls = OutcomeStatus(key=blocked_key, value=blocked_value * ok_value)
            down.tls = OutcomeStatus(key=down_key, value=down_value * ok_value)
            # TODO(arturo): double check this is correct
            ok.tls = OutcomeStatus(key="tls", value=1 - (blocked.sum() + down.sum()))
        else:
            blocked.http = OutcomeStatus(
                key=blocked_key, value=blocked_value * ok_value, scope=blocking_scope
            )
            down.http = OutcomeStatus(key=down_key, value=down_value * ok_value)
            # TODO(arturo): double check this is correct
            ok.http = OutcomeStatus(key="http", value=1 - (blocked.sum() + down.sum()))

    if blocked_key and down_key:
        old_ok_value = ok_value
        ok_value = 1 - (blocked.sum() + down.sum())
        assert (
            round(blocked.sum() + down.sum() + ok_value) == 1
        ), f"{blocked} + {down} + {ok_value} != 1"

    return (
        LoNI(
            ok_final=ok_value,
            ok=ok,
            blocked=blocked,
            down=down,
            blocking_scope=blocking_scope,
        ),
        analysis_transcript,
    )


def make_website_experiment_results(
    web_analysis: List[WebAnalysis],
) -> Generator[MeasurementExperimentResult, None, None]:
    """
    Takes as input a list of web_analysis and outputs a list of
    ExperimentResults for the website.
    """
    observation_id_list = []
    first_analysis = web_analysis[0]

    measurement_uid = first_analysis.measurement_uid
    timeofday = first_analysis.measurement_start_time

    target_nettest_group = "websites"
    target_category = "MISC"
    target_name = map_analysis_to_target_name(first_analysis)
    target_domain_name = first_analysis.target_domain_name
    target_detail = first_analysis.target_detail

    analysis_transcript_list = []
    loni_list: List[LoNI] = []
    loni_blocked_list: List[OutcomeSpace] = []
    loni_down_list: List[OutcomeSpace] = []
    loni_ok_list: List[OutcomeSpace] = []
    for wa in web_analysis:
        loni, analysis_transcript = calculate_web_loni(wa)
        log.debug("wa: %s", wa)
        log.debug("analysis_transcript: %s", analysis_transcript)
        log.debug("loni: %s", loni)
        analysis_transcript_list.append(analysis_transcript)
        loni_list.append(loni)
        loni_blocked_list.append(loni.blocked)
        loni_down_list.append(loni.down)
        loni_ok_list.append(loni.ok)

    final_blocked = OutcomeSpace()
    final_down = OutcomeSpace()
    final_ok = OutcomeSpace()
    ok_value = 0
    blocking_scope = None

    # TODO(arturo): this section needs to be formalized and verified a bit more
    # in depth. Currently it's just a prototype to start seeing how the data
    # looks like.

    def get_agg_outcome(loni_list, category, agg_func) -> Optional[OutcomeStatus]:
        """
        Returns the min or max outcome status of the specified category given the loni list
        """
        try:
            return agg_func(
                filter(
                    lambda x: x is not None,
                    map(lambda x: getattr(x, category), loni_list),
                ),
                key=lambda d: d.value if d else 0,
            )
        except ValueError:
            return None

    ### FINAL DNS
    max_dns_blocked = get_agg_outcome(loni_blocked_list, "dns", max)
    max_dns_down = get_agg_outcome(loni_down_list, "dns", max)
    min_dns_ok = get_agg_outcome(loni_ok_list, "dns", min)

    if max_dns_blocked and max_dns_down and min_dns_ok:
        ok_value = min_dns_ok.value
        final_ok.dns = OutcomeStatus(key="dns", value=min_dns_ok.value)
        final_blocked.dns = OutcomeStatus(
            key=max_dns_blocked.key, value=max_dns_blocked.value
        )
        final_down.dns = OutcomeStatus(
            # TODO(arturo): this is overestimating blocking.
            key=max_dns_down.key,
            value=1 - (min_dns_ok.value + max_dns_blocked.value),
        )
        if max_dns_blocked.scope:
            # TODO(arturo): set this on the parent OutcomeStatus too
            blocking_scope = max_dns_blocked.scope
        log.debug(f"DNS done {ok_value}")

    ### FINAL TCP
    max_tcp_blocked = get_agg_outcome(loni_blocked_list, "tcp", max)
    max_tcp_down = get_agg_outcome(loni_down_list, "tcp", max)
    min_tcp_ok = get_agg_outcome(loni_ok_list, "tcp", min)
    if max_tcp_blocked and max_tcp_down and min_tcp_ok:
        log.debug(f"PERFORMING TCP {ok_value}")
        log.debug(f"max_tcp_blocked: {max_tcp_blocked}")
        log.debug(f"max_tcp_down: {max_tcp_down}")
        log.debug(f"min_tcp_ok: {min_tcp_ok}")
        log.debug(f"final_down: {final_down}")
        log.debug(f"final_blocked: {final_blocked}")
        log.debug(f"final_ok: {final_ok}")
        final_blocked.tcp = OutcomeStatus(
            key=max_tcp_blocked.key, value=max_tcp_blocked.value * ok_value
        )
        final_down.tcp = OutcomeStatus(
            key=max_tcp_down.key,
            value=(1 - (min_tcp_ok.value + max_tcp_blocked.value)) * ok_value,
        )
        final_ok.tcp = OutcomeStatus(key="tcp", value=min_tcp_ok.value)
        # TODO(arturo): should we update the DNS down key value in light of the
        # fact we notice TCP is bad and hence the answer might have been bad to
        # begin with?
        old_ok_value = ok_value
        ok_value = 1 - (final_blocked.sum() + final_down.sum())
        log.debug(f"TCP done {old_ok_value} -> {ok_value}")
        log.debug(f"final_down: {final_down}")
        log.debug(f"final_blocked: {final_blocked}")
        log.debug(f"final_ok: {final_ok}")

    ### FINAL TLS
    max_tls_blocked = get_agg_outcome(loni_blocked_list, "tls", max)
    max_tls_down = get_agg_outcome(loni_down_list, "tls", max)
    min_tls_ok = get_agg_outcome(loni_ok_list, "tls", min)
    if max_tls_blocked and max_tls_down and min_tls_ok:
        final_blocked.tls = OutcomeStatus(
            key=max_tls_blocked.key, value=max_tls_blocked.value * ok_value
        )
        final_down.tls = OutcomeStatus(
            key=max_tls_down.key,
            value=(1 - (min_tls_ok.value + max_tls_blocked.value)) * ok_value,
        )
        final_ok.tls = OutcomeStatus(key="tls", value=min_tls_ok.value)
        old_ok_value = ok_value
        ok_value = 1 - (final_blocked.sum() + final_down.sum())
        log.debug(f"TLS done {old_ok_value} -> {ok_value}")
        log.debug(f"final_down: {final_down}")
        log.debug(f"final_blocked: {final_blocked}")
        log.debug(f"final_ok: {final_ok}")

    ### FINAL HTTP
    max_http_blocked = get_agg_outcome(loni_blocked_list, "http", max)
    max_http_down = get_agg_outcome(loni_down_list, "http", max)
    min_http_ok = get_agg_outcome(loni_ok_list, "http", min)

    if max_http_blocked and max_http_down and min_http_ok:
        final_blocked.http = OutcomeStatus(
            key=max_http_blocked.key, value=max_http_blocked.value * ok_value
        )
        final_down.http = OutcomeStatus(
            key=max_http_down.key,
            value=(1 - (min_http_ok.value + max_http_blocked.value)) * ok_value,
        )
        final_ok.http = OutcomeStatus(key="http", value=min_http_ok.value)
        if max_http_blocked.scope:
            if blocking_scope is not None:
                log.warning(f"overwriting blocking_scope key: {blocking_scope}")
            # TODO(arturo): set this on the parent OutcomeStatus too
            blocking_scope = max_http_blocked.scope

        old_ok_value = ok_value
        ok_value = 1 - (final_blocked.sum() + final_down.sum())
        log.debug(f"HTTP done {old_ok_value} -> {ok_value}")
        log.debug(f"final_down: {final_down}")
        log.debug(f"final_blocked: {final_blocked}")
        log.debug(f"final_ok: {final_ok}")

    final_loni = LoNI(
        ok_final=ok_value,
        ok=final_ok,
        down=final_down,
        blocked=final_blocked,
        blocking_scope=blocking_scope,
    )
    log.debug(f"final_loni: {final_loni}")

    loni_ok_value = final_loni.ok_final

    loni_down = final_loni.down.to_dict()
    loni_down_keys, loni_down_values = list(loni_down.keys()), list(loni_down.values())

    loni_blocked = final_loni.blocked.to_dict()
    loni_blocked_keys, loni_blocked_values = list(loni_blocked.keys()), list(
        loni_blocked.values()
    )

    loni_ok = final_loni.ok.to_dict()
    loni_ok_keys, loni_ok_values = list(loni_ok.keys()), list(loni_ok.values())

    is_anomaly = loni_ok_value < 0.6
    is_confirmed = final_loni.blocked.sum() > 0.9

    er = MeasurementExperimentResult(
        measurement_uid=measurement_uid,
        observation_id_list=observation_id_list,
        timeofday=timeofday,
        created_at=datetime.now(timezone.utc).replace(tzinfo=None),
        location_network_type=first_analysis.network_type,
        location_network_asn=first_analysis.probe_asn,
        location_network_cc=first_analysis.probe_cc,
        location_network_as_org_name=first_analysis.probe_as_org_name,
        location_network_as_cc=first_analysis.probe_as_cc,
        location_resolver_asn=first_analysis.resolver_asn,
        location_resolver_as_org_name=first_analysis.resolver_as_org_name,
        location_resolver_as_cc=first_analysis.resolver_as_cc,
        location_resolver_cc=first_analysis.resolver_cc,
        location_blocking_scope=None,
        target_nettest_group=target_nettest_group,
        target_category=target_category,
        target_name=target_name,
        target_domain_name=target_domain_name,
        target_detail=target_detail,
        loni_ok_value=loni_ok_value,
        loni_down_keys=loni_down_keys,
        loni_down_values=loni_down_values,
        loni_blocked_keys=loni_blocked_keys,
        loni_blocked_values=loni_blocked_values,
        loni_ok_keys=loni_ok_keys,
        loni_ok_values=loni_ok_values,
        loni_list=list(map(lambda x: x.to_dict(), loni_list)),
        analysis_transcript_list=analysis_transcript_list,
        measurement_count=1,
        observation_count=len(web_analysis),
        vp_count=1,
        anomaly=is_anomaly,
        confirmed=is_confirmed,
    )

    yield er
