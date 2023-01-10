from collections import defaultdict
from dataclasses import dataclass
import dataclasses
import ipaddress
import math
from typing import Any, Generator, Iterable, NamedTuple, Optional, List, Dict
from oonidata.db.connections import ClickhouseConnection
from oonidata.analysis.control import (
    WebGroundTruth,
    BodyDB,
)
from oonidata.models.experiment_result import (
    BlockingScope,
    Outcome,
    Scores,
    ExperimentResult,
    fp_to_scope,
    iter_experiment_results,
)

from oonidata.fingerprintdb import FingerprintDB
from oonidata.models.observations import WebControlObservation, WebObservation

import logging

log = logging.getLogger("oonidata.processing")

CLOUD_PROVIDERS_ASNS = [
    13335,  # Cloudflare: https://www.peeringdb.com/net/4224
    20940,  # Akamai: https://www.peeringdb.com/net/2
    9002,  # Akamai RETN
    396982,  # Google Cloud: https://www.peeringdb.com/net/30878
]

CLOUD_PROVIDERS_AS_ORGS_SUBSTRINGS = ["akamai"]


def get_web_ctrl_observations(
    db: ClickhouseConnection, measurement_uid: str
) -> List[WebControlObservation]:
    obs_list = []
    column_names = [f.name for f in dataclasses.fields(WebControlObservation)]
    q = "SELECT ("
    q += ",\n".join(column_names)
    q += ") FROM obs_web_ctrl WHERE measurement_uid = %(measurement_uid)s"

    for res in db.execute_iter(q, {"measurement_uid": measurement_uid}):
        row = res[0]
        obs_list.append(
            WebControlObservation(**{k: row[idx] for idx, k in enumerate(column_names)})
        )
    return obs_list


def is_cloud_provider(asn: Optional[int], as_org_name: Optional[str]):
    if asn and asn in CLOUD_PROVIDERS_ASNS:
        return True
    if as_org_name and any(
        [ss in as_org_name.lower() for ss in CLOUD_PROVIDERS_AS_ORGS_SUBSTRINGS]
    ):
        return True
    return False


def encode_address(ip: str, port: int) -> str:
    """
    return a properly encoded address handling IPv6 IPs
    """
    # I'm amazed python doesn't have this in the standard library
    # and urlparse is incredibly inconsistent with it's handling of IPv6
    # addresses.
    ipaddr = ipaddress.ip_address(ip)
    addr = ip
    if isinstance(ipaddr, ipaddress.IPv6Address):
        addr = "[" + ip + "]"

    addr += f":{port}"
    return addr


def confidence_estimate(x: int, factor: float = 0.8, clamping: float = 0.9):
    """
    Gives an estimate of confidence given the number of datapoints that are
    consistent (x).

    clamping: defines what is the maximum value it can take
    factor: is a multiplicate factor to decrease the value of the function

    This function was derived by looking for an exponential function in
    the form f(x) = c1*a^x + c2 and solving for f(0) = 0 and f(10) = 1,
    giving us a function in the form f(x) = (a^x - 1) / (a^10 - 1). We
    then choose the magic value of 0.5 by looking for a solution in a
    where f(1) ~= 0.5, doing a bit of plots and choosing a curve that
    looks reasonably sloped.
    """
    y = (pow(0.5, x) - 1) / (pow(0.5, 10) - 1)
    return min(clamping, factor * y)


def ok_vs_nok_score(
    ok_count: int, nok_count: int, blocking_factor: float = 0.8
) -> Scores:
    """
    This is a very simplistic estimation that just looks at the proportions of
    failures to reachable measurement to establish if something is blocked or
    not.

    It assumes that what we are calculating the ok_vs_nok score is some kind of
    failure, which means the outcome is either that the target is down or
    blocked.

    In order to determine which of the two cases it is, we look at the ground
    truth.
    """
    # We set this to 0.65 so that for the default value and lack of any ground
    # truth, we end up with blocked_score = 0.52 and down_score = 0.48
    blocked_score = min(1.0, 0.65 * blocking_factor)
    down_score = 1 - blocked_score
    total_count = ok_count + nok_count
    if total_count > 0:
        blocked_score = min(1.0, ok_count / total_count * blocking_factor)
        down_score = 1 - blocked_score

    return Scores(ok=0.0, blocked=blocked_score, down=down_score)


def make_tcp_outcome(
    web_o: WebObservation, web_ground_truths: List[WebGroundTruth]
) -> Outcome:
    assert web_o.ip is not None and web_o.port is not None

    blocking_subject = encode_address(web_o.ip, web_o.port)

    # It's working, wothing to see here, go on with your life
    if web_o.tcp_success:
        return Outcome(
            observation_id=web_o.observation_id,
            scope=BlockingScope.UNKNOWN,
            label="",
            subject=blocking_subject,
            category="tcp",
            detail="ok",
            meta={},
            ok_score=1.0,
            down_score=0.0,
            blocked_score=0.0,
        )

    assert (
        web_o.tcp_failure is not None
    ), "inconsistency between tcp_success and tcp_failure"

    ground_truths = filter(
        lambda gt: gt.ip == web_o.ip and gt.port == web_o.port, web_ground_truths
    )
    unreachable_cc_asn = set()
    reachable_cc_asn = set()
    ok_count = 0
    nok_count = 0
    for gt in ground_truths:
        # We don't check for strict == True, since depending on the DB engine
        # True could also be represented as 1
        if gt.tcp_success is None:
            continue
        if gt.tcp_success:
            if gt.is_trusted_vp:
                ok_count += 1
            else:
                reachable_cc_asn.add((gt.vp_cc, gt.vp_asn))
        else:
            if gt.is_trusted_vp:
                nok_count += 1
            else:
                unreachable_cc_asn.add((gt.vp_cc, gt.vp_asn))

    reachable_count = ok_count + len(reachable_cc_asn)
    unreachable_count = nok_count + len(unreachable_cc_asn)
    blocking_meta = {
        "unreachable_count": str(unreachable_count),
        "reachable_count": str(reachable_count),
    }

    blocking_factor = 0.7
    if web_o.tls_failure == "connection_reset":
        blocking_factor = 0.8

    scores = ok_vs_nok_score(
        ok_count=reachable_count,
        nok_count=unreachable_count,
        blocking_factor=blocking_factor,
    )
    return Outcome(
        observation_id=web_o.observation_id,
        scope=BlockingScope.UNKNOWN,
        label="",
        subject=blocking_subject,
        category="tcp",
        detail=web_o.tcp_failure,
        meta=blocking_meta,
        ok_score=scores.ok,
        blocked_score=scores.blocked,
        down_score=scores.down,
    )


class DNSFingerprintOutcome(NamedTuple):
    meta: Dict[str, str]
    label: str
    scope: BlockingScope


def match_dns_fingerprint(
    dns_observations: List[WebObservation], fingerprintdb: FingerprintDB
) -> DNSFingerprintOutcome:
    outcome_meta = {}
    outcome_label = ""
    outcome_scope = BlockingScope.UNKNOWN
    for web_o in dns_observations:
        if not web_o.dns_answer:
            continue
        fp = fingerprintdb.match_dns(web_o.dns_answer)
        if fp:
            outcome_scope = fp_to_scope(fp.scope)
            if outcome_scope != BlockingScope.SERVER_SIDE_BLOCK:
                outcome_label = f"blocked"
            outcome_meta["fingerprint"] = fp.name
            outcome_meta["fingerprint_consistency"] = "country_consistent"

            # If we see the fingerprint in an unexpected country we should
            # significantly reduce the confidence in the block
            if fp.expected_countries and web_o.probe_cc not in fp.expected_countries:
                log.debug(
                    f"Inconsistent probe_cc vs expected_countries {web_o.probe_cc} != {fp.expected_countries}"
                )
                outcome_meta["fingerprint_consistency"] = "country_inconsistent"
            return DNSFingerprintOutcome(
                meta=outcome_meta, label=outcome_label, scope=outcome_scope
            )
    return DNSFingerprintOutcome(
        meta=outcome_meta, label=outcome_label, scope=outcome_scope
    )


class DNSGroundTruth(NamedTuple):
    nxdomain_cc_asn: set
    failure_cc_asn: set
    ok_cc_asn: set
    other_ips: Dict[str, set]
    other_asns: Dict[str, set]
    trusted_answers: Dict

    @property
    def ok_count(self):
        return len(self.ok_cc_asn)

    @property
    def failure_count(self):
        return len(self.failure_cc_asn)

    @property
    def nxdomain_count(self):
        return len(self.nxdomain_cc_asn)


def make_dns_ground_truth(ground_truths: Iterable[WebGroundTruth]):
    """
    Here we count how many vantage vantage points, as in distinct probe_cc,
    probe_asn pairs, presented the various types of results.
    """
    nxdomain_cc_asn = set()
    failure_cc_asn = set()
    ok_cc_asn = set()
    other_ips = defaultdict(set)
    other_asns = defaultdict(set)
    trusted_answers = {}
    for gt in ground_truths:
        if gt.dns_success is None:
            continue
        if gt.dns_failure == "dns_nxdomain_error":
            nxdomain_cc_asn.add((gt.vp_cc, gt.vp_asn))
        if not gt.dns_success:
            failure_cc_asn.add((gt.vp_cc, gt.vp_asn))
            continue

        ok_cc_asn.add((gt.vp_cc, gt.vp_asn))
        other_ips[gt.ip].add((gt.vp_cc, gt.vp_asn))
        assert gt.ip, "did not find IP in ground truth"
        other_asns[gt.ip_asn].add((gt.vp_cc, gt.vp_asn))
        if gt.tls_is_certificate_valid == True or gt.is_trusted_vp == True:
            trusted_answers[gt.ip] = gt

    return DNSGroundTruth(
        nxdomain_cc_asn=nxdomain_cc_asn,
        failure_cc_asn=failure_cc_asn,
        ok_cc_asn=ok_cc_asn,
        other_asns=other_asns,
        other_ips=other_ips,
        trusted_answers=trusted_answers,
    )


def compute_dns_failure_outcomes(
    dns_ground_truth: DNSGroundTruth, dns_observations: List[WebObservation]
) -> List[Outcome]:
    outcomes = []
    for web_o in dns_observations:
        if not web_o.dns_failure:
            continue

        outcome_meta = {
            "ok_count": str(dns_ground_truth.ok_count),
            "failure_count": str(dns_ground_truth.failure_count),
            "nxdomain_count": str(dns_ground_truth.nxdomain_count),
        }
        scores = ok_vs_nok_score(
            ok_count=dns_ground_truth.ok_count,
            nok_count=dns_ground_truth.failure_count,
        )

        blocking_detail = f"failure.{web_o.dns_failure}"
        if web_o.dns_failure == "dns_nxdomain_error":
            blocking_detail = "inconsistent.nxdomain"
            scores = ok_vs_nok_score(
                ok_count=dns_ground_truth.ok_count,
                nok_count=dns_ground_truth.nxdomain_count,
                blocking_factor=0.85,
            )
        outcome_subject = (
            f"{web_o.hostname}@{web_o.dns_engine}-{web_o.dns_engine_resolver_address}"
        )
        outcomes.append(
            Outcome(
                observation_id=web_o.observation_id,
                scope=BlockingScope.UNKNOWN,
                subject=outcome_subject,
                label="",
                category="dns",
                detail=blocking_detail,
                meta=outcome_meta,
                ok_score=scores.ok,
                down_score=scores.down,
                blocked_score=scores.blocked,
            )
        )
    return outcomes


def dns_observations_by_resolver(
    dns_observations: List[WebObservation],
) -> Dict[str, List[WebObservation]]:
    by_resolver = defaultdict(list)
    for dns_o in dns_observations:
        key = f"{dns_o.dns_engine}-{dns_o.dns_engine_resolver_address}"
        by_resolver[key].append(dns_o)
    return by_resolver


def get_outcome_subject(dns_o: WebObservation):
    return f"{dns_o.ip}@{dns_o.dns_engine}-{dns_o.dns_engine_resolver_address}"


def check_dns_bogon(
    dns_observations: List[WebObservation],
    dns_ground_truth: DNSGroundTruth,
    outcome_fingerprint: DNSFingerprintOutcome,
) -> Optional[Outcome]:
    for web_o in dns_observations:
        outcome_meta = {"ip": web_o.dns_answer or "", **outcome_fingerprint.meta}
        if web_o.ip_is_bogon:
            outcome_meta["why"] = "answer is bogon"
            down_score = 0.1
            blocked_score = 0.9
            # If we saw the same bogon IP inside of the trusted_answers, it means it
            # it's always returning a bogon and hence this site is actually down
            if web_o.dns_answer in dns_ground_truth.trusted_answers:
                outcome_meta["why"] = "answer is bogon as expected"
                down_score = 0.9
                blocked_score = 0.1

            return Outcome(
                observation_id=web_o.observation_id,
                scope=outcome_fingerprint.scope,
                subject=get_outcome_subject(web_o),
                label=outcome_fingerprint.label,
                category="dns",
                detail="inconsistent.bogon",
                meta=outcome_meta,
                ok_score=0.0,
                down_score=down_score,
                blocked_score=blocked_score,
            )


def check_tls_consistency(
    dns_observations: List[WebObservation],
    dns_ground_truth: DNSGroundTruth,
    outcome_fingerprint: DNSFingerprintOutcome,
) -> Optional[Outcome]:
    for web_o in dns_observations:
        outcome_meta = outcome_fingerprint.meta.copy()
        if (
            web_o.tls_is_certificate_valid == True
            or web_o.dns_answer in dns_ground_truth.trusted_answers
        ):
            outcome_meta["why"] = "resolved IP in trusted answers"
            # No blocking detected
            return Outcome(
                observation_id=web_o.observation_id,
                scope=outcome_fingerprint.scope,
                label=outcome_fingerprint.label,
                subject=get_outcome_subject(web_o),
                category="dns",
                detail="ok",
                meta=outcome_meta,
                ok_score=1.0,
                down_score=0.0,
                blocked_score=0.0,
            )


def check_tls_inconsistency(
    dns_observations: List[WebObservation],
    outcome_fingerprint: DNSFingerprintOutcome,
) -> Optional[Outcome]:
    # We do these in two separate loops, so that we first ensure that none of
    # the answers we got were good and only then do we proceed to doing a TLS
    # inconsistency check.
    for web_o in dns_observations:
        outcome_meta = outcome_fingerprint.meta.copy()
        if web_o.tls_is_certificate_valid == False:
            # TODO: we probably need to handle cases here where it might be the case
            # that the CERT is bad because it's always serving a bad certificate.
            # here is an example: https://explorer.ooni.org/measurement/20220930T235729Z_webconnectivity_AE_5384_n1_BLcO454Y5UULxZoq?input=https://www.government.ae/en%23%2F
            outcome_meta["why"] = "tls certificate is bad"
            return Outcome(
                observation_id=web_o.observation_id,
                scope=outcome_fingerprint.scope,
                label=outcome_fingerprint.label,
                subject=get_outcome_subject(web_o),
                category="dns",
                detail="inconsistent",
                meta=outcome_meta,
                ok_score=0.0,
                # We give a little bit of weight to the down score, due to no ground
                # truthing of TLS
                down_score=0.3,
                blocked_score=0.7,
            )


def check_wc_style_consistency(
    dns_observations: List[WebObservation],
    dns_ground_truth: DNSGroundTruth,
    outcome_fingerprint: DNSFingerprintOutcome,
) -> Optional[Outcome]:
    """
    Do a web_connectivity style DNS consistency check.

    If we are in this case, it means we weren't able to determine the
    consistency of the DNS query using TLS. This is the case either
    because the tested site is not in HTTPS and therefore we didn't
    generate a TLS measurement for it or because the target IP isn't
    listening on HTTPS (which is quite fishy).
    In either case we should flag these with being somewhat likely to be
    blocked.
    """
    ground_truth_asns = set()
    ground_truth_as_org_names = set()
    for gt in dns_ground_truth.trusted_answers.values():
        assert gt.ip, f"did not find IP in ground truth {gt.ip}"
        ground_truth_asns.add(gt.ip_asn)
        ground_truth_as_org_names.add(gt.ip_as_org_name.lower())

    contains_matching_asn_answer = False
    contains_matching_cc_answer = False
    system_answers = 0
    for web_o in dns_observations:
        outcome_meta = outcome_fingerprint.meta.copy()
        if web_o.dns_engine == "system":
            system_answers += 1

        if web_o.dns_answer_asn in ground_truth_asns:
            outcome_meta["why"] = "answer in matches AS of trusted answers"
            return Outcome(
                observation_id=web_o.observation_id,
                scope=outcome_fingerprint.scope,
                label=outcome_fingerprint.label,
                subject=get_outcome_subject(web_o),
                category="dns",
                detail="ok",
                meta=outcome_meta,
                ok_score=0.9,
                down_score=0.0,
                blocked_score=0.1,
            )

        if (
            web_o.dns_answer_as_org_name
            and web_o.dns_answer_as_org_name.lower() in ground_truth_as_org_names
        ):
            outcome_meta["why"] = "answer in TLS ground truth as org name"
            return Outcome(
                observation_id=web_o.observation_id,
                scope=outcome_fingerprint.scope,
                label=outcome_fingerprint.label,
                subject=get_outcome_subject(web_o),
                category="dns",
                detail="ok",
                meta=outcome_meta,
                ok_score=0.9,
                down_score=0.0,
                blocked_score=0.1,
            )

        if web_o.dns_answer in dns_ground_truth.other_ips:
            outcome_meta["why"] = "answer in resolved IPs ground truth"
            outcome_meta["other_ip_count"] = str(
                len(dns_ground_truth.other_ips[web_o.dns_answer])
            )
            blocked_score = confidence_estimate(
                len(dns_ground_truth.other_ips[web_o.dns_answer]),
                clamping=0.9,
                factor=0.8,
            )
            ok_score = 1 - blocked_score
            return Outcome(
                observation_id=web_o.observation_id,
                scope=outcome_fingerprint.scope,
                label=outcome_fingerprint.label,
                subject=get_outcome_subject(web_o),
                category="dns",
                detail="ok",
                meta=outcome_meta,
                ok_score=ok_score,
                down_score=0.0,
                blocked_score=blocked_score,
            )

        if web_o.dns_answer in dns_ground_truth.other_asns:
            # We clamp this to some lower values and scale it by a smaller factor,
            # since ASN consistency is less strong than direct IP match.
            outcome_meta["why"] = "answer AS in ground truth"
            outcome_meta["other_asn_count"] = str(
                len(dns_ground_truth.other_asns[web_o.dns_answer])
            )
            blocked_score = confidence_estimate(
                len(dns_ground_truth.other_asns[web_o.dns_answer]),
                clamping=0.9,
                factor=0.8,
            )
            ok_score = 1 - blocked_score
            return Outcome(
                observation_id=web_o.observation_id,
                scope=outcome_fingerprint.scope,
                label=outcome_fingerprint.label,
                subject=get_outcome_subject(web_o),
                category="dns",
                detail="ok",
                meta=outcome_meta,
                ok_score=ok_score,
                down_score=0.0,
                blocked_score=blocked_score,
            )

        if is_cloud_provider(asn=web_o.ip_asn, as_org_name=web_o.ip_as_org_name):
            # Cloud providers are a common source of false positives. Let's just
            # mark them as ok with a low confidence
            outcome_meta["why"] = "answer is cloud service provider"
            return Outcome(
                observation_id=web_o.observation_id,
                scope=outcome_fingerprint.scope,
                label=outcome_fingerprint.label,
                subject=get_outcome_subject(web_o),
                category="dns",
                detail="ok",
                meta=outcome_meta,
                ok_score=0.6,
                down_score=0.0,
                blocked_score=0.4,
            )

        if web_o.dns_answer_asn == web_o.probe_asn:
            contains_matching_asn_answer = True
        elif web_o.ip_as_cc == web_o.probe_cc:
            contains_matching_cc_answer = True

    outcome_meta = {}
    outcome_meta["why"] = "unable to determine consistency through ground truth"
    outcome_meta["system_answers"] = str(system_answers)
    blocked_score = 0.6
    outcome_detail = "inconsistent"

    # It's quite unlikely that a censor will return multiple answers
    if system_answers > 1:
        outcome_meta["why"] += ", but multiple system_answers"
        blocked_score = 0.4
        outcome_detail = "ok"

    # It's more common to answer to DNS queries for blocking with IPs managed by
    # the ISP (ex. to serve their blockpage).
    # So we give this a bit higher confidence
    if contains_matching_asn_answer and system_answers > 1:
        blocked_score = 0.8
        outcome_meta["why"] = "answer matches probe_asn"
        outcome_detail = "inconsistent"

    # It's common to do this also in the country, for example when the blockpage
    # is centrally managed (ex. case in IT, ID)
    elif contains_matching_cc_answer:
        blocked_score = 0.7
        outcome_meta["why"] = "answer matches probe_cc"
        outcome_detail = "inconsistent"

    # We haven't managed to figured out if the DNS resolution was a good one, so
    # we are going to assume it's bad.
    # TODO: Currently web_connectivity assumes that if the last request was HTTPS and it was successful, then the whole measurement was OK.
    # see: https://github.com/ooni/probe-cli/blob/a0dc65641d7a31e116d9411ecf9e69ed1955e792/internal/engine/experiment/webconnectivity/summary.go#L98
    # This seems a little bit too strong. We probably ought to do this only if
    # the redirect chain was a good one, because it will lead to false negatives
    # in cases in which the redirect is triggered by the middlebox.
    # Imagine a case like this:
    # http://example.com/ -> 302 -> https://blockpage.org/
    #
    # The certificate for blockpage.org can be valid, but it's not what we
    # wanted.
    return Outcome(
        observation_id=dns_observations[0].observation_id,
        scope=outcome_fingerprint.scope,
        label=outcome_fingerprint.label,
        subject="all@all",
        category="dns",
        detail=outcome_detail,
        meta=outcome_meta,
        ok_score=1 - blocked_score,
        down_score=0.0,
        blocked_score=blocked_score,
    )


def compute_dns_consistency_outcomes(
    dns_ground_truth: DNSGroundTruth,
    dns_observations: List[WebObservation],
    outcome_fingerprint: DNSFingerprintOutcome,
) -> List[Outcome]:
    outcomes = []

    for dns_observations in dns_observations_by_resolver(dns_observations).values():
        bogon_outcome = check_dns_bogon(
            dns_observations=dns_observations,
            dns_ground_truth=dns_ground_truth,
            outcome_fingerprint=outcome_fingerprint,
        )
        if bogon_outcome:
            outcomes.append(bogon_outcome)
            continue

        tls_consistency_outcome = check_tls_consistency(
            dns_observations=dns_observations,
            dns_ground_truth=dns_ground_truth,
            outcome_fingerprint=outcome_fingerprint,
        )
        if tls_consistency_outcome:
            outcomes.append(tls_consistency_outcome)
            continue

        wc_style_outcome = check_wc_style_consistency(
            dns_observations=dns_observations,
            dns_ground_truth=dns_ground_truth,
            outcome_fingerprint=outcome_fingerprint,
        )
        if wc_style_outcome:
            outcomes.append(wc_style_outcome)
            continue

        # TODO: If we add a ground truth to this, we could potentially do it
        # before the WC style consistency check and it will probably be more
        # robust.
        tls_inconsistency_outcome = check_tls_inconsistency(
            dns_observations=dns_observations,
            outcome_fingerprint=outcome_fingerprint,
        )
        if tls_inconsistency_outcome:
            outcomes.append(tls_inconsistency_outcome)

    return outcomes


def make_dns_outcomes(
    hostname: str,
    dns_observations: List[WebObservation],
    web_ground_truths: List[WebGroundTruth],
    fingerprintdb: FingerprintDB,
) -> List[Outcome]:
    outcomes = []
    dns_ground_truth = make_dns_ground_truth(
        ground_truths=filter(
            lambda gt: gt.hostname == hostname,
            web_ground_truths,
        )
    )
    outcome_fingerprint = match_dns_fingerprint(
        dns_observations=dns_observations, fingerprintdb=fingerprintdb
    )
    outcomes += compute_dns_failure_outcomes(
        dns_ground_truth=dns_ground_truth, dns_observations=dns_observations
    )
    outcomes += compute_dns_consistency_outcomes(
        dns_ground_truth=dns_ground_truth,
        dns_observations=dns_observations,
        outcome_fingerprint=outcome_fingerprint,
    )
    return outcomes


def make_tls_outcome(
    web_o: WebObservation, web_ground_truths: List[WebGroundTruth]
) -> Outcome:
    blocking_subject = web_o.hostname or ""
    outcome_meta = {}
    if web_o.tls_is_certificate_valid == True:
        return Outcome(
            observation_id=web_o.observation_id,
            scope=BlockingScope.UNKNOWN,
            label="",
            subject=blocking_subject,
            category="tls",
            detail="ok",
            meta=outcome_meta,
            ok_score=1.0,
            down_score=0.0,
            blocked_score=0.0,
        )

    ground_truths = filter(
        lambda gt: gt.http_request_url and gt.hostname == web_o.hostname,
        web_ground_truths,
    )
    failure_cc_asn = set()
    ok_cc_asn = set()
    ok_count = 0
    failure_count = 0
    for gt in ground_truths:
        # We don't check for strict == True, since depending on the DB engine
        # True could also be represented as 1
        if gt.http_success is None:
            continue

        if gt.http_success:
            if gt.is_trusted_vp:
                ok_count += gt.count
            else:
                ok_cc_asn.add((gt.vp_cc, gt.vp_asn))
        else:
            if gt.is_trusted_vp:
                failure_count += gt.count
            else:
                failure_cc_asn.add((gt.vp_cc, gt.vp_asn, gt.count))

    # Untrusted Vantage Points (i.e. not control measurements) only count
    # once per probe_cc, probe_asn pair to avoid spammy probes poisoning our
    # data
    failure_count += len(failure_cc_asn)
    ok_count += len(ok_cc_asn)
    outcome_meta["ok_count"] = str(ok_count)
    outcome_meta["failure_count"] = str(failure_count)

    # FIXME: we currently use the HTTP control as a proxy to establish ground truth for TLS
    if web_o.tls_is_certificate_valid == False and failure_count == 0:
        outcome_meta["why"] = "invalid TLS certificate"
        return Outcome(
            observation_id=web_o.observation_id,
            scope=BlockingScope.UNKNOWN,
            label="",
            subject=blocking_subject,
            category="tls",
            detail="mitm",
            meta=outcome_meta,
            ok_score=0.0,
            down_score=0.2,
            blocked_score=0.8,
        )

    elif web_o.tls_failure and failure_count == 0:
        # We only consider it to be a TLS level verdict if we haven't seen any
        # blocks in TCP
        blocking_detail = f"{web_o.tls_failure}"
        blocked_score = 0.5

        if web_o.tls_handshake_read_count == 0 and web_o.tls_handshake_write_count == 1:
            # This means we just wrote the TLS ClientHello, let's give it a bit
            # more confidence in it being a block
            blocked_score = 0.7

        if web_o.tls_failure in ("connection_closed", "connection_reset"):
            blocked_score += 0.15

        return Outcome(
            observation_id=web_o.observation_id,
            scope=BlockingScope.UNKNOWN,
            label="",
            subject=blocking_subject,
            category="tls",
            detail=blocking_detail,
            meta=outcome_meta,
            ok_score=0.0,
            down_score=1 - blocked_score,
            blocked_score=blocked_score,
        )

    elif web_o.tls_failure or web_o.tls_is_certificate_valid == False:
        outcome_detail = f"{web_o.tls_failure}"
        scores = ok_vs_nok_score(
            ok_count=ok_count, nok_count=failure_count, blocking_factor=0.7
        )
        if web_o.tls_is_certificate_valid == False:
            outcome_detail = "bad_cert"

        return Outcome(
            observation_id=web_o.observation_id,
            scope=BlockingScope.UNKNOWN,
            label="",
            subject=blocking_subject,
            category="tls",
            detail=outcome_detail,
            meta=outcome_meta,
            ok_score=0.0,
            down_score=scores.down,
            blocked_score=scores.blocked,
        )

    return Outcome(
        observation_id=web_o.observation_id,
        scope=BlockingScope.UNKNOWN,
        label="",
        subject=blocking_subject,
        category="tls",
        detail="ok",
        meta=outcome_meta,
        ok_score=0.9,
        down_score=0.0,
        blocked_score=0.1,
    )


def make_http_outcome(
    web_o: WebObservation,
    web_ground_truths: List[WebGroundTruth],
    body_db: BodyDB,
    fingerprintdb: FingerprintDB,
) -> Outcome:
    assert web_o.http_request_url
    request_is_encrypted = web_o.http_request_url.startswith("https://")

    blocking_subject = web_o.http_request_url
    outcome_label = ""
    outcome_meta = {}
    outcome_category = "http"
    if request_is_encrypted:
        outcome_category = "https"

    ground_truths = filter(
        lambda gt: gt.http_request_url == web_o.http_request_url, web_ground_truths
    )
    failure_cc_asn = set()
    ok_cc_asn = set()
    ok_count = 0
    failure_count = 0
    response_body_len_count = defaultdict(int)
    for gt in ground_truths:
        # We don't check for strict == True, since depending on the DB engine
        # True could also be represented as 1
        if gt.http_success is None:
            continue

        # TODO: figure out why some are negative
        if gt.http_response_body_length and gt.http_response_body_length > 0:
            response_body_len_count[gt.http_response_body_length] += gt.count

        if gt.http_success:
            if gt.is_trusted_vp:
                ok_count += gt.count
            else:
                ok_cc_asn.add((gt.vp_cc, gt.vp_asn))
        else:
            if gt.is_trusted_vp:
                failure_count += gt.count
            else:
                failure_cc_asn.add((gt.vp_cc, gt.vp_asn, gt.count))

    response_body_length = 0
    if len(response_body_len_count) > 0:
        response_body_length = max(response_body_len_count.items(), key=lambda x: x[1])[
            0
        ]

    # Untrusted Vantage Points (i.e. not control measurements) only count
    # once per probe_cc, probe_asn pair to avoid spammy probes poisoning our
    # data
    failure_count += len(failure_cc_asn)
    ok_count += len(ok_cc_asn)
    outcome_meta["ok_count"] = str(ok_count)
    outcome_meta["failure_count"] = str(failure_count)

    if web_o.http_failure:
        scores = ok_vs_nok_score(ok_count=ok_count, nok_count=failure_count)

        outcome_detail = f"{web_o.http_failure}"

        return Outcome(
            observation_id=web_o.observation_id,
            scope=BlockingScope.UNKNOWN,
            label="",
            subject=blocking_subject,
            category=outcome_category,
            detail=outcome_detail,
            meta=outcome_meta,
            ok_score=scores.ok,
            down_score=scores.down,
            blocked_score=scores.blocked,
        )

    # TODO: do we care to do something about empty bodies?
    # They are commonly a source of blockpages
    if web_o.http_response_body_sha1:
        matched_fp = body_db.lookup(web_o.http_response_body_sha1)
        if len(matched_fp) > 0:
            blocked_score = 0.8
            blocking_scope = BlockingScope.UNKNOWN
            if request_is_encrypted:
                # Likely some form of server-side blocking
                blocking_scope = BlockingScope.SERVER_SIDE_BLOCK
                blocked_score = 0.5

            for fp_name in matched_fp:
                fp = fingerprintdb.get_fp(fp_name)
                if fp.scope:
                    blocking_scope = fp_to_scope(fp.scope)
                    outcome_meta["fingerprint"] = fp.name
                    outcome_meta["why"] = "matched fingerprint"
                    if (
                        fp.expected_countries
                        and web_o.probe_cc in fp.expected_countries
                    ):
                        outcome_label = "blocked"
                        blocked_score = 1.0
                    break

            return Outcome(
                observation_id=web_o.observation_id,
                scope=blocking_scope,
                label=outcome_label,
                subject=blocking_subject,
                category=outcome_category,
                detail="blockpage",
                meta=outcome_meta,
                ok_score=1 - blocked_score,
                down_score=0.0,
                blocked_score=blocked_score,
            )

    if not request_is_encrypted:
        # TODO: We should probably do mining of the body dumps to figure out if there
        # are blockpages in there instead of relying on a per-measurement heuristic

        # TODO: we don't have this
        # if web_o.http_response_body_sha1 == http_ctrl.response_body_sha1:
        #    return ok_be

        if (
            web_o.http_response_body_length
            and response_body_length
            # We need to ignore redirects as we should only be doing matching of the response body on the last element in the chain
            and (
                not web_o.http_response_header_location
                and not math.floor(web_o.http_response_status_code or 0 / 100) == 3
            )
            and (
                (web_o.http_response_body_length + 1.0) / (response_body_length + 1.0)
                < 0.7
            )
        ):
            outcome_meta["response_body_length"] = str(web_o.http_response_body_length)
            outcome_meta["ctrl_response_body_length"] = str(response_body_length)
            blocking_detail = f"http.body-diff"
            return Outcome(
                observation_id=web_o.observation_id,
                scope=BlockingScope.UNKNOWN,
                label="",
                subject=blocking_subject,
                category=outcome_category,
                detail=blocking_detail,
                meta=outcome_meta,
                ok_score=0.3,
                down_score=0.0,
                blocked_score=0.7,
            )

    return Outcome(
        observation_id=web_o.observation_id,
        scope=BlockingScope.UNKNOWN,
        label="",
        subject=blocking_subject,
        category=outcome_category,
        detail="ok",
        meta=outcome_meta,
        ok_score=0.8,
        down_score=0.0,
        blocked_score=0.2,
    )


def is_blocked_or_down(o: Optional[Outcome]) -> bool:
    if not o:
        return False
    if o.ok_score > 0.5:
        return False
    return True


def is_ip_blocked(dns_outcomes: List[Outcome], ip: Optional[str]) -> bool:
    if not ip:
        return False

    for outcome in dns_outcomes:
        if outcome.subject.startswith(ip):
            return is_blocked_or_down(outcome)
    return False


def make_website_experiment_result(
    web_observations: List[WebObservation],
    web_ground_truths: List[WebGroundTruth],
    body_db: BodyDB,
    fingerprintdb: FingerprintDB,
) -> Generator[ExperimentResult, None, None]:
    outcomes: List[Outcome] = []
    domain_name = web_observations[0].hostname

    # We need to process HTTP observations after all the others, because we
    # arent' guaranteed to have on the same row all connected observations.
    # If we don't do that, we will not exclude from our blocking calculations
    # cases in which something has already been counted as blocked through other
    # means
    http_obs = []
    is_tcp_blocked = False
    is_tls_blocked = False

    dns_observations_by_hostname = defaultdict(list)
    dns_outcomes_by_hostname = {}
    other_observations = []
    for web_o in web_observations:
        if web_o.dns_query_type:
            assert web_o.hostname is not None
            dns_observations_by_hostname[web_o.hostname].append(web_o)
        else:
            other_observations.append(web_o)

    for hostname, dns_observations in dns_observations_by_hostname.items():
        dns_outcomes = make_dns_outcomes(
            hostname=hostname,
            dns_observations=dns_observations,
            web_ground_truths=web_ground_truths,
            fingerprintdb=fingerprintdb,
        )
        outcomes += dns_outcomes
        dns_outcomes_by_hostname[hostname] = dns_outcomes

    for web_o in web_observations:
        # FIXME: for the moment we just ignore all IPv6 results, because they are too noisy
        if web_o.ip:
            try:
                ipaddr = ipaddress.ip_address(web_o.ip)
                if isinstance(ipaddr, ipaddress.IPv6Address):
                    continue
            except:
                log.error(f"Invalid IP in {web_o.ip}")

        request_is_encrypted = (
            web_o.http_request_url and web_o.http_request_url.startswith("https://")
        )
        dns_outcomes = dns_outcomes_by_hostname.get(web_o.hostname, [])

        tcp_outcome = None
        if not is_ip_blocked(dns_outcomes, web_o.ip) and web_o.tcp_success is not None:
            tcp_outcome = make_tcp_outcome(
                web_o=web_o, web_ground_truths=web_ground_truths
            )
            if is_blocked_or_down(tcp_outcome):
                is_tcp_blocked = True
            outcomes.append(tcp_outcome)

        tls_outcome = None
        # We ignore things that are already blocked by DNS or TCP
        if (
            not is_ip_blocked(dns_outcomes, web_o.ip)
            and not is_blocked_or_down(tcp_outcome)
            and (web_o.tls_failure or web_o.tls_cipher_suite is not None)
        ):
            tls_outcome = make_tls_outcome(
                web_o=web_o, web_ground_truths=web_ground_truths
            )
            outcomes.append(tls_outcome)
            if is_blocked_or_down(tls_outcome):
                is_tls_blocked = True

        # When we don't know the IP of the http_request, we add them to a
        # separate http_obs list.
        # This is done so we can ignore the HTTP outcome if ANY of the DNS
        # outcomes are an indication of blocking, since we can't do a
        # consistency check on a specific DNS answer.
        if web_o.http_request_url and not web_o.ip:
            http_obs.append(web_o)
            continue

        # For HTTP requests we ignore cases in which we detected the blocking
        # already to be happening via DNS or TCP.
        if (
            web_o.http_request_url
            and (
                not is_ip_blocked(dns_outcomes, web_o.ip)
                and not is_blocked_or_down(tcp_outcome)
                # For HTTPS requests we ignore cases in which we detected the blocking via DNS, TCP or TLS
            )
            and (
                request_is_encrypted == False
                or (request_is_encrypted and not is_blocked_or_down(tls_outcome))
            )
        ):
            http_outcome = make_http_outcome(
                web_o=web_o,
                web_ground_truths=web_ground_truths,
                body_db=body_db,
                fingerprintdb=fingerprintdb,
            )
            outcomes.append(http_outcome)

    # Here we examine all of the HTTP Observations that didn't record an IP address
    for web_o in http_obs:
        is_dns_blocked = any(
            [
                is_blocked_or_down(o)
                for o in dns_outcomes_by_hostname.get(web_o.hostname, [])
            ]
        )
        request_is_encrypted = (
            web_o.http_request_url and web_o.http_request_url.startswith("https://")
        )
        if (
            web_o.http_request_url
            and (
                not is_dns_blocked
                and not is_tcp_blocked
                # For HTTPS requests we ignore cases in which we detected the blocking via DNS, TCP or TLS
            )
            and (
                request_is_encrypted == False
                or (request_is_encrypted and not is_tls_blocked)
            )
        ):
            http_outcome = make_http_outcome(
                web_o=web_o,
                web_ground_truths=web_ground_truths,
                body_db=body_db,
                fingerprintdb=fingerprintdb,
            )
            outcomes.append(http_outcome)

    max_blocked_score = min(map(lambda o: o.blocked_score, outcomes))
    # TODO: we should probably be computing the anomaly and confirmed summary
    # flags directly as part of aggregation.
    confirmed = False
    for o in outcomes:
        if o.label == "blocked":
            confirmed = True
    anomaly = False
    if max_blocked_score > 0.5:
        anomaly = True

    return iter_experiment_results(
        obs=web_observations[0],
        experiment_group="websites",
        domain_name=domain_name or "",
        target_name=domain_name or "",
        anomaly=anomaly,
        confirmed=confirmed,
        outcomes=outcomes,
    )
