from collections import defaultdict
from dataclasses import dataclass
import ipaddress
import time
from typing import Any, Generator, Iterable, Optional, List, Tuple, Dict
from oonidata.experiments.control import (
    WebGroundTruth,
    BodyDB,
)
from oonidata.experiments.experiment_result import (
    BlockingScope,
    Outcome,
    Scores,
    ExperimentResult,
    fp_to_scope,
    iter_experiment_results,
)

from oonidata.fingerprintdb import FingerprintDB

from oonidata.observations import (
    WebObservation,
)

import logging

log = logging.getLogger("oonidata.processing")

CLOUD_PROVIDERS_ASNS = [
    13335,  # Cloudflare: https://www.peeringdb.com/net/4224
    20940,  # Akamai: https://www.peeringdb.com/net/2
    396982,  # Google Cloud: https://www.peeringdb.com/net/30878
]

CLOUD_PROVIDERS_AS_ORGS = ["Akamai Technologies, Inc.".lower()]


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


def confidence_estimate(x, factor=0.8, clamping=0.9):
    """
    Gives an estimate of confidence given the number of datapoints that are
    consistent (x).

    clamping: defines what is the maximum value it can take
    factor: is a multiplicate factor to decrease the value of the function

    This function was derived by looking for an exponential function in
    the form f(x) = c1*a^x + c2 and solving for f(0) = 0 and f(10) = 1,
    giving us a function in the form f(x) = (a^x - 1) / (a^10 - 1). We
    then choose the magic value of 0.6 by looking for a solution in a
    where f(1) ~= 0.5, doing a bit of plots and choosing a curve that
    looks reasonably sloped.
    """
    y = (pow(0.5, x) - 1) / (pow(0.5, 10) - 1)
    return min(clamping, factor * y)


def ok_vs_nok_score(
    ok_count: int,
    nok_count: int,
    blocking_factor: float = 0.8,
    down_factor: float = 0.8,
) -> Scores:
    """
    This is a very simplistic estimation that just looks at the proportions of
    failures to reachable measurement to establish if something is blocked or
    not.
    If we see in the ground truth reachable_count = 1, unreachable_count = 0,
    this will leads to a blocking_score of 0.8, down_score of 0.0 and ok_score
    of 0.2.
    OTOH, if we see something an amibigious ground truth, such as
    reachable_count = 1, unreachable_count = 1, we get:
    blocking_score = 0.4, down_score = 0.4, ok_score = 0.2, which basically
    means we have no idea what is going on.
    TODO: do we want to use a variable multiplicative factor of 0.8 depending
    on the type of tcp_failure we are seeing?
    """
    blocked_score = 0.3
    down_score = 0.3
    total_count = ok_count + nok_count
    if total_count > 0:
        blocked_score = ok_count / total_count * blocking_factor
        down_score = nok_count / total_count * down_factor
    ok_score = 1 - blocked_score - down_score
    return Scores(ok=ok_score, blocked=blocked_score, down=down_score)


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
    for gt in ground_truths:
        # We don't check for strict == True, since depending on the DB engine
        # True could also be represented as 1
        if gt.tcp_success is None:
            continue
        if gt.tcp_success:
            reachable_cc_asn.add((gt.vp_cc, gt.vp_asn))
        else:
            unreachable_cc_asn.add((gt.vp_cc, gt.vp_asn))

    reachable_count = len(reachable_cc_asn)
    unreachable_count = len(unreachable_cc_asn)
    blocking_meta = {
        "unreachable_count": str(unreachable_count),
        "reachable_count": str(reachable_count),
    }

    scores = ok_vs_nok_score(ok_count=reachable_count, nok_count=unreachable_count)
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


def make_dns_outcome(
    web_o: WebObservation,
    web_ground_truths: List[WebGroundTruth],
    fingerprintdb: FingerprintDB,
) -> Outcome:

    assert (
        web_o.hostname is not None
    ), f"missing hostname field for query in {web_o.measurement_uid}"
    blocking_subject = web_o.hostname
    outcome_label = ""
    outcome_scope = BlockingScope.UNKNOWN
    outcome_meta = {}

    fp = None
    if web_o.dns_answer:
        fp = fingerprintdb.match_dns(web_o.dns_answer)

    if fp:
        outcome_scope = fp_to_scope(fp.scope)
        print(f"SCOPE {outcome_scope}")
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

    ground_truths = filter(
        lambda gt: gt.hostname == web_o.hostname,
        web_ground_truths,
    )
    if web_o.dns_failure:
        nxdomain_cc_asn = set()
        failure_cc_asn = set()
        ok_cc_asn = set()
        for gt in ground_truths:
            # We don't check for strict == True, since depending on the DB engine
            # True could also be represented as 1
            if gt.dns_success is None:
                continue
            if gt.dns_success:
                ok_cc_asn.add((gt.vp_cc, gt.vp_asn))
            else:
                failure_cc_asn.add((gt.vp_cc, gt.vp_asn))
            if gt.dns_failure == "dns_nxdomain_error":
                nxdomain_cc_asn.add((gt.vp_cc, gt.vp_asn))

        ok_count = len(ok_cc_asn)
        failure_count = len(failure_cc_asn)
        nxdomain_count = len(nxdomain_cc_asn)

        outcome_meta["ok_count"] = str(ok_count)
        outcome_meta["failure_count"] = str(failure_count)
        outcome_meta["nxdomain_count"] = str(nxdomain_count)
        blocking_detail = f"failure.{web_o.dns_failure}"
        scores = ok_vs_nok_score(
            ok_count=ok_count,
            nok_count=failure_count,
            blocking_factor=0.8,
            down_factor=0.8,
        )
        if web_o.dns_failure == "dns_nxdomain_error":
            blocking_detail = "inconsistent.nxdomain"
            scores = ok_vs_nok_score(
                ok_count=ok_count,
                nok_count=nxdomain_count,
                blocking_factor=0.9,
                down_factor=0.9,
            )
        return Outcome(
            observation_id=web_o.observation_id,
            scope=outcome_scope,
            subject=blocking_subject,
            label=outcome_label,
            category="dns",
            detail=blocking_detail,
            meta=outcome_meta,
            ok_score=scores.ok,
            down_score=scores.down,
            blocked_score=scores.blocked,
        )

    # Here we count how many vantage vantage points, as in distinct probe_cc,
    # probe_asn pairs, had this DNS answer
    other_ips = defaultdict(set)
    other_asns = defaultdict(set)
    trusted_answers = {}
    for gt in ground_truths:
        if gt.dns_success != True:
            continue
        other_ips[gt.ip].add((gt.vp_cc, gt.vp_asn))
        assert gt.ip, "did not find IP in ground truth"
        other_asns[gt.ip_asn].add((gt.vp_cc, gt.vp_asn))
        if gt.tls_is_certificate_valid != False and gt.is_trusted_vp != True:
            continue
        trusted_answers[gt.ip] = gt

    outcome_meta["ip"] = web_o.dns_answer or ""
    if web_o.ip_is_bogon:
        outcome_meta["why"] = "answer is bogon"
        down_score = 0.1
        blocked_score = 0.9
        # If we saw the same bogon IP inside of the trusted_answers, it means it
        # it's always returning a bogon and hence this site is actually down
        if web_o.dns_answer in trusted_answers:
            outcome_meta["why"] = "answer is bogon as expected"
            down_score = 0.9
            blocked_score = 0.1

        return Outcome(
            observation_id=web_o.observation_id,
            scope=outcome_scope,
            subject=blocking_subject,
            label=outcome_label,
            category="dns",
            detail="inconsistent.bogon",
            meta=outcome_meta,
            ok_score=0.0,
            down_score=down_score,
            blocked_score=blocked_score,
        )

    if web_o.tls_is_certificate_valid == True or web_o.dns_answer in trusted_answers:
        outcome_meta["why"] = "resolved IP in trusted answers"
        # No blocking detected
        return Outcome(
            observation_id=web_o.observation_id,
            scope=outcome_scope,
            label=outcome_label,
            subject=blocking_subject,
            category="dns",
            detail="ok",
            meta=outcome_meta,
            ok_score=1.0,
            down_score=0.0,
            blocked_score=0.0,
        )

    if web_o.tls_is_certificate_valid == False:
        # TODO: we probably need to handle cases here where it might be the case
        # that the CERT is bad because it's always serving a bad certificate.
        # here is an example: https://explorer.ooni.org/measurement/20220930T235729Z_webconnectivity_AE_5384_n1_BLcO454Y5UULxZoq?input=https://www.government.ae/en%23%2F
        outcome_meta["why"] = "tls certificate is bad"
        return Outcome(
            observation_id=web_o.observation_id,
            scope=outcome_scope,
            label=outcome_label,
            subject=blocking_subject,
            category="dns",
            detail="inconsistent",
            meta=outcome_meta,
            ok_score=0.0,
            # We give a little bit of weight to the down score, due to no ground
            # truthing of TLS
            down_score=0.2,
            blocked_score=0.8,
        )

    # If we are in this case, it means we weren't able to determine the
    # consistency of the DNS query using TLS. This is the case either
    # because the tested site is not in HTTPS and therefore we didn't
    # generate a TLS measurement for it or because the target IP isn't
    # listening on HTTPS (which is quite fishy).
    # In either case we should flag these with being somewhat likely to be
    # blocked.
    ground_truth_asns = set()
    ground_truth_as_org_names = set()
    for gt in trusted_answers.values():
        assert gt.ip, f"did not find IP in ground truth {gt.ip}"
        ground_truth_asns.add(gt.ip_asn)
        ground_truth_as_org_names.add(gt.ip_as_org_name.lower())

    if web_o.dns_answer_asn in ground_truth_asns:
        outcome_meta["why"] = "answer in matches AS of trusted answers"
        return Outcome(
            observation_id=web_o.observation_id,
            scope=outcome_scope,
            label=outcome_label,
            subject=blocking_subject,
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
            scope=outcome_scope,
            label=outcome_label,
            subject=blocking_subject,
            category="dns",
            detail="ok",
            meta=outcome_meta,
            ok_score=0.9,
            down_score=0.0,
            blocked_score=0.1,
        )

    if web_o.dns_answer in other_ips:
        outcome_meta["why"] = "answer in resolved IPs ground truth"
        outcome_meta["other_ip_count"] = len(other_ips[web_o.dns_answer])
        blocked_score = confidence_estimate(
            len(other_ips[web_o.dns_answer]), clamping=0.9, factor=0.8
        )
        ok_score = 1 - blocked_score
        return Outcome(
            observation_id=web_o.observation_id,
            scope=outcome_scope,
            label=outcome_label,
            subject=blocking_subject,
            category="dns",
            detail="ok",
            meta=outcome_meta,
            ok_score=ok_score,
            down_score=0.0,
            blocked_score=blocked_score,
        )

    if web_o.dns_answer in other_asns:
        # We clamp this to some lower values and scale it by a smaller factor,
        # since ASN consistency is less strong than direct IP match.
        outcome_meta["why"] = "answer AS in ground truth"
        outcome_meta["other_asn_count"] = len(other_asns[web_o.dns_answer])
        blocked_score = confidence_estimate(
            len(other_asns[web_o.dns_answer]), clamping=0.9, factor=0.8
        )
        ok_score = 1 - blocked_score
        return Outcome(
            observation_id=web_o.observation_id,
            scope=outcome_scope,
            label=outcome_label,
            subject=blocking_subject,
            category="dns",
            detail="ok",
            meta=outcome_meta,
            ok_score=ok_score,
            down_score=0.0,
            blocked_score=blocked_score,
        )

    if (
        web_o.ip_asn in CLOUD_PROVIDERS_ASNS
        or (web_o.ip_as_org_name and web_o.ip_as_org_name.lower())
        in CLOUD_PROVIDERS_AS_ORGS
    ):
        # Cloud providers are a common source of false positives. Let's just
        # mark them as ok with a low confidence
        outcome_meta["why"] = "answer is cloud service provider"
        return Outcome(
            observation_id=web_o.observation_id,
            scope=outcome_scope,
            label=outcome_label,
            subject=blocking_subject,
            category="dns",
            detail="ok",
            meta=outcome_meta,
            ok_score=0.6,
            down_score=0.0,
            blocked_score=0.4,
        )

    outcome_meta["why"] = "unable to determine consistency through ground truth"
    blocked_score = 0.6
    outcome_detail = "inconsistent"

    # It's more common to answer to DNS queries for blocking with IPs managed by
    # the ISP (ex. to serve their blockpage).
    # So we give this a bit higher confidence
    if web_o.dns_answer_asn == web_o.probe_asn:
        blocked_score = 0.8
        outcome_meta["why"] = "answer matches probe_asn"
    # It's common to do this also in the country, for example when the blockpage
    # is centrally managed (ex. case in IT, ID)
    elif web_o.ip_as_cc == web_o.probe_cc:
        outcome_meta["why"] = "answer matches probe_cc"
        blocked_score = 0.7

    # We haven't managed to figured out if the DNS resolution was a good one, so
    # we are going to assume it's bad.
    return Outcome(
        observation_id=web_o.observation_id,
        scope=outcome_scope,
        label=outcome_label,
        subject=blocking_subject,
        category="dns",
        detail=outcome_detail,
        meta=outcome_meta,
        ok_score=1 - blocked_score,
        down_score=0.0,
        blocked_score=blocked_score,
    )


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

    if web_o.tls_is_certificate_valid == False:
        # TODO: this is wrong. We need to consider the baseline to establish TLS
        # MITM, because the cert might be invalid also from other location (eg.
        # it expired) and not due to censorship.
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

    elif web_o.tls_failure:
        # We only consider it to be a TLS level verdict if we haven't seen any
        # blocks in TCP
        blocking_detail = f"{web_o.tls_failure}"
        blocked_score = 0.5

        if web_o.tls_handshake_read_count == 0 and web_o.tls_handshake_write_count == 1:
            # This means we just wrote the TLS ClientHello, let's give it a bit
            # more confidence in it being a block
            blocked_score = 0.7

        if web_o.tls_failure in ("connection_closed", "connection_reset"):
            blocked_score = 0.85

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
    if web_o.http_failure:
        failure_cc_asn = set()
        ok_cc_asn = set()
        for gt in ground_truths:
            # We don't check for strict == True, since depending on the DB engine
            # True could also be represented as 1
            if gt.http_success is None:
                continue

            if gt.http_success:
                ok_cc_asn.add((gt.vp_cc, gt.vp_asn, gt.count))
            else:
                failure_cc_asn.add((gt.vp_cc, gt.vp_asn, gt.count))

        failure_count = len(failure_cc_asn)
        ok_count = len(ok_cc_asn)
        outcome_meta["ok_count"] = str(ok_count)
        outcome_meta["failure_count"] = str(failure_count)
        scores = ok_vs_nok_score(ok_count=ok_count, nok_count=failure_count)

        outcome_detail = f"{web_o.http_failure}"

        return Outcome(
            observation_id=web_o.observation_id,
            scope=BlockingScope.UNKNOWN,
            label="",
            subject=blocking_subject,
            category="tls",
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
        # TODO we don't currently do any of this to keep things simple.
        # We should probably do mining of the body dumps to figure out if there
        # are blockpages in there instead of relying on a per-measurement heuristic
        """
        ground_truths = filter(lambda gt: gt.http_response_body_length, ground_truths)
        if web_o.http_response_body_sha1 == http_ctrl.response_body_sha1:
            return ok_be

        if (
            web_o.http_response_body_length
            and http_ctrl.response_body_length
            and (
                (web_o.http_response_body_length + 1.0)
                / (http_ctrl.response_body_length + 1.0)
                < 0.7
            )
        ):
            blocking_detail = f"{detail_prefix}diff.body"
            return BlockingEvent(
                blocking_type=BlockingType.BLOCKED,
                blocking_subject=blocking_subject,
                blocking_detail=blocking_detail,
                blocking_meta={"why": "inconsistent body length"},
                confidence=0.6,
            )
        """

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


def is_blocked(o: Optional[Outcome]) -> bool:
    if not o:
        return False
    if o.blocked_score > 0.3:
        return True
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
    is_dns_blocked = False
    is_tcp_blocked = False
    is_tls_blocked = False
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

        dns_outcome = None
        if web_o.dns_query_type:
            # We have data related to DNS and it's a failure
            dns_outcome = make_dns_outcome(
                web_o=web_o,
                web_ground_truths=web_ground_truths,
                fingerprintdb=fingerprintdb,
            )
            if is_blocked(dns_outcome):
                is_dns_blocked = True
            outcomes.append(dns_outcome)

        # TODO: this is now missing
        # If we didn't get a DNS blocking event from an observation, it means that
        # observation was a sign of everything being OK, hence we should
        # ignore all the previous DNS verdicts as likely false positives and
        # just consider no DNS level censorship to be happening.
        # TODO: probably we want to just reduce the confidence of the DNS
        # level blocks in this case by some factor.

        tcp_outcome = None
        if not is_blocked(dns_outcome) and web_o.tcp_success is not None:
            tcp_outcome = make_tcp_outcome(
                web_o=web_o, web_ground_truths=web_ground_truths
            )
            if is_blocked(tcp_outcome):
                is_tcp_blocked = True
            outcomes.append(tcp_outcome)

        tls_outcome = None
        # We ignore things that are already blocked by DNS or TCP
        if (
            not is_blocked(dns_outcome)
            and not is_blocked(tcp_outcome)
            and (web_o.tls_failure or web_o.tls_cipher_suite is not None)
        ):
            tls_outcome = make_tls_outcome(
                web_o=web_o, web_ground_truths=web_ground_truths
            )
            outcomes.append(tls_outcome)
            if is_blocked(tls_outcome):
                is_tls_blocked = True

        if web_o.http_request_url and not web_o.ip:
            http_obs.append(web_o)
            continue

        # For HTTP requests we ignore cases in which we detected the blocking
        # already to be happening via DNS or TCP.
        if (
            web_o.http_request_url
            and (
                not is_blocked(dns_outcome)
                and not is_blocked(tcp_outcome)
                # For HTTPS requests we ignore cases in which we detected the blocking via DNS, TCP or TLS
            )
            and (
                request_is_encrypted == False
                or (request_is_encrypted and not is_blocked(tls_outcome))
            )
        ):
            http_outcome = make_http_outcome(
                web_o=web_o,
                web_ground_truths=web_ground_truths,
                body_db=body_db,
                fingerprintdb=fingerprintdb,
            )
            outcomes.append(http_outcome)

    for web_o in http_obs:
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
