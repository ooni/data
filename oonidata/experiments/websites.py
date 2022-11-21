from dataclasses import dataclass
import ipaddress
from enum import Enum
from typing import Optional, List, Tuple, Dict
from urllib.parse import urlparse
from oonidata.experiments.control import DNSControl, HTTPControl, TCPControl
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
    TCPObservation,
    TLSObservation,
    WebObservation,
)

import logging

log = logging.getLogger("oonidata.processing")


def is_dns_consistent(
    web_o: WebObservation, dns_ctrl: DNSControl, netinfodb: NetinfoDB
) -> Tuple[bool, float]:
    if not web_o.dns_answer:
        return False, 0

    try:
        ipaddress.ip_address(web_o.dns_answer)
    except ValueError:
        # Not an IP, er can't do much to validate it
        return False, 0

    if web_o.dns_answer in dns_ctrl.tls_consistent_answers:
        return True, 1.0

    baseline_asns = set()
    baseline_as_org_names = set()

    for ip in dns_ctrl.tls_consistent_answers:
        ip_info = netinfodb.lookup_ip(web_o.measurement_start_time, ip)
        if ip_info:
            baseline_asns.add(ip_info.as_info.asn)
            baseline_as_org_names.add(ip_info.as_info.as_org_name.lower())

    if web_o.dns_answer_asn in baseline_asns:
        return True, 0.9

    # XXX maybe with the org_name we can also do something like levenshtein
    # distance to get more similarities
    if (
        web_o.dns_answer_as_org_name
        and web_o.dns_answer_as_org_name.lower() in baseline_as_org_names
    ):
        return True, 0.9

    other_answers = dns_ctrl.answers_map.copy()
    other_answers.pop(web_o.probe_cc, None)
    other_ips = {}
    other_asns = {}
    for answer_list in other_answers.values():
        for _, ip in answer_list:

            other_ips[ip] = other_ips.get(ip, 0)
            other_ips[ip] += 1
            if ip is None:
                log.error(f"Missing ip for {web_o.hostname}")
                continue
            ip_info = netinfodb.lookup_ip(web_o.measurement_start_time, ip)
            if ip_info:
                asn = ip_info.as_info.asn
                other_asns[asn] = other_asns.get(ip, 0)
                other_asns[asn] += 1

    if web_o.dns_answer in other_ips:
        x = other_ips[web_o.dns_answer]
        # This function was derived by looking for an exponential function in
        # the form f(x) = c1*a^x + c2 and solving for f(0) = 0 and f(10) = 1,
        # giving us a function in the form f(x) = (a^x - 1) / (a^10 - 1). We
        # then choose the magic value of 0.6 by looking for a solution in a
        # where f(1) ~= 0.5, doing a bit of plots and choosing a curve that
        # looks reasonably sloped.
        y = (pow(0.5, x) - 1) / (pow(0.5, 10) - 1)
        return True, min(0.9, 0.8 * y)

    if web_o.dns_answer in other_asns:
        x = other_asns[web_o.dns_answer_asn]
        y = (pow(0.5, x) - 1) / (pow(0.5, 10) - 1)
        return True, min(0.8, 0.7 * y)

    x = len(baseline_asns)
    y = (pow(0.5, x) - 1) / (pow(0.5, 10) - 1)
    return False, min(0.9, 0.8 * y)


def make_website_tcp_blocking_event(
    web_o: WebObservation, tcp_b: TCPControl
) -> Optional[BlockingEvent]:
    blocking_type = BlockingType.OK
    blocking_detail = "tcp.ok"
    blocking_subject = f"{web_o.ip}:{web_o.port}"
    blocking_meta = {}
    confidence = 1.0

    if web_o.tcp_failure:
        unreachable_cc_asn = list(tcp_b.unreachable_cc_asn)
        try:
            unreachable_cc_asn.remove((web_o.probe_cc, web_o.probe_asn))
        except ValueError:
            log.info(
                "missing failure in tcp baseline. You are probably using a control derived baseline."
            )

        reachable_count = len(tcp_b.reachable_cc_asn)
        unreachable_count = len(unreachable_cc_asn)
        blocking_meta = {
            "unreachable_count": str(unreachable_count),
            "reachable_count": str(reachable_count),
        }
        if reachable_count > unreachable_count:
            # We are adding back 1 because we removed it above and it avoid a divide by zero
            confidence = (
                reachable_count / (reachable_count + unreachable_count + 1) * 0.9
            )
            blocking_type = BlockingType.BLOCKED
        elif unreachable_count > reachable_count:
            confidence = (
                (unreachable_count + 1) / (reachable_count + unreachable_count + 1)
            ) * 0.9
            blocking_type = BlockingType.DOWN

        # TODO: should we bump up the confidence in the case of connection_reset?
        blocking_detail = f"tcp.{web_o.tcp_failure}"

    if web_o.tcp_success == True:
        return BlockingEvent(
            blocking_type=blocking_type,
            blocking_subject=blocking_subject,
            blocking_detail=blocking_detail,
            blocking_meta=blocking_meta,
            confidence=confidence,
        )


def get_blocking_for_dns_failure(
    web_o: WebObservation, dns_ctrl: DNSControl
) -> Tuple[BlockingType, str, float]:
    failure_cc_asn = list(dns_ctrl.failure_cc_asn)
    try:
        failure_cc_asn.remove((web_o.probe_cc, web_o.probe_asn))
    except ValueError:
        log.info(
            "missing failure for the probe in the baseline. You are probably using a control derived baseline."
        )

    failure_count = len(failure_cc_asn)
    ok_count = len(dns_ctrl.ok_cc_asn)

    if web_o.dns_failure == "dns_nxdomain_error":
        nxdomain_cc_asn = list(dns_ctrl.nxdomain_cc_asn)
        try:
            nxdomain_cc_asn.remove((web_o.probe_cc, web_o.probe_asn))
        except ValueError:
            log.info(
                "missing nx_domain failure for the probe in the baseline. You are probably using a control derived baseline."
            )

        nxdomain_count = len(nxdomain_cc_asn)
        blocking_detail = "dns.inconsistent.nxdomain"
        if ok_count > nxdomain_count:
            # We give a bit extra weight to an NXDOMAIN compared to other failures
            confidence = ok_count / (ok_count + nxdomain_count + 1)
            confidence = min(0.8, confidence * 1.5)
            blocking_type = BlockingType.BLOCKED
        else:
            confidence = (nxdomain_count + 1) / (ok_count + nxdomain_count + 1)
            blocking_type = BlockingType.DOWN
    elif ok_count > failure_count:
        confidence = ok_count / (ok_count + failure_count + 1)
        blocking_type = BlockingType.BLOCKED
        blocking_detail = f"dns.{web_o.dns_failure}"
    else:
        confidence = (failure_count + 1) / (ok_count + failure_count + 1)
        blocking_type = BlockingType.DOWN
        blocking_detail = f"dns.{web_o.dns_failure}"

    return blocking_type, blocking_detail, confidence


def make_website_dns_blocking_event(
    web_o: WebObservation,
    dns_ctrl: DNSControl,
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
) -> Optional[BlockingEvent]:

    blocking_subject = web_o.hostname or ""

    fingerprint_id = web_o.pp_dns_fingerprint_id
    fp = None
    if not fingerprint_id and web_o.dns_answer:
        fp = fingerprintdb.match_dns(web_o.dns_answer)
    elif fingerprint_id:
        fp = fingerprintdb.get_fp(fingerprint_id)

    if fp:
        blocking_type = fp_scope_to_outcome(fp.scope)
        confidence = 1.0
        # If we see the fingerprint in an unexpected country we should
        # significantly reduce the confidence in the block
        if fp.expected_countries and web_o.probe_cc not in fp.expected_countries:
            log.debug(
                f"Inconsistent probe_cc vs expected_countries {web_o.probe_cc} != {fp.expected_countries}"
            )
            confidence = 0.7

        return BlockingEvent(
            blocking_type=blocking_type,
            blocking_subject=blocking_subject,
            blocking_detail="dns.inconsistent.blockpage",
            blocking_meta={"ip": web_o.dns_answer or ""},
            confidence=confidence,
        )

    elif web_o.ip_is_bogon and len(dns_ctrl.tls_consistent_answers) > 0:
        return BlockingEvent(
            blocking_type=BlockingType.BLOCKED,
            blocking_subject=blocking_subject,
            blocking_detail="dns.inconsistent.bogon",
            blocking_meta={"ip": web_o.dns_answer or ""},
            confidence=0.9,
        )

    elif web_o.dns_failure:
        blocking_type, blocking_detail, confidence = get_blocking_for_dns_failure(
            web_o, dns_ctrl=dns_ctrl
        )
        return BlockingEvent(
            blocking_type=blocking_type,
            blocking_subject=blocking_subject,
            blocking_detail=blocking_detail,
            blocking_meta={"ip": web_o.dns_answer or ""},
            confidence=0.9,
        )

    elif web_o.tls_is_certificate_valid == False:
        return BlockingEvent(
            blocking_type=BlockingType.BLOCKED,
            blocking_subject=blocking_subject,
            blocking_detail="dns.inconsistent.tls_mismatch",
            blocking_meta={"ip": web_o.dns_answer or "", "why": "tls_inconsistent"},
            confidence=0.9,
        )

    elif web_o.tls_is_certificate_valid == None:
        # If we are in this case, it means we weren't able to determine the
        # consistency of the DNS query using TLS. This is the case either
        # because the tested site is not in HTTPS and therefore we didn't
        # generate a TLS measurement for it or because the target IP isn't
        # listening on HTTPS (which is quite fishy).
        # In either case we should flag these with being somewhat likely to be
        # blocked.
        ip_based_consistency, consistency_confidence = is_dns_consistent(
            web_o, dns_ctrl, netinfodb
        )
        if ip_based_consistency is False and consistency_confidence > 0:
            confidence = consistency_confidence
            blocking_detail = "dns.inconsistent.generic"
            # If the answer ASN is the same as the probe_asn, it's more likely
            # to be a blockpage
            if web_o.dns_answer_asn == web_o.probe_asn:
                blocking_detail = "dns.inconsistent.asn_match"
                confidence = 0.8
            # same for the answer_cc
            elif web_o.ip_as_cc == web_o.probe_cc:
                blocking_detail = "dns.inconsistent.cc_match"
                confidence = 0.7

            return BlockingEvent(
                blocking_type=BlockingType.BLOCKED,
                blocking_subject=blocking_subject,
                blocking_detail=blocking_detail,
                blocking_meta={"ip": web_o.dns_answer or "", "why": "tls_inconsistent"},
                confidence=0.9,
            )

    if web_o.dns_answer:
        # No blocking detected
        return BlockingEvent(
            blocking_type=BlockingType.OK,
            blocking_subject=blocking_subject,
            blocking_detail="dns.ok",
            blocking_meta={"ip": web_o.dns_answer or ""},
            confidence=0.8,
        )


def make_website_tls_blocking_event(web_o: WebObservation) -> Optional[BlockingEvent]:
    blocking_subject = web_o.hostname or ""

    if web_o.tls_is_certificate_valid == True:
        return BlockingEvent(
            blocking_type=BlockingType.OK,
            blocking_subject=blocking_subject,
            blocking_detail="tls.ok",
            blocking_meta={},
            confidence=1.0,
        )

    if web_o.tls_is_certificate_valid == False:
        # TODO: this is wrong. We need to consider the baseline to establish TLS
        # MITM, because the cert might be invalid also from other location (eg.
        # it expired) and not due to censorship.
        return BlockingEvent(
            blocking_type=BlockingType.BLOCKED,
            blocking_subject=blocking_subject,
            blocking_detail="tls.mitm",
            blocking_meta={"why": "invalid certificate"},
            confidence=0.8,
        )

    elif web_o.tls_failure:
        # We only consider it to be a TLS level verdict if we haven't seen any
        # blocks in TCP
        blocking_detail = f"tls.{web_o.tls_failure}"
        confidence = 0.5

        if web_o.tls_handshake_read_count == 0 and web_o.tls_handshake_write_count == 1:
            # This means we just wrote the TLS ClientHello, let's give it a bit
            # more confidence in it being a block
            confidence = 0.7

        if web_o.tls_failure in ("connection_closed", "connection_reset"):
            confidence += 0.2

        return BlockingEvent(
            blocking_type=BlockingType.BLOCKED,
            blocking_subject=blocking_subject,
            blocking_detail=blocking_detail,
            blocking_meta={},
            confidence=confidence,
        )


def make_website_http_blocking_event(
    web_o: WebObservation,
    http_ctrl: HTTPControl,
    fingerprintdb: FingerprintDB,
) -> Optional[BlockingEvent]:
    blocking_subject = web_o.http_request_url or ""

    request_is_encrypted = web_o.http_request_url and web_o.http_request_url.startswith(
        "https://"
    )

    ok_be = BlockingEvent(
        blocking_type=BlockingType.OK,
        blocking_subject=blocking_subject,
        blocking_detail="http.ok",
        blocking_meta={},
        confidence=0.8,
    )

    detail_prefix = "http."
    if request_is_encrypted:
        detail_prefix = "https."

    if web_o.http_failure:
        failure_cc_asn = list(http_ctrl.failure_cc_asn)
        try:
            failure_cc_asn.remove((web_o.probe_cc, web_o.probe_asn))
        except ValueError:
            log.info(
                "missing failure in http baseline. Either something is wrong or you are using a control derived baseline"
            )

        failure_count = len(failure_cc_asn)
        ok_count = len(http_ctrl.ok_cc_asn)
        if ok_count > failure_count:
            # We are adding back 1 because we removed it above and it avoid a divide by zero
            confidence = ok_count / (ok_count + failure_count + 1)
            blocking_type = BlockingType.BLOCKED
        else:
            confidence = (failure_count + 1) / (ok_count + failure_count + 1)
            blocking_type = BlockingType.DOWN
        blocking_detail = f"{detail_prefix}{web_o.http_failure}"

        return BlockingEvent(
            blocking_type=blocking_type,
            blocking_subject=blocking_subject,
            blocking_detail=blocking_detail,
            blocking_meta={},
            confidence=confidence,
        )

    elif web_o.pp_http_response_matches_blockpage:
        blocking_type = BlockingType.BLOCKED
        blocking_meta = {}
        confidence = 0.7
        if request_is_encrypted:
            # Likely some form of server-side blocking
            blocking_type = BlockingType.SERVER_SIDE_BLOCK
            confidence = 0.5
        elif web_o.pp_http_fingerprint_country_consistent:
            confidence = 1

        for fp_name in web_o.pp_http_response_fingerprints:
            fp = fingerprintdb.get_fp(fp_name)
            if fp.scope:
                blocking_type = fp_scope_to_outcome(fp.scope)
                blocking_meta = {"fp_name": fp.name, "why": "matched fingerprint"}
                break

        blocking_detail = f"{detail_prefix}diff"
        return BlockingEvent(
            blocking_type=blocking_type,
            blocking_subject=blocking_subject,
            blocking_detail=blocking_detail,
            blocking_meta=blocking_meta,
            confidence=confidence,
        )

    elif not request_is_encrypted:
        if web_o.http_response_body_sha1 == http_ctrl.response_body_sha1:
            return ok_be
        if web_o.pp_http_response_matches_false_positive:
            return ok_be
        if web_o.pp_http_response_body_title == http_ctrl.response_body_title:
            return ok_be
        if web_o.pp_http_response_body_meta_title == http_ctrl.response_body_meta_title:
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

    return ok_be


def is_blocked(be: Optional[BlockingEvent]) -> bool:
    if not be:
        return False
    if be.blocking_type not in (BlockingType.OK, BlockingType.DOWN):
        return True
    return False


@dataclass
class WebsiteExperimentResult(ExperimentResult):
    domain_name: str
    website_name: str


def make_website_experiment_result(
    web_observations: List[WebObservation],
    dns_ctrl: DNSControl,
    tcp_ctrl_map: Dict[str, TCPControl],
    http_ctrl_map: Dict[str, HTTPControl],
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
) -> WebsiteExperimentResult:
    """
    make_website_verdicts will yield many verdicts given some observations
    related to a website measurement.

    We MUST pass in DNS observations, but observations of other types are
    optional. This is to workaround the fact that not every version of OONI
    Probe was generating all types of observations.

    The order in which we compute the verdicts is important, since the knowledge
    of some form of blocking is relevant to being able to determine future
    methods of blocking.
    Examples of this include:
    * If you know that DNS is consistent and you see a TLS certificate
    validation error, you can conclude that it's a MITM
    * If you see that TCP connect is failing, you will not attribute a failing
    TLS to a TLS level interference (ex. SNI filtering)

    For some lists of observations we also need to pass in a baseline. The
    baseline is some groundtruth related to the targets being measured that are
    needed in order to draw some meaningful conclusion about it's blocking.
    We need this so that we are able to exclude instances in which the target is
    unavailable due to transient network failures.

    It is the job of who calls the make_website_verdicts function to build this
    baseline by either running queries against the database of observations or
    using some set of observations that are already in memory.

    The basic idea is that since we are going to be generating verdicts in
    windows of 24h, we would have to do the baselining only once for the 24h
    time window given a certain domain.
    """
    blocking_events = []
    observation_ids = []

    domain_name = web_observations[0].hostname
    for web_o in web_observations:
        request_is_encrypted = (
            web_o.http_request_url and web_o.http_request_url.startswith("https://")
        )

        observation_ids.append(web_o.observation_id)
        dns_be = make_website_dns_blocking_event(
            web_o, dns_ctrl, fingerprintdb, netinfodb
        )
        if dns_be:
            blocking_events.append(dns_be)

        # TODO: this is now missing
        # If we didn't get a DNS blocking event from an observation, it means that
        # observation was a sign of everything being OK, hence we should
        # ignore all the previous DNS verdicts as likely false positives and
        # just consider no DNS level censorship to be happening.
        # TODO: probably we want to just reduce the confidence of the DNS
        # level blocks in this case by some factor.

        tcp_be = None
        if not is_blocked(dns_be):
            tcp_ctrl = tcp_ctrl_map.get(f"{web_o.ip}:{web_o.port}")
            if tcp_ctrl:
                tcp_be = make_website_tcp_blocking_event(web_o, tcp_ctrl)
                if tcp_be:
                    blocking_events.append(tcp_be)

        tls_be = None
        # We ignore things that are already blocked by DNS or TCP
        if not is_blocked(dns_be) and not is_blocked(tcp_be):
            tls_be = make_website_tls_blocking_event(web_o)
            if tls_be:
                blocking_events.append(tls_be)

        # For HTTP requests we ignore cases in which we detected the blocking
        # already to be happening via DNS or TCP.
        if (
            web_o.http_request_url
            and (
                not is_blocked(dns_be)
                and not is_blocked(tcp_be)
                # For HTTPS requests we ignore cases in which we detected the blocking via DNS, TCP or TLS
            )
            and (
                request_is_encrypted == False
                or (request_is_encrypted and not is_blocked(tls_be))
            )
        ):
            http_ctrl = http_ctrl_map.get(web_o.http_request_url)
            if http_ctrl:
                http_be = make_website_http_blocking_event(
                    web_o, http_ctrl, fingerprintdb
                )
                blocking_events.append(http_be)

    # TODO: Should we be including this also BlockingType.DOWN,SERVER_SIDE_BLOCK or not?
    nok_blocking_confidence = list(
        map(
            lambda be: be.confidence,
            filter(
                lambda be: be.blocking_type
                not in (
                    BlockingType.OK,
                    BlockingType.DOWN,
                    BlockingType.SERVER_SIDE_BLOCK,
                ),
                blocking_events,
            ),
        )
    )
    ok_blocking_confidence = list(
        map(
            lambda be: be.confidence,
            filter(
                lambda be: be.blocking_type == BlockingType.OK,
                blocking_events,
            ),
        )
    )

    ok_confidence = 0.5
    if len(ok_blocking_confidence) > 0:
        ok_confidence = min(ok_blocking_confidence)

    if len(nok_blocking_confidence) > 0:
        ok_confidence = 1 - max(nok_blocking_confidence)

    confirmed = False
    anomaly = False
    if ok_confidence == 0:
        confirmed = True
    if ok_confidence < 0.6:
        anomaly = True

    return WebsiteExperimentResult(
        domain_name=domain_name or "",
        website_name=domain_name or "",
        blocking_events=blocking_events,
        observation_ids=observation_ids,
        anomaly=anomaly,
        confirmed=confirmed,
        ok_confidence=ok_confidence,
        **make_base_result_meta(web_observations[0]),
    )
