from dataclasses import dataclass
import ipaddress
from enum import Enum
from typing import Optional, List, Tuple, Dict
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
    NettestObservation,
    TCPObservation,
    TLSObservation,
)

import logging

log = logging.getLogger("oonidata.processing")


def is_dns_consistent(
    dns_o: DNSObservation, dns_ctrl: DNSControl, netinfodb: NetinfoDB
) -> Tuple[bool, float]:
    if not dns_o.answer:
        return False, 0

    try:
        ipaddress.ip_address(dns_o.answer)
    except ValueError:
        # Not an IP, er can't do much to validate it
        return False, 0

    if dns_o.answer in dns_ctrl.tls_consistent_answers:
        return True, 1.0

    baseline_asns = set()
    baseline_as_org_names = set()

    for ip in dns_ctrl.tls_consistent_answers:
        ip_info = netinfodb.lookup_ip(dns_o.timestamp, ip)
        if ip_info:
            baseline_asns.add(ip_info.as_info.asn)
            baseline_as_org_names.add(ip_info.as_info.as_org_name.lower())

    if dns_o.answer_asn in baseline_asns:
        return True, 0.9

    # XXX maybe with the org_name we can also do something like levenshtein
    # distance to get more similarities
    if (
        dns_o.answer_as_org_name
        and dns_o.answer_as_org_name.lower() in baseline_as_org_names
    ):
        return True, 0.9

    other_answers = dns_ctrl.answers_map.copy()
    other_answers.pop(dns_o.probe_cc, None)
    other_ips = {}
    other_asns = {}
    for answer_list in other_answers.values():
        for _, ip in answer_list:

            other_ips[ip] = other_ips.get(ip, 0)
            other_ips[ip] += 1
            if ip is None:
                log.error(f"Missing ip for {dns_o.domain_name}")
                continue
            ip_info = netinfodb.lookup_ip(dns_o.timestamp, ip)
            if ip_info:
                asn = ip_info.as_info.asn
                other_asns[asn] = other_asns.get(ip, 0)
                other_asns[asn] += 1

    if dns_o.answer in other_ips:
        x = other_ips[dns_o.answer]
        # This function was derived by looking for an exponential function in
        # the form f(x) = c1*a^x + c2 and solving for f(0) = 0 and f(10) = 1,
        # giving us a function in the form f(x) = (a^x - 1) / (a^10 - 1). We
        # then choose the magic value of 0.6 by looking for a solution in a
        # where f(1) ~= 0.5, doing a bit of plots and choosing a curve that
        # looks reasonably sloped.
        y = (pow(0.5, x) - 1) / (pow(0.5, 10) - 1)
        return True, min(0.9, 0.8 * y)

    if dns_o.answer in other_asns:
        x = other_asns[dns_o.answer_asn]
        y = (pow(0.5, x) - 1) / (pow(0.5, 10) - 1)
        return True, min(0.8, 0.7 * y)

    x = len(baseline_asns)
    y = (pow(0.5, x) - 1) / (pow(0.5, 10) - 1)
    return False, min(0.9, 0.8 * y)


def make_website_tcp_blocking_event(
    tcp_o: TCPObservation, tcp_b: TCPControl
) -> BlockingEvent:
    blocking_type = BlockingType.OK
    blocking_detail = "ok"
    blocking_subject = f"{tcp_o.ip}:{tcp_o.port}"
    blocking_meta = {}
    confidence = 1.0

    if tcp_o.failure:
        unreachable_cc_asn = list(tcp_b.unreachable_cc_asn)
        try:
            unreachable_cc_asn.remove((tcp_o.probe_cc, tcp_o.probe_asn))
        except ValueError:
            log.info(
                "missing failure in tcp baseline. You are probably using a control derived baseline."
            )

        reachable_count = len(tcp_b.reachable_cc_asn)
        unreachable_count = len(unreachable_cc_asn)
        blocking_meta = {
            "unreachable_count": unreachable_count,
            "reachable_count": reachable_count,
        }
        if reachable_count > unreachable_count:
            # We are adding back 1 because we removed it above and it avoid a divide by zero
            confidence = reachable_count / (reachable_count + unreachable_count + 1)
            blocking_type = BlockingType.BLOCKED
        elif unreachable_count > reachable_count:
            confidence = (unreachable_count + 1) / (
                reachable_count + unreachable_count + 1
            )
            blocking_type = BlockingType.BLOCKED

        # TODO: should we bump up the confidence in the case of connection_reset?
        blocking_detail = f"tcp.{tcp_o.failure}"

    return BlockingEvent(
        blocking_type=blocking_type,
        blocking_subject=blocking_subject,
        blocking_detail=blocking_detail,
        blocking_meta=blocking_meta,
        confidence=confidence,
    )


def make_website_dns_blocking_event(
    dns_o: DNSObservation,
    dns_ctrl: DNSControl,
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
) -> BlockingEvent:

    blocking_subject = dns_o.domain_name

    if dns_o.fingerprint_id:
        fp = fingerprintdb.get_fp(dns_o.fingerprint_id)
        blocking_type = fp_scope_to_outcome(fp.scope)
        confidence = 1.0
        # If we see the fingerprint in an unexpected country we should
        # significantly reduce the confidence in the block
        if (
            dns_o.probe_cc
            and fp.expected_countries
            and len(fp.expected_countries) > 0
            and dns_o.probe_cc not in fp.expected_countries
        ):
            log.debug(
                f"Inconsistent probe_cc vs expected_countries {dns_o.probe_cc} != {fp.expected_countries}"
            )
            confidence = 0.7

        return BlockingEvent(
            blocking_type=blocking_type,
            blocking_subject=blocking_subject,
            blocking_detail="dns.inconsistent.blockpage",
            blocking_meta={"ip": dns_o.answer},
            confidence=confidence,
        )

    elif dns_o.answer_is_bogon and len(dns_ctrl.tls_consistent_answers) > 0:
        return BlockingEvent(
            blocking_type=BlockingType.BLOCKED,
            blocking_subject=blocking_subject,
            blocking_detail="dns.inconsistent.bogon",
            blocking_meta={"ip": dns_o.answer},
            confidence=0.9,
        )

    elif dns_o.failure:
        failure_cc_asn = list(dns_ctrl.failure_cc_asn)
        try:
            failure_cc_asn.remove((dns_o.probe_cc, dns_o.probe_asn))
        except ValueError:
            log.info(
                "missing failure for the probe in the baseline. You are probably using a control derived baseline."
            )

        failure_count = len(failure_cc_asn)
        ok_count = len(dns_ctrl.ok_cc_asn)

        if dns_o.failure == "dns_nxdomain_error":
            nxdomain_cc_asn = list(dns_ctrl.nxdomain_cc_asn)
            try:
                nxdomain_cc_asn.remove((dns_o.probe_cc, dns_o.probe_asn))
            except ValueError:
                log.info(
                    "missing nx_domain failure for the probe in the baseline. You are probably using a control derived baseline."
                )

            nxdomain_count = len(nxdomain_cc_asn)
            if ok_count > nxdomain_count:
                # We give a bit extra weight to an NXDOMAIN compared to other failures
                confidence = ok_count / (ok_count + nxdomain_count + 1)
                confidence = min(0.8, confidence * 1.5)
                blocking_type = BlockingType.BLOCKED
                blocking_detail = "dns.inconsistent.nxdomain"
            else:
                confidence = (nxdomain_count + 1) / (ok_count + nxdomain_count + 1)
                blocking_type = BlockingType.DOWN
                blocking_detail = "dns.inconsistent.nxdomain"
        elif ok_count > failure_count:
            confidence = ok_count / (ok_count + failure_count + 1)
            blocking_type = BlockingType.BLOCKED
            blocking_detail = f"dns.{dns_o.failure}"
        else:
            confidence = (failure_count + 1) / (ok_count + failure_count + 1)
            blocking_type = BlockingType.DOWN
            blocking_detail = f"dns.{dns_o.failure}"

        return BlockingEvent(
            blocking_type=blocking_type,
            blocking_subject=blocking_subject,
            blocking_detail=blocking_detail,
            blocking_meta={"ip": dns_o.answer},
            confidence=0.9,
        )

    elif dns_o.is_tls_consistent == False:
        return BlockingEvent(
            blocking_type=BlockingType.BLOCKED,
            blocking_subject=blocking_subject,
            blocking_detail="dns.inconsistent.tls_mismatch",
            blocking_meta={"ip": dns_o.answer, "why": "tls_inconsistent"},
            confidence=0.9,
        )

    elif dns_o.is_tls_consistent == None:
        # If we are in this case, it means we weren't able to determine the
        # consistency of the DNS query using TLS. This is the case either
        # because the tested site is not in HTTPS and therefore we didn't
        # generate a TLS measurement for it or because the target IP isn't
        # listening on HTTPS (which is quite fishy).
        # In either case we should flag these with being somewhat likely to be
        # blocked.
        ip_based_consistency, consistency_confidence = is_dns_consistent(
            dns_o, dns_ctrl, netinfodb
        )
        if ip_based_consistency is False and consistency_confidence > 0:
            confidence = consistency_confidence
            blocking_detail = "dns.inconsistent.generic"
            # If the answer ASN is the same as the probe_asn, it's more likely
            # to be a blockpage
            if dns_o.answer_asn == dns_o.probe_asn:
                blocking_detail = "dns.inconsistent.asn_match"
                confidence = 0.8
            # same for the answer_cc
            elif dns_o.answer_as_cc == dns_o.probe_cc:
                blocking_detail = "dns.inconsistent.cc_match"
                confidence = 0.7

            return BlockingEvent(
                blocking_type=BlockingType.BLOCKED,
                blocking_subject=blocking_subject,
                blocking_detail=blocking_detail,
                blocking_meta={"ip": dns_o.answer, "why": "tls_inconsistent"},
                confidence=0.9,
            )

    # No blocking detected
    return BlockingEvent(
        blocking_type=BlockingType.OK,
        blocking_subject=blocking_subject,
        blocking_detail="ok",
        blocking_meta={"ip": dns_o.answer},
        confidence=0.8,
    )


def make_website_tls_blocking_event(
    tls_o: TLSObservation, prev_be: List[BlockingEvent]
) -> Optional[BlockingEvent]:
    blocking_subject = tls_o.domain_name

    if tls_o.is_certificate_valid == False:
        # We only consider it to be a TLS level verdict in cases when there is a
        # certificate mismatch, but there was no DNS inconsistency.
        # If the DNS was inconsistent, we will just count the DNS verdict
        if (
            len(
                list(
                    filter(
                        lambda v: v.blocking_detail.startswith("dns.")
                        and v.blocking_meta.get("ip") == tls_o.ip,
                        prev_be,
                    )
                )
            )
            > 0
        ):
            return

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

    elif tls_o.failure:
        if (
            len(
                list(
                    filter(
                        lambda v: v.blocking_detail.startswith("tcp.")
                        and v.blocking_subject == f"{tls_o.ip}:443",
                        prev_be,
                    )
                )
            )
            > 0
        ):
            return

        # We only consider it to be a TLS level verdict if we haven't seen any
        # blocks in TCP
        blocking_detail = f"tls.{tls_o.failure}"
        confidence = 0.5

        if tls_o.tls_handshake_read_count == 0 and tls_o.tls_handshake_write_count == 1:
            # This means we just wrote the TLS ClientHello, let's give it a bit
            # more confidence in it being a block
            confidence = 0.7

        if tls_o.failure in ("connection_closed", "connection_reset"):
            confidence += 0.2

        return BlockingEvent(
            blocking_type=BlockingType.BLOCKED,
            blocking_subject=blocking_subject,
            blocking_detail=blocking_detail,
            blocking_meta={},
            confidence=confidence,
        )

    return BlockingEvent(
        blocking_type=BlockingType.OK,
        blocking_subject=blocking_subject,
        blocking_detail="ok",
        blocking_meta={},
        confidence=1.0,
    )


def make_website_http_blocking_event(
    http_o: HTTPObservation,
    http_ctrl: HTTPControl,
    prev_be: List[BlockingEvent],
    fingerprintdb: FingerprintDB,
) -> Optional[BlockingEvent]:
    blocking_subject = http_o.request_url

    ok_be = BlockingEvent(
        blocking_type=BlockingType.OK,
        blocking_subject=blocking_subject,
        blocking_detail="ok",
        blocking_meta={},
        confidence=0.8,
    )

    detail_prefix = "http."
    if http_o.request_is_encrypted:
        detail_prefix = "https."

    if http_o.failure:
        # For HTTP requests we ignore cases in which we detected the blocking
        # already to be happening via DNS or TCP.
        if not http_o.request_is_encrypted and (
            len(
                list(
                    filter(
                        lambda v: v.blocking_detail.startswith("dns.")
                        or (
                            v.blocking_detail.startswith("tcp.")
                            and v.blocking_subject.endswith(":80")
                        ),
                        prev_be,
                    )
                )
            )
            > 0
        ):
            return

        # Similarly for HTTPS we ignore cases when the block is done via TLS or TCP
        if http_o.request_is_encrypted and (
            len(
                list(
                    filter(
                        lambda v: v.blocking_detail.startswith("dns.")
                        or (
                            v.blocking_detail.startswith("tcp.")
                            and v.blocking_subject.endswith(":443")
                        )
                        or v.blocking_detail.startswith("tls."),
                        prev_be,
                    )
                )
            )
            > 0
        ):
            return

        failure_cc_asn = list(http_ctrl.failure_cc_asn)
        try:
            failure_cc_asn.remove((http_o.probe_cc, http_o.probe_asn))
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
        blocking_detail = f"{detail_prefix}{http_o.failure}"

        return BlockingEvent(
            blocking_type=blocking_type,
            blocking_subject=blocking_subject,
            blocking_detail=blocking_detail,
            blocking_meta={},
            confidence=confidence,
        )

    elif http_o.response_matches_blockpage:
        blocking_type = BlockingType.BLOCKED
        blocking_meta = {}
        confidence = 0.7
        if http_o.request_is_encrypted:
            # Likely some form of server-side blocking
            blocking_type = BlockingType.SERVER_SIDE_BLOCK
            confidence = 0.5
        elif http_o.fingerprint_country_consistent:
            confidence = 1

        for fp_name in http_o.response_fingerprints:
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

    elif not http_o.request_is_encrypted:
        if http_o.response_matches_false_positive:
            return ok_be
        if http_o.response_body_title == http_ctrl.response_body_title:
            return ok_be
        if http_o.response_body_meta_title == http_ctrl.response_body_meta_title:
            return ok_be
        if http_o.response_body_sha1 == http_ctrl.response_body_sha1:
            return ok_be

        if (
            http_o.response_body_length
            and http_ctrl.response_body_length
            and (
                (http_o.response_body_length + 1.0)
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


@dataclass
class WebsiteExperimentResult(ExperimentResult):
    domain_name: str
    website_name: str


def make_website_experiment_result(
    nt_o: NettestObservation,
    dns_o_list: List[DNSObservation],
    dns_ctrl: DNSControl,
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
    tcp_o_list: List[TCPObservation],
    tcp_ctrl_map: Dict[str, TCPControl],
    tls_o_list: List[TLSObservation],
    http_o_list: List[HTTPObservation],
    http_ctrl_map: Dict[str, HTTPControl],
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

    domain_name = dns_o_list[0].domain_name
    dns_blocking_events = []
    for dns_o in dns_o_list:
        observation_ids.append(dns_o.observation_id)

        assert (
            domain_name == dns_o.domain_name
        ), f"Inconsistent domain_name in dns_o {dns_o.domain_name}"
        dns_be = make_website_dns_blocking_event(
            dns_o, dns_ctrl, fingerprintdb, netinfodb
        )
        if dns_be:
            dns_blocking_events.append(dns_be)
        else:
            # If we didn't get a DNS blocking event from an observation, it means that
            # observation was a sign of everything being OK, hence we should
            # ignore all the previous DNS verdicts as likely false positives and
            # just consider no DNS level censorship to be happening.
            # TODO: probably we want to just reduce the confidence of the DNS
            # level blocks in this case by some factor.
            dns_blocking_events = []
            break

    for dns_be in dns_blocking_events:
        blocking_events.append(dns_be)

    if tcp_o_list:
        for tcp_o in tcp_o_list:
            observation_ids.append(tcp_o.observation_id)
            assert (
                domain_name == tcp_o.domain_name
            ), f"Inconsistent domain_name in tcp_o {tcp_o.domain_name}"
            tcp_ctrl = tcp_ctrl_map.get(f"{tcp_o.ip}:{tcp_o.port}")
            tcp_be = (
                make_website_tcp_blocking_event(tcp_o, tcp_ctrl) if tcp_ctrl else None
            )
            if tcp_be:
                blocking_events.append(tcp_be)

    if tls_o_list:
        for tls_o in tls_o_list:
            observation_ids.append(tls_o.observation_id)
            assert (
                domain_name == tls_o.domain_name
            ), f"Inconsistent domain_name in tls_o {tls_o.domain_name}"
            tls_be = make_website_tls_blocking_event(tls_o, blocking_events)
            if tls_be:
                blocking_events.append(tls_be)

    if http_o_list:
        for http_o in http_o_list:
            observation_ids.append(http_o.observation_id)
            assert (
                domain_name == http_o.domain_name
            ), f"Inconsistent domain_name in http_o {http_o.domain_name}"
            http_ctrl = http_ctrl_map.get(http_o.request_url)
            http_be = (
                make_website_http_blocking_event(
                    http_o, http_ctrl, blocking_events, fingerprintdb
                )
                if http_ctrl
                else None
            )
            if http_be:
                blocking_events.append(http_be)

    # TODO: Should we be including this also BlockingType.DOWN,SERVER_SIDE_BLOCK or not?
    ok_confidence = 1 - max(
        filter(
            lambda be: be.blocking_type
            not in (BlockingType.OK, BlockingType.DOWN, BlockingType.SERVER_SIDE_BLOCK),
            blocking_events,
        )
    )

    confirmed = False
    anomaly = False
    if ok_confidence == 0:
        confirmed = True
    if ok_confidence > 0.6:
        anomaly = True

    return WebsiteExperimentResult(
        blocking_events=blocking_events,
        observation_ids=observation_ids,
        anomaly=anomaly,
        confirmed=confirmed,
        ok_confidence=ok_confidence,
        **make_base_result_meta(nt_o),
    )
