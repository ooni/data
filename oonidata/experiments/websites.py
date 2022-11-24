from collections import defaultdict
from dataclasses import dataclass
import ipaddress
from typing import Optional, List, Tuple, Dict
from oonidata.experiments.control import (
    WebGroundTruth,
    WebGroundTruthDB,
    BodyDB,
)
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
    WebObservation,
)

import logging

log = logging.getLogger("oonidata.processing")


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


def make_tcp_blocking_event(
    web_o: WebObservation, web_ground_truth_db: WebGroundTruthDB
) -> Optional[BlockingEvent]:
    assert web_o.ip is not None and web_o.port is not None

    blocking_subject = encode_address(web_o.ip, web_o.port)

    # Nothing to see here, go on with your life
    if web_o.tcp_success == True:
        return BlockingEvent(
            blocking_type=BlockingType.OK,
            blocking_subject=blocking_subject,
            blocking_detail="tcp.ok",
            blocking_meta={},
            confidence=1.0,
        )

    assert (
        web_o.tcp_failure is not None
    ), "inconsistency between tcp_success and tcp_failure"

    ground_truths = web_ground_truth_db.lookup(
        probe_cc=web_o.probe_cc, probe_asn=web_o.probe_asn, ip=web_o.ip, port=web_o.port
    )
    unreachable_cc_asn = set()
    reachable_cc_asn = set()
    for gt in ground_truths:
        if gt.tcp_success == True:
            reachable_cc_asn.add((gt.vp_cc, gt.vp_asn))
        elif gt.tcp_success == False:
            unreachable_cc_asn.add((gt.vp_cc, gt.vp_asn))

    reachable_count = len(reachable_cc_asn)
    unreachable_count = len(unreachable_cc_asn)
    blocking_meta = {
        "unreachable_count": str(unreachable_count),
        "reachable_count": str(reachable_count),
    }
    if reachable_count > unreachable_count:
        # We are adding back 1 because we removed it above and it avoid a divide by zero
        confidence = reachable_count / (reachable_count + unreachable_count + 1) * 0.9
        blocking_type = BlockingType.BLOCKED
        blocking_meta["why"] = "it's reachable from most places"
    else:
        confidence = (
            (unreachable_count + 1) / (reachable_count + unreachable_count + 1)
        ) * 0.9
        blocking_meta["why"] = "it's not reachable from most places"
        blocking_type = BlockingType.DOWN

    # TODO: should we bump up the confidence in the case of connection_reset?
    blocking_detail = f"tcp.{web_o.tcp_failure}"
    return BlockingEvent(
        blocking_type=blocking_type,
        blocking_subject=blocking_subject,
        blocking_detail=blocking_detail,
        blocking_meta=blocking_meta,
        confidence=confidence,
    )


def get_blocking_for_dns_failure(
    dns_failure: str, ground_truths: List[WebGroundTruth]
) -> Tuple[BlockingType, str, float]:
    nxdomain_cc_asn = set()
    failure_cc_asn = set()
    ok_cc_asn = set()
    for gt in ground_truths:
        if gt.dns_success == False:
            failure_cc_asn.add((gt.vp_cc, gt.vp_asn))
        elif gt.dns_success == True:
            ok_cc_asn.add((gt.vp_cc, gt.vp_asn))
        if gt.dns_failure == "dns_nxdomain_error":
            nxdomain_cc_asn.add((gt.vp_cc, gt.vp_asn))

    ok_count = len(ok_cc_asn)
    failure_count = len(failure_cc_asn)
    nxdomain_count = len(nxdomain_cc_asn)

    if dns_failure == "dns_nxdomain_error":
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
        blocking_detail = f"dns.{dns_failure}"
    else:
        confidence = (failure_count + 1) / (ok_count + failure_count + 1)
        blocking_type = BlockingType.DOWN
        blocking_detail = f"dns.{dns_failure}"

    return blocking_type, blocking_detail, confidence


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


def make_dns_blocking_event(
    web_o: WebObservation,
    web_ground_truth_db: WebGroundTruthDB,
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
) -> Optional[BlockingEvent]:

    blocking_subject = web_o.hostname or ""

    fp = None
    if web_o.dns_answer:
        fp = fingerprintdb.match_dns(web_o.dns_answer)

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

    assert web_o.hostname, "malformed DNS observation"
    ground_truths = web_ground_truth_db.lookup(
        probe_cc=web_o.probe_cc, probe_asn=web_o.probe_asn, hostname=web_o.hostname
    )
    if web_o.dns_failure:
        blocking_type, blocking_detail, confidence = get_blocking_for_dns_failure(
            dns_failure=web_o.dns_failure, ground_truths=ground_truths
        )
        return BlockingEvent(
            blocking_type=blocking_type,
            blocking_subject=blocking_subject,
            blocking_detail=blocking_detail,
            blocking_meta={"ip": web_o.dns_answer or ""},
            confidence=0.9,
        )

    trusted_answers = set(
        list(
            map(
                lambda gt: gt.ip,
                filter(
                    lambda gt: (gt.dns_success == True and gt.tls_is_certificate_valid)
                    or gt.is_trusted_vp,
                    ground_truths,
                ),
            )
        )
    )
    if web_o.ip_is_bogon and len(trusted_answers) > 0:
        return BlockingEvent(
            blocking_type=BlockingType.BLOCKED,
            blocking_subject=blocking_subject,
            blocking_detail="dns.inconsistent.bogon",
            blocking_meta={"ip": web_o.dns_answer or ""},
            confidence=0.9,
        )

    if web_o.tls_is_certificate_valid == False:
        return BlockingEvent(
            blocking_type=BlockingType.BLOCKED,
            blocking_subject=blocking_subject,
            blocking_detail="dns.inconsistent.tls_mismatch",
            blocking_meta={"ip": web_o.dns_answer or "", "why": "tls_inconsistent"},
            confidence=0.9,
        )

    if web_o.tls_is_certificate_valid == True or web_o.dns_answer in trusted_answers:
        # No blocking detected
        return BlockingEvent(
            blocking_type=BlockingType.OK,
            blocking_subject=blocking_subject,
            blocking_detail="dns.ok",
            blocking_meta={
                "ip": web_o.dns_answer or "",
                "why": "resolved IP in trusted answers",
            },
            confidence=1.0,
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
    for ip in trusted_answers:
        assert ip, "did not find IP in ground truth"
        ip_info = netinfodb.lookup_ip(web_o.measurement_start_time, ip)
        if ip_info:
            ground_truth_asns.add(ip_info.as_info.asn)
            ground_truth_as_org_names.add(ip_info.as_info.as_org_name.lower())

    if web_o.dns_answer_asn in ground_truth_asns:
        return BlockingEvent(
            blocking_type=BlockingType.OK,
            blocking_subject=blocking_subject,
            blocking_detail="dns.ok",
            blocking_meta={
                "ip": web_o.dns_answer or "",
                "why": "answer in matches AS of trusted answers",
            },
            confidence=0.9,
        )

    if (
        web_o.dns_answer_as_org_name
        and web_o.dns_answer_as_org_name.lower() in ground_truth_as_org_names
    ):
        return BlockingEvent(
            blocking_type=BlockingType.OK,
            blocking_subject=blocking_subject,
            blocking_detail="dns.ok",
            blocking_meta={
                "ip": web_o.dns_answer or "",
                "why": "answer in TLS ground truth as org name",
            },
            confidence=0.9,
        )

    # Here we count how many vantage vantage points, as in distinct probe_cc,
    # probe_asn pairs, had this DNS answer
    other_ips = defaultdict(set)
    other_asns = defaultdict(set)
    for gt in ground_truths:
        if gt.dns_success != True:
            continue
        other_ips[gt.ip].add((gt.vp_cc, gt.vp_asn))
        assert gt.ip, "did not find IP in ground truth"
        ip_info = netinfodb.lookup_ip(web_o.measurement_start_time, gt.ip)
        if ip_info:
            other_asns[ip_info.as_info.asn].add((gt.vp_cc, gt.vp_asn))

    if web_o.dns_answer in other_ips:
        return BlockingEvent(
            blocking_type=BlockingType.OK,
            blocking_subject=blocking_subject,
            blocking_detail="dns.ok",
            blocking_meta={
                "ip": web_o.dns_answer or "",
                "why": "answer in resolver IPs in ground truth",
            },
            confidence=confidence_estimate(
                len(other_ips[web_o.dns_answer]), clamping=0.9, factor=0.8
            ),
        )

    if web_o.dns_answer in other_asns:
        # We clamp this to some lower values and scale it by a smaller factor,
        # since ASN consistency is less strong than direct IP match.
        return BlockingEvent(
            blocking_type=BlockingType.OK,
            blocking_subject=blocking_subject,
            blocking_detail="dns.ok",
            blocking_meta={
                "ip": web_o.dns_answer or "",
                "why": "answer in resolver IPs in ground truth",
            },
            confidence=confidence_estimate(
                len(other_asns[web_o.dns_answer]), clamping=0.8, factor=0.7
            ),
        )

    blocking_meta = {
        "ip": web_o.dns_answer or "",
        "why": "unable to determine consistency through ground truth",
    }
    confidence = 0.6
    blocking_detail = "dns.inconsistent"

    # It's more common to answer to DNS queries for blocking with IPs managed by
    # the ISP (ex. to serve their blockpage).
    # So we give this a bit higher confidence
    if web_o.dns_answer_asn == web_o.probe_asn:
        confidence = 0.8
        blocking_meta["why"] = "answer matches probe_asn"
    # It's common to do this also in the country, for example when the blockpage
    # is centrally managed (ex. case in IT, ID)
    elif web_o.ip_as_cc == web_o.probe_cc:
        blocking_detail = "dns.inconsistent"
        blocking_meta["why"] = "answer matches probe_cc"
        confidence = 0.7

    # We haven't managed to figured out if the DNS resolution was a good one, so
    # we are going to assume it's bad.
    return BlockingEvent(
        blocking_type=BlockingType.BLOCKED,
        blocking_subject=blocking_subject,
        blocking_detail=blocking_detail,
        blocking_meta=blocking_meta,
        confidence=confidence,
    )


def make_tls_blocking_event(
    web_o: WebObservation, web_ground_truth_db: WebGroundTruthDB
) -> Optional[BlockingEvent]:
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


def make_http_blocking_event(
    web_o: WebObservation,
    web_ground_truth_db: WebGroundTruthDB,
    body_db: BodyDB,
    fingerprintdb: FingerprintDB,
) -> Optional[BlockingEvent]:
    assert web_o.http_request_url

    blocking_subject = web_o.http_request_url

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

    ground_truths = web_ground_truth_db.lookup(
        probe_cc=web_o.probe_cc,
        probe_asn=web_o.probe_asn,
        http_request_url=web_o.http_request_url,
    )
    if web_o.http_failure:
        blocking_meta = {}

        failure_cc_asn = set()
        ok_cc_asn = set()
        for gt in ground_truths:
            if gt.http_success == False:
                failure_cc_asn.add((gt.vp_cc, gt.vp_asn))
            elif gt.http_success == True:
                ok_cc_asn.add((gt.vp_cc, gt.vp_asn))

        failure_count = len(failure_cc_asn)
        ok_count = len(ok_cc_asn)
        if ok_count > failure_count:
            # We are adding back 1 because we removed it above and it avoid a divide by zero
            confidence = ok_count / (ok_count + failure_count + 1)
            blocking_type = BlockingType.BLOCKED
            blocking_meta["why"] = "it's mostly accessible"
        else:
            confidence = (failure_count + 1) / (ok_count + failure_count + 1)
            blocking_type = BlockingType.DOWN
            blocking_meta["why"] = "the site is down"

        blocking_detail = f"{detail_prefix}{web_o.http_failure}"

        return BlockingEvent(
            blocking_type=blocking_type,
            blocking_subject=blocking_subject,
            blocking_detail=blocking_detail,
            blocking_meta=blocking_meta,
            confidence=confidence,
        )

    # TODO: do we care to do something about empty bodies?
    # They are commonly a source of blockpages
    if web_o.http_response_body_sha1:
        matched_fp = body_db.lookup(web_o.http_response_body_sha1)
        if len(matched_fp) > 0:
            blocking_type = BlockingType.BLOCKED
            blocking_meta = {}
            confidence = 0.8
            if request_is_encrypted:
                # Likely some form of server-side blocking
                blocking_type = BlockingType.SERVER_SIDE_BLOCK
                confidence = 0.5

            for fp_name in matched_fp:
                fp = fingerprintdb.get_fp(fp_name)
                if fp.scope:
                    blocking_type = fp_scope_to_outcome(fp.scope)
                    blocking_meta = {
                        "fp_name": fp.name,
                        "why": f"matched fingerprint {fp.name}",
                    }
                    if (
                        fp.expected_countries
                        and web_o.probe_cc in fp.expected_countries
                    ):
                        confidence = 1.0
                    break

            blocking_detail = f"{detail_prefix}diff.blockpage"
            return BlockingEvent(
                blocking_type=blocking_type,
                blocking_subject=blocking_subject,
                blocking_detail=blocking_detail,
                blocking_meta=blocking_meta,
                confidence=confidence,
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
    web_ground_truth_db: WebGroundTruthDB,
    body_db: BodyDB,
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
) -> WebsiteExperimentResult:
    blocking_events = []
    observation_ids = []

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
        request_is_encrypted = (
            web_o.http_request_url and web_o.http_request_url.startswith("https://")
        )
        observation_ids.append(web_o.observation_id)

        dns_be = None
        if web_o.dns_query_type:
            # We have data related to DNS and it's a failure
            dns_be = make_dns_blocking_event(
                web_o=web_o,
                web_ground_truth_db=web_ground_truth_db,
                fingerprintdb=fingerprintdb,
                netinfodb=netinfodb,
            )
            if is_blocked(dns_be):
                is_dns_blocked = True
            blocking_events.append(dns_be)

        # TODO: this is now missing
        # If we didn't get a DNS blocking event from an observation, it means that
        # observation was a sign of everything being OK, hence we should
        # ignore all the previous DNS verdicts as likely false positives and
        # just consider no DNS level censorship to be happening.
        # TODO: probably we want to just reduce the confidence of the DNS
        # level blocks in this case by some factor.

        tcp_be = None
        if not is_blocked(dns_be) and web_o.tcp_success is not None:
            tcp_be = make_tcp_blocking_event(web_o, web_ground_truth_db)
            if is_blocked(tcp_be):
                is_tcp_blocked = True
            blocking_events.append(tcp_be)

        tls_be = None
        # We ignore things that are already blocked by DNS or TCP
        if (
            not is_blocked(dns_be)
            and not is_blocked(tcp_be)
            and (web_o.tls_failure or web_o.tls_cipher_suite is not None)
        ):
            tls_be = make_tls_blocking_event(
                web_o=web_o, web_ground_truth_db=web_ground_truth_db
            )
            blocking_events.append(tls_be)
            if is_blocked(tls_be):
                is_tls_blocked = True

        if web_o.http_request_url and not web_o.ip:
            http_obs.append(web_o)
            continue

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
            http_be = make_http_blocking_event(
                web_o=web_o,
                web_ground_truth_db=web_ground_truth_db,
                body_db=body_db,
                fingerprintdb=fingerprintdb,
            )
            blocking_events.append(http_be)

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
            http_be = make_http_blocking_event(
                web_o=web_o,
                web_ground_truth_db=web_ground_truth_db,
                body_db=body_db,
                fingerprintdb=fingerprintdb,
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
