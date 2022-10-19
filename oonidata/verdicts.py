import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from re import L
from typing import Optional, List, Tuple, Generator, Any, Mapping
from datetime import datetime, date, timedelta

from urllib.parse import urlparse

from oonidata.fingerprintdb import FingerprintDB
from oonidata.netinfo import NetinfoDB

from oonidata.datautils import one_day_dict

from oonidata.observations import (
    DNSObservation,
    HTTPObservation,
    Observation,
    TCPObservation,
    TLSObservation,
)
from oonidata.dataformat import WebConnectivityControl, WebConnectivity
from oonidata.db.connections import ClickhouseConnection

import logging

log = logging.getLogger("oonidata.processing")


class Outcome(Enum):
    # k: everything is OK
    OK = "k"
    # b: blocking is happening with an unknown scope
    BLOCKED = "b"
    # n: national level blocking
    NATIONAL_BLOCK = "n"
    # i: isp level blocking
    ISP_BLOCK = "i"
    # l: local blocking (school, office, home network)
    LOCAL_BLOCK = "l"
    # s: server-side blocking
    SERVER_SIDE_BLOCK = "s"
    # d: the subject is down
    DOWN = "d"
    # t: this is a signal indicating some form of network throttling
    THROTTLING = "t"


def fp_scope_to_outcome(scope: Optional[str]) -> Outcome:
    # "nat" national level blockpage
    # "isp" ISP level blockpage
    # "prod" text pattern related to a middlebox product
    # "inst" text pattern related to a voluntary instition blockpage (school, office)
    # "vbw" vague blocking word
    # "fp" fingerprint for false positives
    if scope == "nat":
        return Outcome.NATIONAL_BLOCK
    elif scope == "isp":
        return Outcome.ISP_BLOCK
    elif scope == "inst":
        return Outcome.LOCAL_BLOCK
    elif scope == "fp":
        return Outcome.SERVER_SIDE_BLOCK
    return Outcome.BLOCKED


@dataclass
class Verdict:
    measurement_uid: str
    observation_id: str
    report_id: str
    input: str
    timestamp: datetime

    probe_asn: int
    probe_cc: str

    probe_as_org_name: str
    probe_as_cc: str

    network_type: str

    resolver_ip: Optional[str]
    resolver_asn: Optional[int]
    resolver_as_org_name: Optional[str]
    resolver_as_cc: Optional[str]
    resolver_cc: Optional[str]

    confidence: float

    subject: str
    subject_category: str
    subject_detail: str

    outcome: Outcome

    # This will include a more detailed breakdown of the outcome, for example it
    # can be "dns.nxdomain"
    outcome_detail: str


def make_verdict_from_obs(
    obs: Observation,
    confidence: float,
    subject: str,
    subject_category: str,
    subject_detail: str,
    outcome: Outcome,
    outcome_detail: str,
) -> Verdict:
    return Verdict(
        measurement_uid=obs.measurement_uid,
        observation_id=obs.observation_id,
        report_id=obs.report_id,
        input=obs.input,
        timestamp=obs.timestamp,
        probe_asn=obs.probe_asn,
        probe_cc=obs.probe_cc,
        probe_as_org_name=obs.probe_as_org_name,
        probe_as_cc=obs.probe_as_cc,
        network_type=obs.network_type,
        resolver_ip=obs.resolver_ip,
        resolver_asn=obs.resolver_asn,
        resolver_as_org_name=obs.resolver_as_org_name,
        resolver_as_cc=obs.resolver_as_cc,
        resolver_cc=obs.resolver_cc,
        confidence=confidence,
        subject=subject,
        subject_category=subject_category,
        subject_detail=subject_detail,
        outcome=outcome,
        outcome_detail=outcome_detail,
    )


@dataclass
class TCPBaseline:
    address: str
    reachable_cc_asn: List[Tuple[str, int]] = field(default_factory=list)
    unreachable_cc_asn: List[Tuple[str, int]] = field(default_factory=list)


def make_tcp_baseline_map(
    day: date, domain_name: str, db: ClickhouseConnection
) -> dict[str, TCPBaseline]:
    tcp_baseline_map = {}
    q_params = one_day_dict(day)
    q_params["domain_name"] = domain_name

    q = """SELECT probe_cc, probe_asn, ip, port, failure FROM obs_tcp
    WHERE domain_name = %(domain_name)s 
    AND timestamp >= %(start_day)s
    AND timestamp <= %(end_day)s
    GROUP BY probe_cc, probe_asn, ip, port, failure;
    """
    res = db.execute(q, q_params)
    if isinstance(res, list) and len(res) > 0:
        for probe_cc, probe_asn, ip, port, failure in res:
            address = f"{ip}:{port}"
            tcp_baseline_map[address] = tcp_baseline_map.get(
                address, TCPBaseline(address)
            )
            if not failure:
                tcp_baseline_map[address].reachable_cc_asn.append((probe_cc, probe_asn))
            else:
                tcp_baseline_map[address].unreachable_cc_asn.append(
                    (probe_cc, probe_asn)
                )
    return tcp_baseline_map


@dataclass
class HTTPBaseline:
    url: str
    failure_cc_asn: List[Tuple[str, int]] = field(default_factory=list)
    ok_cc_asn: List[Tuple[str, int]] = field(default_factory=list)

    response_body_length: int = 0
    response_body_sha1: str = ""
    response_body_title: str = ""
    response_body_meta_title: str = ""

    response_status_code: int = 0


def maybe_get_first(l: list, default_value: Any = None) -> Optional[Any]:
    try:
        return l[0]
    except IndexError:
        return default_value


def make_http_baseline_map(
    day: date, domain_name: str, db: ClickhouseConnection
) -> dict[str, HTTPBaseline]:
    http_baseline_map = {}

    q_params = one_day_dict(day)
    q_params["domain_name"] = domain_name

    q = """SELECT probe_cc, probe_asn, request_url, failure FROM obs_http
    WHERE domain_name = %(domain_name)s 
    AND timestamp >= %(start_day)s
    AND timestamp <= %(end_day)s
    GROUP BY probe_cc, probe_asn, request_url, failure;
    """
    res = db.execute(q, q_params)
    if isinstance(res, list) and len(res) > 0:
        for probe_cc, probe_asn, request_url, failure in res:
            http_baseline_map[request_url] = http_baseline_map.get(
                request_url, HTTPBaseline(request_url)
            )
            if not failure:
                http_baseline_map[request_url].ok_cc_asn.append((probe_cc, probe_asn))
            else:
                http_baseline_map[request_url].failure_cc_asn.append(
                    (probe_cc, probe_asn)
                )

    q = """SELECT request_url,
    topK(1)(response_body_sha1),
    topK(1)(response_body_length),
    topK(1)(response_body_title),
    topK(1)(response_body_meta_title),
    topK(1)(response_status_code)
    FROM obs_http
    WHERE failure IS NULL
    AND domain_name = %(domain_name)s 
    AND timestamp >= %(start_day)s
    AND timestamp <= %(end_day)s
    GROUP BY request_url;
    """
    res = db.execute(q, q_params)
    if isinstance(res, list) and len(res) > 0:
        for (
            request_url,
            response_body_sha1,
            response_body_length,
            response_body_title,
            response_body_meta_title,
            response_status_code,
        ) in res:
            http_baseline_map[request_url] = http_baseline_map.get(
                request_url, HTTPBaseline(request_url)
            )
            http_baseline_map[request_url].response_body_sha1 = maybe_get_first(
                response_body_sha1, ""
            )
            http_baseline_map[request_url].response_body_length = maybe_get_first(
                response_body_length, ""
            )
            http_baseline_map[request_url].response_body_title = maybe_get_first(
                response_body_title, ""
            )
            http_baseline_map[request_url].response_body_meta_title = maybe_get_first(
                response_body_meta_title, ""
            )
            http_baseline_map[request_url].response_status_code = maybe_get_first(
                response_status_code, ""
            )

    return http_baseline_map


@dataclass
class DNSBaseline:
    domain: str
    nxdomain_cc_asn: List[Tuple[str, int]] = field(default_factory=list)
    failure_cc_asn: List[Tuple[str, int]] = field(default_factory=list)
    ok_cc_asn: List[Tuple[str, int]] = field(default_factory=list)
    tls_consistent_answers: List[str] = field(default_factory=list)
    answers_map: dict[str, List[Tuple[str, str]]] = field(default_factory=dict)


def make_dns_baseline(
    day: date, domain_name: str, db: ClickhouseConnection
) -> DNSBaseline:
    dns_baseline = DNSBaseline(domain_name)

    q_params = one_day_dict(day)
    q_params["domain_name"] = domain_name

    q = """SELECT DISTINCT(ip) FROM obs_tls
    WHERE is_certificate_valid = 1 
    AND domain_name = %(domain_name)s 
    AND timestamp >= %(start_day)s
    AND timestamp <= %(end_day)s;
    """
    res = db.execute(q, q_params)
    if isinstance(res, list) and len(res) > 0:
        dns_baseline.tls_consistent_answers = [row[0] for row in res]

    q = """SELECT probe_cc, probe_asn, failure, answer FROM obs_dns
    WHERE domain_name = %(domain_name)s 
    AND timestamp >= %(start_day)s
    AND timestamp <= %(end_day)s
    GROUP BY probe_cc, probe_asn, failure, answer;
    """
    res = db.execute(q, q_params)
    if isinstance(res, list) and len(res) > 0:
        for probe_cc, probe_asn, failure, ip in res:
            if not failure:
                dns_baseline.ok_cc_asn.append((probe_cc, probe_asn))
                dns_baseline.answers_map[probe_cc] = dns_baseline.answers_map.get(
                    probe_cc, []
                )
                if ip:
                    dns_baseline.answers_map[probe_cc].append((probe_asn, ip))
                else:
                    log.error(
                        f"No IP present for {domain_name} {probe_cc} ({probe_asn}) in baseline"
                    )
            else:
                dns_baseline.failure_cc_asn.append((probe_cc, probe_asn))
                if failure == "dns_nxdomain_error":
                    dns_baseline.nxdomain_cc_asn.append((probe_cc, probe_asn))

    return dns_baseline


def is_dns_consistent(
    dns_o: DNSObservation, dns_b: DNSBaseline, netinfodb: NetinfoDB
) -> Tuple[bool, float]:
    if not dns_o.answer:
        return False, 0

    try:
        ipaddress.ip_address(dns_o.answer)
    except ValueError:
        # Not an IP, er can't do much to validate it
        return False, 0

    if dns_o.answer in dns_b.tls_consistent_answers:
        return True, 1.0

    baseline_asns = set()
    baseline_as_org_names = set()

    for ip in dns_b.tls_consistent_answers:
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

    other_answers = dns_b.answers_map.copy()
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


def make_website_tcp_verdicts(
    tcp_o: TCPObservation, tcp_b: TCPBaseline
) -> Optional[Verdict]:
    outcome = Outcome.OK
    confidence = 1
    outcome_detail = ""

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
        if reachable_count > unreachable_count:
            # We are adding back 1 because we removed it above and it avoid a divide by zero
            confidence = reachable_count / (reachable_count + unreachable_count + 1)
            outcome = Outcome.BLOCKED
        elif unreachable_count > reachable_count:
            confidence = (unreachable_count + 1) / (
                reachable_count + unreachable_count + 1
            )
            outcome = Outcome.DOWN

        outcome_detail = f"tcp.{tcp_o.failure}"

    if outcome != Outcome.OK:
        return make_verdict_from_obs(
            tcp_o,
            confidence=confidence,
            subject=tcp_o.domain_name,
            subject_detail=f"{tcp_o.ip}:{tcp_o.port}",
            subject_category="website",
            outcome=outcome,
            outcome_detail=outcome_detail,
        )


def make_website_dns_verdict(
    dns_o: DNSObservation,
    dns_b: DNSBaseline,
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
) -> Optional[Verdict]:
    if dns_o.fingerprint_id:
        fp = fingerprintdb.get_fp(dns_o.fingerprint_id)
        outcome = fp_scope_to_outcome(fp.scope)
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

        outcome_detail = "dns.blockpage"
        return make_verdict_from_obs(
            dns_o,
            confidence=confidence,
            subject=dns_o.domain_name,
            subject_detail=f"{dns_o.answer}",
            subject_category="website",
            outcome=Outcome.BLOCKED,
            outcome_detail=outcome_detail,
        )

    elif dns_o.answer_is_bogon and len(dns_b.tls_consistent_answers) > 0:
        outcome_detail = "dns.bogon"
        return make_verdict_from_obs(
            dns_o,
            confidence=0.9,
            subject=dns_o.domain_name,
            subject_detail=f"{dns_o.answer}",
            subject_category="website",
            outcome=Outcome.BLOCKED,
            outcome_detail="dns.bogon",
        )

    elif dns_o.failure:
        failure_cc_asn = list(dns_b.failure_cc_asn)
        try:
            failure_cc_asn.remove((dns_o.probe_cc, dns_o.probe_asn))
        except ValueError:
            log.info(
                "missing failure for the probe in the baseline. You are probably using a control derived baseline."
            )

        failure_count = len(failure_cc_asn)
        ok_count = len(dns_b.ok_cc_asn)

        if dns_o.failure == "dns_nxdomain_error":
            nxdomain_cc_asn = list(dns_b.nxdomain_cc_asn)
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
                outcome = Outcome.BLOCKED
                outcome_detail = "dns.nxdomain"
            else:
                confidence = (nxdomain_count + 1) / (ok_count + nxdomain_count + 1)
                outcome = Outcome.DOWN
                outcome_detail = "dns.nxdomain"
        elif ok_count > failure_count:
            confidence = ok_count / (ok_count + failure_count + 1)
            outcome = Outcome.BLOCKED
            outcome_detail = f"dns.{dns_o.failure}"
        else:
            confidence = (failure_count + 1) / (ok_count + failure_count + 1)
            outcome = Outcome.DOWN
            outcome_detail = f"dns.{dns_o.failure}"
        return make_verdict_from_obs(
            dns_o,
            confidence=confidence,
            subject=dns_o.domain_name,
            subject_detail=f"{dns_o.answer}",
            subject_category="website",
            outcome=outcome,
            outcome_detail=outcome_detail,
        )

    elif dns_o.is_tls_consistent == False:
        outcome_detail = "dns.inconsistent.tls_mismatch"
        return make_verdict_from_obs(
            dns_o,
            confidence=0.8,
            subject=dns_o.domain_name,
            subject_detail=f"{dns_o.answer}",
            subject_category="website",
            outcome=Outcome.BLOCKED,
            outcome_detail=outcome_detail,
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
            dns_o, dns_b, netinfodb
        )
        if ip_based_consistency is False and consistency_confidence > 0:
            confidence = consistency_confidence
            outcome_detail = "dns.inconsistent.generic"
            # If the answer ASN is the same as the probe_asn, it's more likely
            # to be a blockpage
            if dns_o.answer_asn == dns_o.probe_asn:
                outcome_detail = "dns.inconsistent.asn_match"
                confidence = 0.8
            # same for the answer_cc
            elif dns_o.answer_as_cc == dns_o.probe_cc:
                outcome_detail = "dns.inconsistent.cc_match"
                confidence = 0.7
            return make_verdict_from_obs(
                dns_o,
                confidence=confidence,
                subject=dns_o.domain_name,
                subject_detail=f"{dns_o.answer}",
                subject_category="website",
                outcome=Outcome.BLOCKED,
                outcome_detail=outcome_detail,
            )
    # No blocking detected
    return None


def make_website_tls_verdict(
    tls_o: TLSObservation, prev_verdicts: List[Verdict]
) -> Optional[Verdict]:
    if tls_o.is_certificate_valid == False:
        # We only consider it to be a TLS level verdict in cases when there is a
        # certificate mismatch, but there was no DNS inconsistency.
        # If the DNS was inconsistent, we will just count the DNS verdict
        if (
            len(
                list(
                    filter(
                        lambda v: v.outcome_detail.startswith("dns.")
                        and v.subject_detail == tls_o.ip,
                        prev_verdicts,
                    )
                )
            )
            > 0
        ):
            return

        # TODO: this is wrong. We need to consider the baseline to establish TLS
        # MITM, because the cert might be invalid also from other location (eg.
        # it expired) and not due to censorship.
        outcome_detail = "tls.mitm"
        return make_verdict_from_obs(
            tls_o,
            confidence=1,
            subject=tls_o.domain_name,
            subject_detail=f"{tls_o.ip}:{tls_o.port}",
            subject_category="website",
            outcome=Outcome.BLOCKED,
            outcome_detail=outcome_detail,
        )
    elif tls_o.failure:
        if (
            len(
                list(
                    filter(
                        lambda v: v.outcome_detail.startswith("tcp.")
                        and v.subject_detail == f"{tls_o.ip}:443",
                        prev_verdicts,
                    )
                )
            )
            > 0
        ):
            return

        # We only consider it to be a TLS level verdict if we haven't seen any
        # blocks in TCP
        outcome_detail = f"tls.{tls_o.failure}"
        confidence = 0.5

        if tls_o.tls_handshake_read_count == 0 and tls_o.tls_handshake_write_count == 1:
            # This means we just wrote the TLS ClientHello, let's give it a bit
            # more confidence in it being a block
            confidence = 0.7

        if tls_o.failure in ("connection_closed", "connection_reset"):
            confidence += 0.2

        return make_verdict_from_obs(
            tls_o,
            confidence=confidence,
            subject=tls_o.domain_name,
            subject_detail=f"{tls_o.ip}:{tls_o.port}",
            subject_category="website",
            outcome=Outcome.BLOCKED,
            outcome_detail=outcome_detail,
        )


def make_website_http_verdict(
    http_o: HTTPObservation,
    http_b: HTTPBaseline,
    prev_verdicts: List[Verdict],
    fingerprintdb: FingerprintDB,
) -> Optional[Verdict]:
    if http_o.failure:
        # For HTTP requests we ignore cases in which we detected the blocking
        # already to be happening via DNS or TCP.
        if not http_o.request_is_encrypted and (
            len(
                list(
                    filter(
                        lambda v: v.outcome_detail.startswith("dns.")
                        or (
                            v.outcome_detail.startswith("tcp.")
                            and v.subject_detail.endswith(":80")
                        ),
                        prev_verdicts,
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
                        lambda v: v.outcome_detail.startswith("dns.")
                        or (
                            v.outcome_detail.startswith("tcp.")
                            and v.subject_detail.endswith(":443")
                        )
                        or v.outcome_detail.startswith("tls."),
                        prev_verdicts,
                    )
                )
            )
            > 0
        ):
            return

        failure_cc_asn = list(http_b.failure_cc_asn)
        try:
            failure_cc_asn.remove((http_o.probe_cc, http_o.probe_asn))
        except ValueError:
            log.info(
                "missing failure in http baseline. Either something is wrong or you are using a control derived baseline"
            )

        failure_count = len(failure_cc_asn)
        ok_count = len(http_b.ok_cc_asn)
        if ok_count > failure_count:
            # We are adding back 1 because we removed it above and it avoid a divide by zero
            confidence = ok_count / (ok_count + failure_count + 1)
            outcome = Outcome.BLOCKED
        else:
            confidence = (failure_count + 1) / (ok_count + failure_count + 1)
            outcome = Outcome.DOWN

        outcome_detail = "http."
        if http_o.request_is_encrypted:
            outcome_detail = "https."
        outcome_detail += http_o.failure
        return make_verdict_from_obs(
            http_o,
            confidence=confidence,
            subject=http_o.domain_name,
            subject_detail="",
            subject_category="website",
            outcome=outcome,
            outcome_detail=outcome_detail,
        )
    elif http_o.response_matches_blockpage:
        outcome = Outcome.BLOCKED
        confidence = 0.7
        if http_o.request_is_encrypted:
            confidence = 0
        elif http_o.fingerprint_country_consistent:
            confidence = 1

        for fp_name in http_o.response_fingerprints:
            fp = fingerprintdb.get_fp(fp_name)
            if fp.scope:
                outcome = fp_scope_to_outcome(fp.scope)
                break

        return make_verdict_from_obs(
            http_o,
            confidence=confidence,
            subject=http_o.domain_name,
            subject_detail="",
            subject_category="website",
            outcome=outcome,
            outcome_detail="http.blockpage",
        )

    elif not http_o.request_is_encrypted:
        if http_o.response_matches_false_positive:
            return
        if http_o.response_body_title == http_b.response_body_title:
            return
        if http_o.response_body_meta_title == http_b.response_body_meta_title:
            return
        if http_o.response_body_sha1 == http_b.response_body_sha1:
            return

        if (
            http_o.response_body_length
            and http_b.response_body_length
            and (
                (http_o.response_body_length + 1.0)
                / (http_b.response_body_length + 1.0)
                < 0.7
            )
        ):
            return make_verdict_from_obs(
                http_o,
                confidence=0.6,
                subject=http_o.domain_name,
                subject_detail="",
                subject_category="website",
                outcome=Outcome.BLOCKED,
                outcome_detail="http.bodydiff",
            )


def make_dns_baseline_from_control(
    msmt_input: str, control: WebConnectivityControl
) -> DNSBaseline:
    domain_name = urlparse(msmt_input).hostname

    assert domain_name is not None, "domain_name is None"

    if not control or not control.dns:
        return DNSBaseline(domain=domain_name)

    nxdomain_cc_asn = []
    if control.dns.failure == "dns_nxdomain_error":
        nxdomain_cc_asn.append(("ZZ", 0))

    ok_cc_asn = []
    failure_cc_asn = []
    if control.dns.failure is not None:
        failure_cc_asn.append(("ZZ", 0))
    else:
        ok_cc_asn.append(("ZZ", 0))

    answers_map = {}
    if control.dns.addrs:
        answers_map["ZZ"] = [(0, ip) for ip in control.dns.addrs]

    return DNSBaseline(
        domain=domain_name,
        answers_map=answers_map,
        ok_cc_asn=ok_cc_asn,
        nxdomain_cc_asn=nxdomain_cc_asn,
        failure_cc_asn=failure_cc_asn,
    )


def make_tcp_baseline_from_control(
    control: WebConnectivityControl,
) -> dict[str, TCPBaseline]:
    if not control or not control.tcp_connect:
        return {}

    tcp_b_map = {}
    for key, status in control.tcp_connect.items():
        if status.failure == None:
            tcp_b_map[key] = TCPBaseline(address=key, reachable_cc_asn=[("ZZ", 0)])
        else:
            tcp_b_map[key] = TCPBaseline(address=key, unreachable_cc_asn=[("ZZ", 0)])
    return tcp_b_map


def make_http_baseline_from_control(
    msmt: WebConnectivity, control: WebConnectivityControl
) -> dict[str, HTTPBaseline]:
    if not control or not control.http_request:
        return {}

    if not msmt.test_keys.requests:
        return {}

    http_b_map = {}
    # We make the baseline apply to every URL in the response chain, XXX evaluate how much this is a good idea
    for http_transaction in msmt.test_keys.requests:
        if not http_transaction.request:
            continue

        url = http_transaction.request.url
        if control.http_request.failure == None:
            http_b_map[url] = HTTPBaseline(
                url=url,
                response_body_title=control.http_request.title or "",
                response_body_length=control.http_request.body_length or 0,
                response_status_code=control.http_request.status_code or 0,
                response_body_meta_title="",
                response_body_sha1="",
                ok_cc_asn=[("ZZ", 0)],
            )
        else:
            http_b_map[url] = HTTPBaseline(
                url=url,
                response_body_title="",
                response_body_length=0,
                response_status_code=0,
                response_body_meta_title="",
                response_body_sha1="",
                failure_cc_asn=[("ZZ", 0)],
            )
    return http_b_map


def make_website_verdicts(
    dns_o_list: List[DNSObservation],
    dns_b: DNSBaseline,
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
    tcp_o_list: List[TCPObservation],
    tcp_b_map: dict[str, TCPBaseline],
    tls_o_list: List[TLSObservation],
    http_o_list: List[HTTPObservation],
    http_b_map: dict[str, HTTPBaseline],
) -> Generator[Verdict, None, List[str]]:
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
    verdicts = []

    domain_name = dns_o_list[0].domain_name
    dns_verdicts = []
    for dns_o in dns_o_list:
        assert (
            domain_name == dns_o.domain_name
        ), f"Inconsistent domain_name in dns_o {dns_o.domain_name}"
        dns_v = make_website_dns_verdict(dns_o, dns_b, fingerprintdb, netinfodb)
        if dns_v:
            dns_verdicts.append(dns_v)
        else:
            # If we didn't get a DNS verdict from an observation, it means that
            # observation was a sign of everything being OK, hence we should
            # ignore all the previous DNS verdicts as likely false positives and
            # just consider no DNS level censorship to be happening.
            dns_verdicts = []
            break

    for dns_v in dns_verdicts:
        verdicts.append(dns_v)
        yield dns_v

    if tcp_o_list:
        for tcp_o in tcp_o_list:
            assert (
                domain_name == tcp_o.domain_name
            ), f"Inconsistent domain_name in tcp_o {tcp_o.domain_name}"
            tcp_b = tcp_b_map.get(f"{tcp_o.ip}:{tcp_o.port}")
            tcp_v = make_website_tcp_verdicts(tcp_o, tcp_b) if tcp_b else None
            if tcp_v:
                verdicts.append(tcp_v)
                yield tcp_v

    if tls_o_list:
        for tls_o in tls_o_list:
            assert (
                domain_name == tls_o.domain_name
            ), f"Inconsistent domain_name in tls_o {tls_o.domain_name}"
            tls_v = make_website_tls_verdict(tls_o, verdicts)
            if tls_v:
                verdicts.append(tls_v)
                yield tls_v

    if http_o_list:
        for http_o in http_o_list:
            assert (
                domain_name == http_o.domain_name
            ), f"Inconsistent domain_name in http_o {http_o.domain_name}"
            http_b = http_b_map.get(http_o.request_url)
            http_v = (
                make_website_http_verdict(http_o, http_b, verdicts, fingerprintdb)
                if http_b
                else None
            )
            if http_v:
                verdicts.append(http_v)
                yield http_v

    if len(verdicts) == 0:
        # We didn't generate any verdicts up to now, so it's reasonable to say
        # there is no interference happening for the given domain_name
        ok_verdict = make_verdict_from_obs(
            dns_o_list[0],
            confidence=0.9,
            subject=domain_name,
            subject_detail="",
            subject_category="website",
            outcome=Outcome.OK,
            outcome_detail="all",
        )
        yield ok_verdict
        verdicts.append(ok_verdict)
    return verdicts
