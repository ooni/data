from collections import defaultdict
from dataclasses import dataclass
import dataclasses
from datetime import datetime
import ipaddress
from typing import (
    Generator,
    Iterable,
    Optional,
    List,
    Dict,
)
from oonidata.db.connections import ClickhouseConnection
from oonidata.analysis.control import (
    WebGroundTruth,
    BodyDB,
)
from oonidata.models.analysis import WebsiteAnalysis

from oonidata.fingerprintdb import FingerprintDB
from oonidata.models.observations import WebControlObservation, WebObservation

import logging

log = logging.getLogger("oonidata.processing")

SYSTEM_RESOLVERS = ["system", "getaddrinfo", "golang_net_resolver", "go", "unknown"]
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


def encode_address(ip: str, port: Optional[int]) -> str:
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

    if port:
        addr += f":{port}"
    return addr


@dataclass
class TCPAnalysis:
    address: str
    success: bool

    ground_truth_failure_count: Optional[int]
    ground_truth_failure_asn_cc_count: Optional[int]
    ground_truth_ok_count: Optional[int]
    ground_truth_ok_asn_cc_count: Optional[int]

    ground_truth_trusted_failure_count: Optional[int]
    ground_truth_trusted_ok_count: Optional[int]


def make_tcp_analysis(
    web_o: WebObservation, web_ground_truths: List[WebGroundTruth]
) -> TCPAnalysis:
    assert web_o.ip is not None and web_o.port is not None

    blocking_subject = encode_address(web_o.ip, web_o.port)

    # It's working, wothing to see here, go on with your life
    if web_o.tcp_success:
        return TCPAnalysis(
            address=blocking_subject,
            success=True,
            ground_truth_failure_asn_cc_count=None,
            ground_truth_failure_count=None,
            ground_truth_ok_asn_cc_count=None,
            ground_truth_ok_count=None,
            ground_truth_trusted_failure_count=None,
            ground_truth_trusted_ok_count=None,
        )

    assert (
        web_o.tcp_failure is not None
    ), "inconsistency between tcp_success and tcp_failure"

    ground_truths = filter(
        lambda gt: gt.ip == web_o.ip and gt.port == web_o.port, web_ground_truths
    )
    unreachable_cc_asn = set()
    reachable_cc_asn = set()

    tcp_ground_truth_failure_asn_cc_count = 0
    tcp_ground_truth_failure_count = 0
    tcp_ground_truth_ok_asn_cc_count = 0
    tcp_ground_truth_ok_count = 0
    tcp_ground_truth_trusted_failure_count = 0
    tcp_ground_truth_trusted_ok_count = 0

    for gt in ground_truths:
        if gt.tcp_success is None:
            continue
        # We don't check for strict == True, since depending on the DB engine
        # True could also be represented as 1
        if gt.tcp_success:
            if gt.is_trusted_vp:
                tcp_ground_truth_trusted_ok_count += gt.count
            else:
                tcp_ground_truth_ok_count += 1
                reachable_cc_asn.add((gt.vp_cc, gt.vp_asn))
        else:
            if gt.is_trusted_vp:
                tcp_ground_truth_trusted_failure_count += gt.count
            else:
                tcp_ground_truth_failure_count += 1
                unreachable_cc_asn.add((gt.vp_cc, gt.vp_asn))

    tcp_ground_truth_failure_asn_cc_count = len(unreachable_cc_asn)
    tcp_ground_truth_ok_asn_cc_count = len(reachable_cc_asn)

    return TCPAnalysis(
        address=blocking_subject,
        success=False,
        ground_truth_failure_asn_cc_count=tcp_ground_truth_failure_asn_cc_count,
        ground_truth_failure_count=tcp_ground_truth_failure_count,
        ground_truth_ok_asn_cc_count=tcp_ground_truth_ok_asn_cc_count,
        ground_truth_ok_count=tcp_ground_truth_ok_count,
        ground_truth_trusted_failure_count=tcp_ground_truth_trusted_failure_count,
        ground_truth_trusted_ok_count=tcp_ground_truth_trusted_ok_count,
    )


@dataclass
class DNSGroundTruth:
    nxdomain_count: int
    nxdomain_cc_asn: set
    failure_cc_asn: set
    failure_count: int
    ok_cc_asn: set
    ok_count: int
    other_ips: Dict[str, set]
    other_asns: Dict[str, set]
    trusted_answers: Dict

    ok_cc_asn_count: int
    failure_cc_asn_count: int
    nxdomain_cc_asn_count: int


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
    ok_count = 0
    failure_count = 0
    nxdomain_count = 0
    for gt in ground_truths:
        if gt.dns_success is None:
            continue

        if gt.dns_failure == "dns_nxdomain_error":
            nxdomain_count += gt.count
            nxdomain_cc_asn.add((gt.vp_cc, gt.vp_asn))
            continue

        if not gt.dns_success:
            failure_count += gt.count
            failure_cc_asn.add((gt.vp_cc, gt.vp_asn))
            continue

        ok_count += gt.count
        ok_cc_asn.add((gt.vp_cc, gt.vp_asn))
        other_ips[gt.ip].add((gt.vp_cc, gt.vp_asn))
        assert gt.ip, "did not find IP in ground truth"
        other_asns[gt.ip_asn].add((gt.vp_cc, gt.vp_asn))
        if gt.tls_is_certificate_valid == True or gt.is_trusted_vp == True:
            trusted_answers[gt.ip] = gt

    return DNSGroundTruth(
        failure_count=failure_count,
        ok_count=ok_count,
        nxdomain_count=nxdomain_count,
        nxdomain_cc_asn=nxdomain_cc_asn,
        failure_cc_asn=failure_cc_asn,
        ok_cc_asn=ok_cc_asn,
        other_asns=other_asns,
        other_ips=other_ips,
        trusted_answers=trusted_answers,
        ok_cc_asn_count=len(ok_cc_asn),
        failure_cc_asn_count=len(failure_cc_asn),
        nxdomain_cc_asn_count=len(nxdomain_cc_asn),
    )


def dns_observations_by_resolver(
    dns_observations: List[WebObservation],
) -> Dict[str, List[WebObservation]]:
    by_resolver = defaultdict(list)
    for dns_o in dns_observations:
        dns_engine = dns_o.dns_engine or "system"
        key = f"{dns_engine}-{dns_o.dns_engine_resolver_address}"
        by_resolver[key].append(dns_o)
    return by_resolver


@dataclass
class DNSConsistencyResults:
    answers: List[str]
    success: bool = False
    failure: Optional[str] = None
    answer_count: int = 0

    is_answer_tls_consistent: bool = False
    is_answer_tls_inconsistent: bool = False
    is_answer_ip_in_trusted_answers: bool = False
    is_answer_asn_in_trusted_answers: bool = False
    is_answer_asorg_in_trusted_answers: bool = False
    is_answer_cloud_provider: bool = False
    is_answer_probe_asn_match: bool = False
    is_answer_probe_cc_match: bool = False
    is_answer_bogon: bool = False

    answer_fp_name: str = ""
    is_answer_fp_match: bool = False
    is_answer_fp_country_consistent: bool = False
    is_answer_fp_false_positive: bool = False

    is_resolver_probe_asn_match: bool = False
    is_resolver_probe_cc_match: bool = False

    answer_ip_ground_truth_asn_count: int = 0
    answer_asn_ground_truth_asn_count: int = 0


def check_dns_consistency(
    dns_observations: List[WebObservation],
    dns_ground_truth: DNSGroundTruth,
    fingerprintdb: FingerprintDB,
) -> DNSConsistencyResults:
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
    consistency_results = DNSConsistencyResults(answers=[])

    ground_truth_asns = set()
    ground_truth_ips = set()
    ground_truth_as_org_names = set()
    for gt in dns_ground_truth.trusted_answers.values():
        assert gt.ip, f"did not find IP in ground truth {gt.ip}"
        ground_truth_ips.add(gt.ip)
        ground_truth_asns.add(gt.ip_asn)
        ground_truth_as_org_names.add(gt.ip_as_org_name.lower())

    for web_o in dns_observations:
        if web_o.dns_failure == None and web_o.dns_answer:
            consistency_results.success = True
            consistency_results.answers.append(web_o.dns_answer)
            consistency_results.answer_count += 1
        else:
            consistency_results.failure = web_o.dns_failure

        fp = fingerprintdb.match_dns(web_o.dns_answer)

        if fp:
            consistency_results.is_answer_fp_match = True
            if fp.expected_countries and web_o.probe_cc in fp.expected_countries:
                consistency_results.is_answer_fp_country_consistent = True
            if fp.scope == "fp":
                consistency_results.is_answer_fp_false_positive = True
            # XXX in the event of multiple matches, we are overriding it with
            # the last value. It's probably OK for now.
            consistency_results.answer_fp_name = fp.name

        if not web_o.dns_engine or web_o.dns_engine in SYSTEM_RESOLVERS:
            # TODO: do the same thing for the non-system resolver
            if web_o.resolver_asn == web_o.probe_asn:
                consistency_results.is_resolver_probe_asn_match = True
            if web_o.resolver_cc == web_o.probe_cc:
                consistency_results.is_resolver_probe_cc_match = True

        if web_o.tls_is_certificate_valid == True:
            consistency_results.is_answer_tls_consistent = True

        if web_o.tls_is_certificate_valid == False:
            consistency_results.is_answer_tls_inconsistent = True

        if web_o.ip_is_bogon:
            consistency_results.is_answer_bogon = True

        if web_o.dns_answer_asn in ground_truth_asns:
            consistency_results.is_answer_asn_in_trusted_answers = True

        if web_o.dns_answer in ground_truth_ips:
            consistency_results.is_answer_ip_in_trusted_answers = True

        if (
            web_o.dns_answer_as_org_name
            and web_o.dns_answer_as_org_name.lower() in ground_truth_as_org_names
        ):
            consistency_results.is_answer_asorg_in_trusted_answers = True

        if web_o.dns_answer in dns_ground_truth.other_ips:
            consistency_results.answer_ip_ground_truth_asn_count += len(
                dns_ground_truth.other_ips[web_o.dns_answer]
            )

        if web_o.dns_answer in dns_ground_truth.other_asns:
            consistency_results.answer_asn_ground_truth_asn_count += len(
                dns_ground_truth.other_asns[web_o.dns_answer]
            )

        if is_cloud_provider(asn=web_o.ip_asn, as_org_name=web_o.ip_as_org_name):
            consistency_results.is_answer_cloud_provider = True

        if web_o.dns_answer_asn == web_o.probe_asn:
            consistency_results.is_answer_probe_asn_match = True
        elif web_o.ip_as_cc == web_o.probe_cc:
            consistency_results.is_answer_probe_cc_match = True

    return consistency_results


@dataclass
class DNSAnalysis:
    ground_truth: DNSGroundTruth

    consistency_system: DNSConsistencyResults
    consistency_other: Optional[DNSConsistencyResults]


def make_dns_analysis(
    hostname: str,
    dns_observations: List[WebObservation],
    web_ground_truths: List[WebGroundTruth],
    fingerprintdb: FingerprintDB,
) -> DNSAnalysis:
    dns_ground_truth = make_dns_ground_truth(
        ground_truths=filter(
            lambda gt: gt.hostname == hostname,
            web_ground_truths,
        )
    )
    dns_consistency_system = None
    dns_consistency_other = None

    for resolver_str, dns_observations in dns_observations_by_resolver(
        dns_observations
    ).items():
        if any([resolver_str.startswith(s) for s in SYSTEM_RESOLVERS]):
            dns_consistency_system = check_dns_consistency(
                fingerprintdb=fingerprintdb,
                dns_observations=dns_observations,
                dns_ground_truth=dns_ground_truth,
            )
        else:
            if dns_consistency_other is not None:
                log.warn(
                    "more than one alternative resolver in query list. overriding."
                )
            dns_consistency_other = check_dns_consistency(
                fingerprintdb=fingerprintdb,
                dns_observations=dns_observations,
                dns_ground_truth=dns_ground_truth,
            )

    assert dns_consistency_system is not None, "could not find system DNS resolution"

    return DNSAnalysis(
        ground_truth=dns_ground_truth,
        consistency_system=dns_consistency_system,
        consistency_other=dns_consistency_other,
    )


@dataclass
class TLSAnalysis:
    success: bool
    failure: Optional[str]
    is_tls_certificate_valid: bool
    is_tls_certificate_invalid: bool

    handshake_read_count: Optional[int]
    handshake_write_count: Optional[int]
    handshake_read_bytes: Optional[float]
    handshake_write_bytes: Optional[float]
    handshake_time: Optional[float]

    ground_truth_failure_count: int = 0
    ground_truth_failure_asn_cc_count: int = 0
    ground_truth_ok_count: int = 0
    ground_truth_ok_asn_cc_count: int = 0

    ground_truth_trusted_failure_count: int = 0
    ground_truth_trusted_ok_count: int = 0


def make_tls_analysis(
    web_o: WebObservation, web_ground_truths: List[WebGroundTruth]
) -> TLSAnalysis:
    tls_analysis = TLSAnalysis(
        success=web_o.tls_is_certificate_valid == True,
        failure=web_o.tls_failure,
        is_tls_certificate_valid=web_o.tls_is_certificate_valid == True,
        is_tls_certificate_invalid=web_o.tls_is_certificate_valid == False,
        handshake_read_count=web_o.tls_handshake_read_count,
        handshake_write_count=web_o.tls_handshake_write_count,
        handshake_read_bytes=web_o.tls_handshake_read_bytes,
        handshake_write_bytes=web_o.tls_handshake_write_bytes,
        handshake_time=web_o.tls_handshake_time,
    )
    ground_truths = filter(
        lambda gt: gt.http_request_url and gt.hostname == web_o.hostname,
        web_ground_truths,
    )
    failure_cc_asn = set()
    ok_cc_asn = set()
    for gt in ground_truths:
        # We don't check for strict == True, since depending on the DB engine
        # True could also be represented as 1
        if gt.http_success is None:
            continue

        if gt.http_success:
            if gt.is_trusted_vp:
                tls_analysis.ground_truth_trusted_ok_count += gt.count
            else:
                tls_analysis.ground_truth_ok_count += gt.count
                ok_cc_asn.add((gt.vp_cc, gt.vp_asn))
        else:
            if gt.is_trusted_vp:
                tls_analysis.ground_truth_trusted_failure_count += gt.count
            else:
                tls_analysis.ground_truth_failure_count += gt.count
                failure_cc_asn.add((gt.vp_cc, gt.vp_asn, gt.count))

    tls_analysis.ground_truth_ok_asn_cc_count = len(ok_cc_asn)
    tls_analysis.ground_truth_failure_asn_cc_count = len(failure_cc_asn)

    return tls_analysis


@dataclass
class HTTPAnalysis:
    success: bool
    failure: Optional[str]
    is_http_request_encrypted: bool

    response_body_proportion: Optional[float] = None
    response_body_length: Optional[int] = None
    response_status_code: Optional[int] = None

    ground_truth_failure_count: int = 0
    ground_truth_failure_asn_cc_count: int = 0
    ground_truth_ok_count: int = 0
    ground_truth_ok_asn_cc_count: int = 0

    ground_truth_trusted_ok_count: int = 0
    ground_truth_trusted_failure_count: int = 0
    ground_truth_body_length: int = 0

    fp_name: str = ""
    is_http_fp_match: bool = False
    is_http_fp_country_consistent: bool = False
    is_http_fp_false_positive: bool = False


def make_http_analysis(
    web_o: WebObservation,
    web_ground_truths: List[WebGroundTruth],
    body_db: BodyDB,
    fingerprintdb: FingerprintDB,
) -> HTTPAnalysis:
    assert web_o.http_request_url

    http_analysis = HTTPAnalysis(
        success=web_o.http_failure == None,
        failure=web_o.http_failure,
        is_http_request_encrypted=web_o.http_request_url.startswith("https://"),
    )

    ground_truths = filter(
        lambda gt: gt.http_request_url == web_o.http_request_url, web_ground_truths
    )
    failure_cc_asn = set()
    ok_cc_asn = set()
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
                http_analysis.ground_truth_trusted_ok_count += gt.count
            else:
                http_analysis.ground_truth_ok_count += gt.count
                ok_cc_asn.add((gt.vp_cc, gt.vp_asn))
        else:
            if gt.is_trusted_vp:
                http_analysis.ground_truth_trusted_failure_count += gt.count
            else:
                http_analysis.ground_truth_failure_count += gt.count
                failure_cc_asn.add((gt.vp_cc, gt.vp_asn, gt.count))

    response_body_length = 0
    if len(response_body_len_count) > 0:
        response_body_length = max(response_body_len_count.items(), key=lambda x: x[1])[
            0
        ]
    http_analysis.ground_truth_body_length = response_body_length

    # Untrusted Vantage Points (i.e. not control measurements) only count
    # once per probe_cc, probe_asn pair to avoid spammy probes poisoning our
    # data
    http_analysis.ground_truth_failure_asn_cc_count += len(failure_cc_asn)
    http_analysis.ground_truth_ok_asn_cc_count += len(ok_cc_asn)

    # TODO: do we care to do something about empty bodies?
    # They are commonly a source of blockpages
    if web_o.http_response_body_sha1:
        matched_fp = body_db.lookup(web_o.http_response_body_sha1)
        if len(matched_fp) > 0:
            for fp_name in matched_fp:
                fp = fingerprintdb.get_fp(fp_name)
                if fp.scope:
                    http_analysis.is_http_fp_match = True
                    if fp.scope == "fp":
                        http_analysis.is_http_fp_false_positive = True
                    if (
                        fp.expected_countries
                        and web_o.probe_cc in fp.expected_countries
                    ):
                        http_analysis.is_http_fp_country_consistent = True
                    if fp.name:
                        http_analysis.fp_name = fp.name

    if web_o.http_response_body_length:
        http_analysis.response_body_length = web_o.http_response_body_length
        http_analysis.response_body_proportion = (
            web_o.http_response_body_length + 1.0
        ) / (response_body_length + 1.0)

    http_analysis.response_status_code = web_o.http_response_status_code
    return http_analysis


def make_website_analysis(
    web_observations: List[WebObservation],
    web_ground_truths: List[WebGroundTruth],
    body_db: BodyDB,
    fingerprintdb: FingerprintDB,
) -> Generator[WebsiteAnalysis, None, None]:
    domain_name = web_observations[0].hostname or ""
    experiment_group = "websites"
    # Ghetto hax attempt at consolidating targets
    target_name = domain_name.replace("www.", "")

    dns_observations_by_hostname = defaultdict(list)
    dns_analysis_by_hostname = {}
    other_observations = []
    for web_o in web_observations:
        if web_o.dns_query_type:
            assert web_o.hostname is not None
            dns_observations_by_hostname[web_o.hostname].append(web_o)
        else:
            other_observations.append(web_o)

    for hostname, dns_observations in dns_observations_by_hostname.items():
        dns_analysis = make_dns_analysis(
            hostname=hostname,
            dns_observations=dns_observations,
            web_ground_truths=web_ground_truths,
            fingerprintdb=fingerprintdb,
        )
        dns_analysis_by_hostname[hostname] = dns_analysis

    for idx, web_o in enumerate(web_observations):
        subject = web_o.http_request_url or domain_name
        if web_o.ip:
            try:
                ipaddr = ipaddress.ip_address(web_o.ip)
                # FIXME: for the moment we just ignore all IPv6 results, because they are too noisy
                if isinstance(ipaddr, ipaddress.IPv6Address):
                    continue
                address = encode_address(web_o.ip, web_o.port)
                subject = f"{address} {subject}"
            except:
                log.error(f"Invalid IP in {web_o.ip}")

        dns_analysis = dns_analysis_by_hostname.get(web_o.hostname, None)

        tcp_analysis = None
        tls_analysis = None
        http_analysis = None
        if web_o.tcp_success is not None:
            tcp_analysis = make_tcp_analysis(
                web_o=web_o, web_ground_truths=web_ground_truths
            )
        if web_o.tls_failure or web_o.tls_cipher_suite is not None:
            tls_analysis = make_tls_analysis(
                web_o=web_o, web_ground_truths=web_ground_truths
            )

        if web_o.http_request_url:
            http_analysis = make_http_analysis(
                web_o=web_o,
                web_ground_truths=web_ground_truths,
                body_db=body_db,
                fingerprintdb=fingerprintdb,
            )

        created_at = datetime.utcnow()
        website_analysis = WebsiteAnalysis(
            measurement_uid=web_o.measurement_uid,
            observation_id=web_o.observation_id,
            created_at=created_at,
            report_id=web_o.report_id,
            input=web_o.input,
            measurement_start_time=web_o.measurement_start_time,
            probe_asn=web_o.probe_asn,
            probe_cc=web_o.probe_cc,
            probe_as_org_name=web_o.probe_as_org_name,
            probe_as_cc=web_o.probe_as_cc,
            network_type=web_o.network_type,
            resolver_ip=web_o.resolver_ip,
            resolver_asn=web_o.resolver_asn,
            resolver_as_org_name=web_o.resolver_as_org_name,
            resolver_as_cc=web_o.resolver_as_cc,
            resolver_cc=web_o.resolver_cc,
            analysis_id=f"{web_o.measurement_uid}_{idx}",
            experiment_group=experiment_group,
            domain_name=domain_name,
            target_name=target_name,
            subject=subject,
        )

        if dns_analysis:
            website_analysis.dns_ground_truth_nxdomain_count = (
                dns_analysis.ground_truth.nxdomain_count
            )
            website_analysis.dns_ground_truth_ok_cc_asn_count = (
                dns_analysis.ground_truth.ok_cc_asn_count
            )
            website_analysis.dns_ground_truth_failure_cc_asn_count = (
                dns_analysis.ground_truth.failure_cc_asn_count
            )
            website_analysis.dns_ground_truth_nxdomain_cc_asn_count = (
                dns_analysis.ground_truth.nxdomain_cc_asn_count
            )
            website_analysis.dns_consistency_system_answers = (
                dns_analysis.consistency_system.answers
            )
            website_analysis.dns_consistency_system_success = (
                dns_analysis.consistency_system.success
            )
            website_analysis.dns_consistency_system_failure = (
                dns_analysis.consistency_system.failure
            )
            website_analysis.dns_consistency_system_answer_count = (
                dns_analysis.consistency_system.answer_count
            )
            website_analysis.dns_consistency_system_is_answer_tls_consistent = (
                dns_analysis.consistency_system.is_answer_tls_consistent
            )
            website_analysis.dns_consistency_system_is_answer_tls_inconsistent = (
                dns_analysis.consistency_system.is_answer_tls_inconsistent
            )
            website_analysis.dns_consistency_system_is_answer_ip_in_trusted_answers = (
                dns_analysis.consistency_system.is_answer_ip_in_trusted_answers
            )
            website_analysis.dns_consistency_system_is_answer_asn_in_trusted_answers = (
                dns_analysis.consistency_system.is_answer_asn_in_trusted_answers
            )
            website_analysis.dns_consistency_system_is_answer_asorg_in_trusted_answers = (
                dns_analysis.consistency_system.is_answer_asorg_in_trusted_answers
            )
            website_analysis.dns_consistency_system_is_answer_cloud_provider = (
                dns_analysis.consistency_system.is_answer_cloud_provider
            )
            website_analysis.dns_consistency_system_is_answer_probe_asn_match = (
                dns_analysis.consistency_system.is_answer_probe_asn_match
            )
            website_analysis.dns_consistency_system_is_answer_probe_cc_match = (
                dns_analysis.consistency_system.is_answer_probe_cc_match
            )
            website_analysis.dns_consistency_system_is_answer_bogon = (
                dns_analysis.consistency_system.is_answer_bogon
            )
            website_analysis.dns_consistency_system_answer_fp_name = (
                dns_analysis.consistency_system.answer_fp_name
            )
            website_analysis.dns_consistency_system_is_answer_fp_match = (
                dns_analysis.consistency_system.is_answer_fp_match
            )
            website_analysis.dns_consistency_system_is_answer_fp_country_consistent = (
                dns_analysis.consistency_system.is_answer_fp_country_consistent
            )
            website_analysis.dns_consistency_system_is_answer_fp_false_positive = (
                dns_analysis.consistency_system.is_answer_fp_false_positive
            )
            website_analysis.dns_consistency_system_is_resolver_probe_asn_match = (
                dns_analysis.consistency_system.is_resolver_probe_asn_match
            )
            website_analysis.dns_consistency_system_is_resolver_probe_cc_match = (
                dns_analysis.consistency_system.is_resolver_probe_cc_match
            )
            website_analysis.dns_consistency_system_answer_ip_ground_truth_asn_count = (
                dns_analysis.consistency_system.answer_ip_ground_truth_asn_count
            )
            website_analysis.dns_consistency_system_answer_asn_ground_truth_asn_count = (
                dns_analysis.consistency_system.answer_asn_ground_truth_asn_count
            )
            """
            website_analysis.dns_ground_truth_nxdomain_cc_asn = (
                dns_analysis.ground_truth.nxdomain_cc_asn
            )
            website_analysis.dns_ground_truth_failure_cc_asn = (
                dns_analysis.ground_truth.failure_cc_asn
            )
            website_analysis.dns_ground_truth_failure_count = (
                dns_analysis.ground_truth.failure_count
            )
            website_analysis.dns_ground_truth_ok_cc_asn = (
                dns_analysis.ground_truth.ok_cc_asn
            )
            website_analysis.dns_ground_truth_ok_count = (
                dns_analysis.ground_truth.ok_count
            )
            website_analysis.dns_ground_truth_other_ips = (
                dns_analysis.ground_truth.other_ips
            )
            website_analysis.dns_ground_truth_other_asns = (
                dns_analysis.ground_truth.other_asns
            )
            website_analysis.dns_ground_truth_trusted_answers = (
                dns_analysis.ground_truth.trusted_answers
            )
            """

        if dns_analysis and dns_analysis.consistency_other:
            website_analysis.dns_consistency_other_answers = (
                dns_analysis.consistency_other.answers
            )
            website_analysis.dns_consistency_other_success = (
                dns_analysis.consistency_other.success
            )
            website_analysis.dns_consistency_other_failure = (
                dns_analysis.consistency_other.failure
            )
            website_analysis.dns_consistency_other_answer_count = (
                dns_analysis.consistency_other.answer_count
            )
            website_analysis.dns_consistency_other_is_answer_tls_consistent = (
                dns_analysis.consistency_other.is_answer_tls_consistent
            )
            website_analysis.dns_consistency_other_is_answer_tls_inconsistent = (
                dns_analysis.consistency_other.is_answer_tls_inconsistent
            )
            website_analysis.dns_consistency_other_is_answer_ip_in_trusted_answers = (
                dns_analysis.consistency_other.is_answer_ip_in_trusted_answers
            )
            website_analysis.dns_consistency_other_is_answer_asn_in_trusted_answers = (
                dns_analysis.consistency_other.is_answer_asn_in_trusted_answers
            )
            website_analysis.dns_consistency_other_is_answer_asorg_in_trusted_answers = (
                dns_analysis.consistency_other.is_answer_asorg_in_trusted_answers
            )
            website_analysis.dns_consistency_other_is_answer_cloud_provider = (
                dns_analysis.consistency_other.is_answer_cloud_provider
            )
            website_analysis.dns_consistency_other_is_answer_probe_asn_match = (
                dns_analysis.consistency_other.is_answer_probe_asn_match
            )
            website_analysis.dns_consistency_other_is_answer_probe_cc_match = (
                dns_analysis.consistency_other.is_answer_probe_cc_match
            )
            website_analysis.dns_consistency_other_is_answer_bogon = (
                dns_analysis.consistency_other.is_answer_bogon
            )
            website_analysis.dns_consistency_other_answer_fp_name = (
                dns_analysis.consistency_other.answer_fp_name
            )
            website_analysis.dns_consistency_other_is_answer_fp_match = (
                dns_analysis.consistency_other.is_answer_fp_match
            )
            website_analysis.dns_consistency_other_is_answer_fp_country_consistent = (
                dns_analysis.consistency_other.is_answer_fp_country_consistent
            )
            website_analysis.dns_consistency_other_is_answer_fp_false_positive = (
                dns_analysis.consistency_other.is_answer_fp_false_positive
            )
            website_analysis.dns_consistency_other_is_resolver_probe_asn_match = (
                dns_analysis.consistency_other.is_resolver_probe_asn_match
            )
            website_analysis.dns_consistency_other_is_resolver_probe_cc_match = (
                dns_analysis.consistency_other.is_resolver_probe_cc_match
            )
            website_analysis.dns_consistency_other_answer_ip_ground_truth_asn_count = (
                dns_analysis.consistency_other.answer_ip_ground_truth_asn_count
            )
            website_analysis.dns_consistency_other_answer_asn_ground_truth_asn_count = (
                dns_analysis.consistency_other.answer_asn_ground_truth_asn_count
            )
        if tls_analysis:
            website_analysis.tls_success = tls_analysis.success
            website_analysis.tls_failure = tls_analysis.failure
            website_analysis.tls_is_tls_certificate_valid = (
                tls_analysis.is_tls_certificate_valid
            )
            website_analysis.tls_is_tls_certificate_invalid = (
                tls_analysis.is_tls_certificate_invalid
            )
            website_analysis.tls_handshake_read_count = (
                tls_analysis.handshake_read_count
            )
            website_analysis.tls_handshake_write_count = (
                tls_analysis.handshake_write_count
            )
            website_analysis.tls_handshake_read_bytes = (
                tls_analysis.handshake_read_bytes
            )
            website_analysis.tls_handshake_write_bytes = (
                tls_analysis.handshake_write_bytes
            )
            website_analysis.tls_handshake_time = tls_analysis.handshake_time
            website_analysis.tls_ground_truth_failure_count = (
                tls_analysis.ground_truth_failure_count
            )
            website_analysis.tls_ground_truth_failure_asn_cc_count = (
                tls_analysis.ground_truth_failure_asn_cc_count
            )
            website_analysis.tls_ground_truth_ok_count = (
                tls_analysis.ground_truth_ok_count
            )
            website_analysis.tls_ground_truth_ok_asn_cc_count = (
                tls_analysis.ground_truth_ok_asn_cc_count
            )
            website_analysis.tls_ground_truth_trusted_failure_count = (
                tls_analysis.ground_truth_trusted_failure_count
            )
            website_analysis.tls_ground_truth_trusted_ok_count = (
                tls_analysis.ground_truth_trusted_ok_count
            )
        if tcp_analysis:
            website_analysis.tcp_address = tcp_analysis.address
            website_analysis.tcp_success = tcp_analysis.success
            website_analysis.tcp_ground_truth_failure_count = (
                tcp_analysis.ground_truth_failure_count
            )
            website_analysis.tcp_ground_truth_failure_asn_cc_count = (
                tcp_analysis.ground_truth_failure_asn_cc_count
            )
            website_analysis.tcp_ground_truth_ok_count = (
                tcp_analysis.ground_truth_ok_count
            )
            website_analysis.tcp_ground_truth_ok_asn_cc_count = (
                tcp_analysis.ground_truth_ok_asn_cc_count
            )
            website_analysis.tcp_ground_truth_trusted_failure_count = (
                tcp_analysis.ground_truth_trusted_failure_count
            )
            website_analysis.tcp_ground_truth_trusted_ok_count = (
                tcp_analysis.ground_truth_trusted_ok_count
            )
        if http_analysis:
            website_analysis.http_success = http_analysis.success
            website_analysis.http_failure = http_analysis.failure
            website_analysis.http_is_http_request_encrypted = (
                http_analysis.is_http_request_encrypted
            )
            website_analysis.http_response_body_length = (
                http_analysis.response_body_length
            )
            website_analysis.http_response_body_proportion = (
                http_analysis.response_body_proportion
            )
            website_analysis.http_response_status_code = (
                http_analysis.response_status_code
            )
            website_analysis.http_ground_truth_failure_count = (
                http_analysis.ground_truth_failure_count
            )
            website_analysis.http_ground_truth_failure_asn_cc_count = (
                http_analysis.ground_truth_failure_asn_cc_count
            )
            website_analysis.http_ground_truth_ok_count = (
                http_analysis.ground_truth_ok_count
            )
            website_analysis.http_ground_truth_ok_asn_cc_count = (
                http_analysis.ground_truth_ok_asn_cc_count
            )
            website_analysis.http_ground_truth_trusted_ok_count = (
                http_analysis.ground_truth_trusted_ok_count
            )
            website_analysis.http_ground_truth_trusted_failure_count = (
                http_analysis.ground_truth_trusted_failure_count
            )
            website_analysis.http_ground_truth_body_length = (
                http_analysis.ground_truth_body_length
            )
            website_analysis.http_fp_name = http_analysis.fp_name
            website_analysis.http_is_http_fp_match = http_analysis.is_http_fp_match
            website_analysis.http_is_http_fp_country_consistent = (
                http_analysis.is_http_fp_country_consistent
            )
            website_analysis.http_is_http_fp_false_positive = (
                http_analysis.is_http_fp_false_positive
            )

        yield website_analysis
