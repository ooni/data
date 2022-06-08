import hashlib
from datetime import datetime
from dataclasses import dataclass, field
from typing import Generator, Optional, List

from oonidata.dataformat import (
    BaseMeasurement,
    DNSQuery,
    HeadersList,
    HTTPTransaction,
    Failure,
)

from oonidata.datautils import (
    get_first_http_header,
    get_html_meta_title,
    get_html_title,
    is_ipv4_bogon,
    is_ipv6_bogon,
)
from oonidata.fingerprints.matcher import FingerprintDB
from oonidata.netinfo import NetinfoDB


def normalize_failure(failure: Failure):
    # TODO: implement a mapping between known unknowns to cleanup the data a bit
    return failure


class Observation:
    measurement_uid: str
    timestamp: datetime

    probe_asn: int
    probe_cc: str

    probe_as_org_name: Optional[str]
    probe_as_cc: Optional[str]

    software_name: str
    software_version: str
    network_type: str
    platform: str
    origin: str

    resolver_asn: Optional[str]
    resolver_ip: Optional[str]
    resolver_cc: Optional[str]
    resolver_as_org_name: Optional[str]
    resolver_as_cc: Optional[str]

    def __init__(self, msmt: BaseMeasurement, netinfodb: NetinfoDB):
        self.measurement_uid = msmt.measurement_uid
        self.timestamp = datetime.strptime(
            msmt.measurement_start_time, "%Y-%m-%d %H:%M:%S"
        )
        self.probe_asn = int(msmt.probe_asn.lstrip("AS"))
        self.probe_cc = msmt.probe_cc

        self.software_name = msmt.software_name
        self.software_version = msmt.software_version
        self.network_type = msmt.annotations.network_type
        self.platform = msmt.annotations.platform
        self.origin = msmt.annotations.origin

        probe_as_info = netinfodb.lookup_asn(self.timestamp, self.probe_asn)
        if probe_as_info:
            self.probe_as_org_name = probe_as_info.as_org_name
            self.probe_as_cc = probe_as_info.as_cc

        resolver_ip = msmt.resolver_ip or msmt.test_keys.client_resolver
        if resolver_ip:
            resolver_as_info = netinfodb.lookup_ip(self.timestamp, resolver_ip)
            if resolver_as_info:
                self.resolver_ip = resolver_ip
                self.resolver_asn = resolver_as_info.as_info.asn
                self.resolver_as_org_name = resolver_as_info.as_info.as_org_name
                self.resolver_as_cc = resolver_as_info.as_info.as_cc
                self.resolver_cc = resolver_as_info.cc


class HTTPObservation(Observation):
    db_table = "obs_http"

    request_url: str
    request_is_encrypted: bool

    request_redirect_from: Optional[str]
    request_body_length: Optional[int]
    request_body_is_truncated: Optional[bool]
    request_headers_list: Optional[HeadersList]
    request_method: Optional[str]

    response_body_length: Optional[int]
    response_body_is_truncated: Optional[bool]
    response_body_sha1: Optional[str]
    response_body_title: Optional[str]
    response_body_meta_title: Optional[str]

    response_status_code: Optional[int]
    response_headers_list: Optional[HeadersList]
    response_header_location: Optional[str]
    response_header_server: Optional[str]

    failure: Failure

    response_fingerprints: List[str]
    fingerprint_country_consistent: Optional[bool]
    response_matches_blockpage: bool = False
    response_matches_false_positive: bool = False
    x_transport: Optional[str] = "tcp"


def make_http_observations(
    msmt: BaseMeasurement,
    requests_list: List[HTTPTransaction],
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
) -> Generator[HTTPObservation, None, None]:
    for idx, http_transaction in enumerate(requests_list):
        hrro = HTTPObservation(msmt, netinfodb)

        hrro.request_url = http_transaction.request.url
        hrro.request_is_encrypted = http_transaction.request.url.startswith("https://")
        hrro.request_body_is_truncated = http_transaction.request.body_is_truncated
        hrro.request_headers_list = http_transaction.request.headers_list
        hrro.request_method = http_transaction.request.method

        if http_transaction.request.body_bytes:
            hrro.request_body_length = len(http_transaction.request.body_bytes)

        hrro.response_body_is_truncated = http_transaction.response.body_is_truncated

        hrro.response_fingerprints = []
        fp_matches = fingerprintdb.match_http(http_transaction.response)
        for fp in fp_matches:
            if fp.scope == "fp":
                hrro.response_matches_false_positive = True
            else:
                hrro.response_matches_blockpage = True
            if fp.expected_countries and msmt.probe_cc in fp.expected_countries:
                hrro.fingerprint_country_consistent = True
            hrro.response_fingerprints.append(fp.name)

        hrro.failure = normalize_failure(http_transaction.failure)

        if http_transaction.response.body_bytes:
            hrro.response_body_length = len(http_transaction.response.body_bytes)
            hrro.response_body_sha1 = hashlib.sha1(
                http_transaction.response.body_bytes
            ).hexdigest()
            hrro.response_body_title = get_html_title(
                http_transaction.response.body_bytes
            )
            hrro.response_body_meta_title = get_html_meta_title(
                http_transaction.response.body_bytes
            )

        hrro.response_status_code = http_transaction.response.code
        hrro.response_headers_list = http_transaction.response.headers_list

        hrro.response_header_location = get_first_http_header(
            "location", http_transaction.response.headers_list_bytes
        )
        hrro.response_header_server = get_first_http_header(
            "server", http_transaction.response.headers_list_bytes
        )
        hrro.x_transport = http_transaction.request.x_transport

        try:
            prev_request = requests_list[idx + 1]
            prev_location = get_first_http_header(
                "location", prev_request.response.headers_list_bytes
            ).decode("utf-8")
            if prev_location == hrro.request_url:
                hrro.request_redirect_from = prev_request.request.url
        except (IndexError, UnicodeDecodeError):
            pass

        yield hrro


class DNSObservation(Observation):
    db_table = "obs_dns"

    query_type: str
    answer_type: str
    answer: str
    answer_asn: Optional[str]
    answer_as_org_name: Optional[str]
    answer_as_cc: Optional[str]
    answer_cc: Optional[str]
    answer_is_bogon: Optional[str]

    domain: str
    failure: Failure
    fingerprint_id: str
    fingerprint_country_consistent: Optional[bool]


def make_dns_observations(
    msmt: BaseMeasurement,
    queries: List[DNSQuery],
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
) -> Generator[DNSObservation, None, None]:
    for query in queries:
        if not query.answers:
            dnso = DNSObservation(msmt, netinfodb)
            dnso.query_type = query.query_type
            dnso.domain = query.hostname
            dnso.failure = normalize_failure(query.failure)
            yield dnso
            continue

        for answer in query.answers:
            dnso = DNSObservation(msmt, netinfodb)
            dnso.query_type = query.query_type
            dnso.domain = query.hostname
            dnso.answer_type = answer.answer_type
            if answer.ipv4:
                dnso.answer = answer.ipv4
                dnso.answer_is_bogon = is_ipv4_bogon(answer.ipv4)
            elif answer.ipv6:
                dnso.answer = answer.ipv6
                dnso.answer_is_bogon = is_ipv6_bogon(answer.ipv6)
            elif answer.hostname:
                dnso.answer = answer.hostname

            if answer.ipv4 or answer.ipv6:
                answer_meta = netinfodb.lookup_ip(dnso.timestamp, dnso.answer)
                if answer_meta:
                    dnso.answer_asn = answer_meta.as_info.asn
                    dnso.answer_as_cc = answer_meta.as_info.as_cc
                    dnso.answer_as_org_name = answer_meta.as_info.as_org_name
                    dnso.answer_cc = answer_meta.cc

            matched_fingerprint = fingerprintdb.match_dns(dnso.answer)
            if matched_fingerprint:
                dnso.fingerprint_id = matched_fingerprint.name
                if matched_fingerprint.expected_countries:
                    dnso.fingerprint_country_consistent = (
                        msmt.probe_cc in matched_fingerprint.expected_countries
                    )
            yield dnso
