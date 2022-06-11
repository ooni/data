import hashlib
from unittest.mock import Base
from urllib.parse import urlparse, urlsplit
from datetime import datetime, timedelta
from typing import Generator, Optional, List, Dict

from requests import request

from oonidata.dataformat import (
    BaseMeasurement,
    DNSAnswer,
    DNSQuery,
    HTTPTransaction,
    Failure,
    NetworkEvent,
    TCPConnect,
    TLSHandshake,
)

from oonidata.datautils import (
    get_first_http_header,
    get_html_meta_title,
    get_html_title,
    is_ipv4_bogon,
    is_ipv6_bogon,
    get_certificate_meta,
)
from oonidata.fingerprints.matcher import FingerprintDB
from oonidata.netinfo import NetinfoDB


def normalize_failure(failure: Failure):
    # TODO: implement a mapping between known unknowns to cleanup the data a bit
    return failure


class Observation:
    measurement_uid: str
    observation_id: str

    session_id: str

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

    resolver_asn: Optional[int]
    resolver_ip: Optional[str]
    resolver_cc: Optional[str]
    resolver_as_org_name: Optional[str]
    resolver_as_cc: Optional[str]


def set_base_observation_meta(
    obs: Observation, msmt: BaseMeasurement, netinfodb: NetinfoDB
) -> "Observation":
    assert msmt.measurement_uid is not None
    obs.measurement_uid = msmt.measurement_uid
    obs.timestamp = datetime.strptime(msmt.measurement_start_time, "%Y-%m-%d %H:%M:%S")
    obs.probe_asn = int(msmt.probe_asn.lstrip("AS"))
    obs.probe_cc = msmt.probe_cc
    obs.session_id = msmt.report_id

    obs.software_name = msmt.software_name
    obs.software_version = msmt.software_version
    obs.network_type = msmt.annotations.network_type
    obs.platform = msmt.annotations.platform
    obs.origin = msmt.annotations.origin

    probe_as_info = netinfodb.lookup_asn(obs.timestamp, obs.probe_asn)
    if probe_as_info:
        obs.probe_as_org_name = probe_as_info.as_org_name
        obs.probe_as_cc = probe_as_info.as_cc

    resolver_ip = msmt.resolver_ip
    if not resolver_ip and msmt.test_keys and msmt.test_keys.client_resolver:
        resolver_ip = msmt.test_keys.client_resolver
    if resolver_ip:
        resolver_as_info = netinfodb.lookup_ip(obs.timestamp, resolver_ip)
        if resolver_as_info:
            obs.resolver_ip = resolver_ip
            obs.resolver_asn = resolver_as_info.as_info.asn
            obs.resolver_as_org_name = resolver_as_info.as_info.as_org_name
            obs.resolver_as_cc = resolver_as_info.as_info.as_cc
            obs.resolver_cc = resolver_as_info.cc
    return obs


class HTTPObservation(Observation):
    db_table = "obs_http"

    domain_name: str
    request_url: str
    request_is_encrypted: bool

    request_redirect_from: Optional[str]
    request_body_length: int
    request_body_is_truncated: Optional[bool]
    # request_headers_list: Optional[List[Tuple[str, bytes]]]
    request_method: Optional[str]

    response_body_length: Optional[int]
    response_body_is_truncated: Optional[bool]
    response_body_sha1: Optional[str]
    response_body_title: Optional[str]
    response_body_meta_title: Optional[str]

    response_status_code: Optional[int]
    # response_headers_list: Optional[List[Tuple[str, bytes]]]
    response_header_location: Optional[str]
    response_header_server: Optional[str]

    failure: Failure

    response_fingerprints: List[str]
    fingerprint_country_consistent: Optional[bool]
    response_matches_blockpage: bool = False
    response_matches_false_positive: bool = False
    x_transport: Optional[str] = "tcp"

    @staticmethod
    def from_measurement(
        msmt: BaseMeasurement,
        netinfodb: NetinfoDB,
        idx: int,
        requests_list: Optional[List[HTTPTransaction]],
        http_transaction: HTTPTransaction,
        fingerprintdb: FingerprintDB,
    ) -> Optional["HTTPObservation"]:
        hrro = HTTPObservation()
        hrro = set_base_observation_meta(hrro, msmt, netinfodb)

        if http_transaction.t:
            hrro.timestamp += timedelta(seconds=http_transaction.t)

        hrro.observation_id = f"{hrro.measurement_uid}{idx}"

        hrro.response_fingerprints = []
        hrro.failure = normalize_failure(http_transaction.failure)

        if not http_transaction.request:
            # This is a very malformed request, we don't consider it a valid
            # observation as we don't know what it's referring to.
            # XXX maybe log this somewhere
            return None

        parsed_url = urlparse(http_transaction.request.url)

        hrro.request_url = http_transaction.request.url
        hrro.domain_name = parsed_url.hostname
        hrro.request_is_encrypted = parsed_url.scheme == "https"
        hrro.request_body_is_truncated = http_transaction.request.body_is_truncated
        # hrro.request_headers_list = http_transaction.request.headers_list_bytes
        hrro.request_method = http_transaction.request.method

        hrro.x_transport = http_transaction.request.x_transport
        hrro.request_body_length = 0
        if http_transaction.request.body_bytes:
            hrro.request_body_length = len(http_transaction.request.body_bytes)

        if not http_transaction.response:
            return hrro

        hrro.response_body_is_truncated = http_transaction.response.body_is_truncated

        fp_matches = fingerprintdb.match_http(http_transaction.response)
        for fp in fp_matches:
            if fp.scope == "fp":
                hrro.response_matches_false_positive = True
            else:
                hrro.response_matches_blockpage = True
            if fp.expected_countries and msmt.probe_cc in fp.expected_countries:
                hrro.fingerprint_country_consistent = True
            hrro.response_fingerprints.append(fp.name)

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
        # hrro.response_headers_list = http_transaction.response.headers_list_bytes

        hrro.response_header_location = get_first_http_header(
            "location", http_transaction.response.headers_list_bytes
        )
        hrro.response_header_server = get_first_http_header(
            "server", http_transaction.response.headers_list_bytes
        )

        try:
            prev_request = requests_list[idx + 1]
            prev_location = get_first_http_header(
                "location", prev_request.response.headers_list_bytes
            ).decode("utf-8")
            if prev_location == hrro.request_url:
                hrro.request_redirect_from = prev_request.request.url
        except (IndexError, UnicodeDecodeError, AttributeError):
            pass
        return hrro


def make_http_observations(
    msmt: BaseMeasurement,
    requests_list: Optional[List[HTTPTransaction]],
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
) -> Generator[HTTPObservation, None, None]:
    if not requests_list:
        return

    for idx, http_transaction in enumerate(requests_list):
        httpo = HTTPObservation.from_measurement(
            msmt, netinfodb, idx, requests_list, http_transaction, fingerprintdb
        )
        if httpo:
            yield httpo


class DNSObservation(Observation):
    db_table = "obs_dns"

    domain_name: str

    query_type: str
    answer_type: str
    answer: str
    answer_asn: Optional[int]
    answer_as_org_name: Optional[str]
    answer_as_cc: Optional[str]
    answer_cc: Optional[str]
    answer_is_bogon: Optional[bool]

    failure: Failure
    fingerprint_id: str
    fingerprint_country_consistent: Optional[bool]

    is_tls_consistent: Optional[bool]

    @staticmethod
    def from_measurement(
        msmt: BaseMeasurement,
        query: DNSQuery,
        answer: Optional[DNSAnswer],
        idx: int,
        fingerprintdb: FingerprintDB,
        netinfodb: NetinfoDB,
    ) -> "DNSObservation":
        dnso = DNSObservation()
        dnso = set_base_observation_meta(dnso, msmt, netinfodb)
        if query.t:
            dnso.timestamp += timedelta(seconds=query.t)

        dnso.observation_id = f"{dnso.measurement_uid}{idx}"

        dnso.query_type = query.query_type
        dnso.domain_name = query.hostname
        dnso.failure = normalize_failure(query.failure)
        if not answer:
            return dnso

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
        return dnso


def make_dns_observations(
    msmt: BaseMeasurement,
    queries: Optional[List[DNSQuery]],
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
) -> Generator[DNSObservation, None, None]:
    if not queries:
        return

    for query in queries:
        answer_list = query.answers
        if not answer_list:
            answer_list = [None]
        for idx, answer in enumerate(answer_list):
            yield DNSObservation.from_measurement(
                msmt, query, answer, idx, fingerprintdb, netinfodb
            )


class TCPObservation(Observation):
    db_table = "obs_tcp"

    domain_name: str

    ip: str
    port: int

    ip_asn: Optional[int]
    ip_as_org_name: Optional[str]
    ip_as_cc: Optional[str]
    ip_cc: Optional[str]

    failure: Failure

    @staticmethod
    def from_measurement(
        msmt: BaseMeasurement,
        res: TCPConnect,
        idx: int,
        ip_to_domain: Dict[str, str],
        netinfodb: NetinfoDB,
    ) -> "TCPObservation":
        tcpo = TCPObservation()
        tcpo = set_base_observation_meta(tcpo, msmt, netinfodb)
        if res.t:
            tcpo.timestamp += timedelta(seconds=res.t)

        tcpo.observation_id = f"{tcpo.measurement_uid}{idx}"

        tcpo.ip = res.ip
        tcpo.port = res.port
        tcpo.failure = normalize_failure(res.status.failure)
        tcpo.domain_name = ip_to_domain.get(res.ip, "")

        ip_info = netinfodb.lookup_ip(tcpo.timestamp, res.ip)
        if ip_info:
            tcpo.ip_asn = ip_info.as_info.asn
            tcpo.ip_as_org_name = ip_info.as_info.as_org_name
            tcpo.ip_as_cc = ip_info.as_info.as_cc

            tcpo.ip_cc = ip_info.cc

        return tcpo


def make_tcp_observations(
    msmt: BaseMeasurement,
    tcp_connect: Optional[List[TCPConnect]],
    netinfodb: NetinfoDB,
    ip_to_domain: Dict[str, str] = {},
) -> Generator[TCPObservation, None, None]:
    if not tcp_connect:
        return

    for idx, res in enumerate(tcp_connect):
        yield TCPObservation.from_measurement(msmt, res, idx, ip_to_domain, netinfodb)


def network_events_until_connect(
    network_events: List[NetworkEvent],
) -> List[NetworkEvent]:
    ne_list = []
    for ne in network_events:
        if ne.operation == "connect":
            break
        ne_list.append(ne)
    return ne_list


def find_tls_handshake_network_events(
    tls_handshake: TLSHandshake, network_events: List[NetworkEvent]
) -> List[NetworkEvent]:
    current_event_window = []
    for idx, ne in enumerate(network_events):
        if ne.operation == "connect":
            current_event_window = []
        current_event_window.append(ne)
        # We identify the network_event for the given TLS handshake based on the
        # fact that the timestamp on tls_handshake_done event is the same as the
        # tls_handshake time
        if ne.operation == "tls_handshake_done" and ne.t == tls_handshake.t:
            current_event_window += network_events_until_connect(network_events[idx:])
            return current_event_window


class TLSObservation(Observation):
    db_table = "obs_tls"

    domain_name: str

    ip: Optional[str]
    port: Optional[int]

    ip_asn: Optional[int]
    ip_as_org_name: Optional[str]
    ip_as_cc: Optional[str]
    ip_cc: Optional[str]

    failure: Failure

    server_name: str
    tls_version: Optional[str]
    cipher_suite: Optional[str]

    is_certificate_valid: Optional[bool]

    end_entity_certificate_fingerprint: Optional[str]
    end_entity_certificate_subject: Optional[str]
    end_entity_certificate_subject_common_name: Optional[str]
    end_entity_certificate_issuer: Optional[str]
    end_entity_certificate_issuer_common_name: Optional[str]
    end_entity_certificate_san_list: List[str]
    end_entity_certificate_not_valid_after: Optional[datetime]
    end_entity_certificate_not_valid_before: Optional[datetime]
    certificate_chain_length: Optional[int]

    tls_handshake_read_count: Optional[int]
    tls_handshake_write_count: Optional[int]
    tls_handshake_read_bytes: Optional[float]
    tls_handshake_write_bytes: Optional[float]
    tls_handshake_last_operation: Optional[str]
    tls_handshake_time: Optional[float]

    @staticmethod
    def from_measurement(
        msmt: BaseMeasurement,
        tls_h: TLSHandshake,
        network_events: Optional[List[NetworkEvent]],
        idx: int,
        ip_to_domain: Dict[str, str],
        netinfodb: NetinfoDB,
    ) -> "TLSObservation":
        tso = TLSObservation()
        tso = set_base_observation_meta(tso, msmt, netinfodb)

        tso.observation_id = f"{tso.measurement_uid}{idx}"
        if tls_h.t:
            tso.timestamp += timedelta(seconds=tls_h.t)

        tso.server_name = tls_h.server_name
        tso.domain_name = tls_h.server_name
        tso.tls_version = tls_h.tls_version
        tso.cipher_suite = tls_h.cipher_suite

        tso.end_entity_certificate_san_list = []

        tso.failure = normalize_failure(tls_h.failure)
        if tls_h.no_tls_verify == False:
            if tso.failure in (
                "ssl_invalid_hostname",
                "ssl_unknown_authority",
                "ssl_invalid_certificate",
            ):
                tso.is_certificate_valid = False
            elif not tso.failure:
                tso.is_certificate_valid = True

        tls_network_events = find_tls_handshake_network_events(tls_h, network_events)
        if tls_network_events:
            p = urlsplit("//" + tls_network_events[0].address)
            tso.ip = p.hostname
            tso.port = p.port

            tso.domain_name = ip_to_domain.get(tso.ip, "")

            tso.tls_handshake_time = tls_network_events[-1].t - tls_network_events[0].t
            tso.tls_handshake_read_count = 0
            tso.tls_handshake_write_count = 0
            tso.tls_handshake_read_bytes = 0
            tso.tls_handshake_write_bytes = 0
            for ne in tls_network_events:
                if ne.operation == "write":
                    if ne.num_bytes:
                        tso.tls_handshake_write_count += 1
                        tso.tls_handshake_write_bytes += ne.num_bytes
                    tso.tls_handshake_last_operation = (
                        f"write_{tso.tls_handshake_write_count}"
                    )
                elif ne.operation == "read" and ne.num_bytes:
                    if ne.num_bytes:
                        tso.tls_handshake_read_count += 1
                        tso.tls_handshake_read_bytes += ne.num_bytes
                    tso.tls_handshake_last_operation = (
                        f"read_{tso.tls_handshake_read_count}"
                    )

        if tls_h.peer_certificates:
            tso.certificate_chain_length = len(tls_h.peer_certificates)
            cert_meta = get_certificate_meta(tls_h.peer_certificates[0])
            tso.end_entity_certificate_fingerprint = cert_meta.fingerprint
            tso.end_entity_certificate_subject = cert_meta.subject
            tso.end_entity_certificate_subject_common_name = (
                cert_meta.subject_common_name
            )
            tso.end_entity_certificate_issuer = cert_meta.issuer
            tso.end_entity_certificate_issuer_common_name = cert_meta.issuer_common_name
            tso.end_entity_certificate_not_valid_after = cert_meta.not_valid_after
            tso.end_entity_certificate_not_valid_before = cert_meta.not_valid_before
            tso.end_entity_certificate_san_list = cert_meta.san_list

        return tso


def make_tls_observations(
    msmt: BaseMeasurement,
    tls_handshakes: Optional[List[TLSHandshake]],
    network_events: Optional[List[NetworkEvent]],
    netinfodb: NetinfoDB,
    ip_to_domain: Dict[str, str] = {},
) -> Generator[TLSObservation, None, None]:
    if not tls_handshakes:
        return

    for idx, tls_h in enumerate(tls_handshakes):
        yield TLSObservation.from_measurement(
            msmt, tls_h, network_events, idx, ip_to_domain, netinfodb
        )
