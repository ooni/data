from base64 import b64decode
import hashlib
import abc
import logging

import dataclasses
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlsplit
from datetime import datetime, timedelta
from typing import (
    Callable,
    Optional,
    List,
    Tuple,
    Union,
    Dict,
)
from oonidata.dataformat import SIGNAL_PEM_STORE, DNSCheck, Tor

from oonidata.dataformat import (
    BaseMeasurement,
    DNSAnswer,
    DNSQuery,
    HTTPTransaction,
    Failure,
    NetworkEvent,
    Signal,
    TCPConnect,
    TLSHandshake,
    WebConnectivity,
)

from oonidata.datautils import (
    InvalidCertificateChain,
    TLSCertStore,
    get_first_http_header,
    get_first_http_header_str,
    get_html_meta_title,
    get_html_title,
    is_ipv4_bogon,
    is_ipv6_bogon,
    get_certificate_meta,
    removeprefix,
)
from oonidata.fingerprintdb import FingerprintDB
from oonidata.netinfo import NetinfoDB


log = logging.getLogger("oonidata.processing")


unknown_failure_map = (
    (
        "This is usually a temporary error during hostname resolution and means that the local server did not receive a response from an authoritative server",
        "dns_temporary_failure",
    ),
    (
        "Der angeforderte Name ist gültig, es wurden jedoch keine Daten des angeforderten Typs gefunden",
        "dns_temporary_failure",
    ),
    ("certificate has expired or is not yet valid", "ssl_invalid_certificate"),
)


def normalize_failure(failure: Failure):
    # TODO: implement a mapping between known unknowns to cleanup the data a bit
    if not failure:
        return failure

    for substring, new_failure in unknown_failure_map:
        if substring in failure:
            return new_failure
    return failure


@dataclass
class Observation(abc.ABC):
    __table_name__ = "obs"

    measurement_uid: str
    observation_id: str

    input: str
    report_id: str

    timestamp: datetime

    target: str

    probe_asn: int
    probe_cc: str

    probe_as_org_name: str
    probe_as_cc: str
    probe_as_name: str

    software_name: str
    software_version: str
    test_name: str
    test_version: str

    network_type: str
    platform: str
    origin: str

    resolver_ip: str
    resolver_asn: int
    resolver_cc: str
    resolver_as_org_name: str
    resolver_as_cc: str

    resolver_is_scrubbed: bool

    # This is the resolver metadata computed by the probe. Once we do some
    # quality control on them we might consolidate these into a single set of
    # fields.
    # If the resolver_is_scrubbed, we will be setting the resolver_* values to
    # those computed by the probe and resolver_ip will be the empty string.
    resolver_asn_probe: int
    resolver_as_org_name_probe: str

    bucket_date: str


def make_base_observation_meta(msmt: BaseMeasurement, netinfodb: NetinfoDB) -> dict:
    assert msmt.measurement_uid is not None
    probe_asn = int(msmt.probe_asn[len("AS") :])
    measurement_start_time = datetime.strptime(
        msmt.measurement_start_time, "%Y-%m-%d %H:%M:%S"
    )
    probe_as_info = netinfodb.lookup_asn(measurement_start_time, probe_asn)

    resolver_as_info = None
    resolver_ip = msmt.resolver_ip
    client_resolver = None
    resolver_is_scrubbed = False
    if msmt.test_keys and msmt.test_keys.client_resolver:
        client_resolver = msmt.test_keys.client_resolver

    if client_resolver == "[scrubbed]" or resolver_ip == "[scrubbed]":
        resolver_is_scrubbed = True

    resolver_ip = resolver_ip or client_resolver or ""
    resolver_cc = ""
    resolver_asn = 0
    resolver_as_org_name = ""
    resolver_as_cc = ""

    resolver_asn_probe = msmt.resolver_asn
    if resolver_asn_probe is None:
        resolver_asn_probe = 0
    else:
        resolver_asn_probe = int(resolver_asn_probe[2:])
    resolver_as_org_name_probe = msmt.resolver_network_name or ""
    if resolver_ip == "[scrubbed]":
        resolver_asn = resolver_asn_probe
        resolver_as_org_name = resolver_as_org_name_probe
        resolver_ip = ""

    if resolver_ip != "":
        resolver_as_info = netinfodb.lookup_ip(measurement_start_time, resolver_ip)
        if resolver_as_info:
            resolver_cc = resolver_as_info.cc
            resolver_asn = resolver_as_info.as_info.asn
            resolver_as_org_name = resolver_as_info.as_info.as_org_name
            resolver_as_cc = resolver_as_info.as_info.as_cc

    input_ = msmt.input
    if isinstance(input_, list):
        input_ = ":".join(input_)

    return dict(
        measurement_uid=msmt.measurement_uid,
        probe_asn=probe_asn,
        probe_cc=msmt.probe_cc,
        probe_as_org_name=probe_as_info.as_org_name if probe_as_info else "",
        probe_as_cc=probe_as_info.as_cc if probe_as_info else "",
        probe_as_name=probe_as_info.as_name if probe_as_info else "",
        report_id=msmt.report_id,
        input=input_,
        software_name=msmt.software_name,
        software_version=msmt.software_version,
        test_name=msmt.test_name,
        test_version=msmt.test_version,
        network_type=msmt.annotations.get("network_type", "unknown"),
        platform=msmt.annotations.get("platform", "unknown"),
        origin=msmt.annotations.get("origin", "unknown"),
        resolver_ip=resolver_ip,
        resolver_cc=resolver_cc,
        resolver_asn=resolver_asn,
        resolver_as_org_name=resolver_as_org_name,
        resolver_as_cc=resolver_as_cc,
        resolver_asn_probe=resolver_asn_probe,
        resolver_as_org_name_probe=resolver_as_org_name_probe,
        resolver_is_scrubbed=resolver_is_scrubbed,
        bucket_date="",
    )


def make_timestamp(msmt: BaseMeasurement, t: Optional[float] = None):
    timestamp = datetime.strptime(msmt.measurement_start_time, "%Y-%m-%d %H:%M:%S")
    if t:
        timestamp += timedelta(seconds=t)
    return timestamp


@dataclass
class NettestObservation(Observation):
    __table_name__ = "obs_nettest"

    test_runtime: float
    annotations: Dict[str, str]

    @staticmethod
    def from_measurement(
        msmt: BaseMeasurement,
        netinfodb: NetinfoDB,
    ) -> "NettestObservation":
        return NettestObservation(
            observation_id=f"{msmt.measurement_uid}_nettest",
            timestamp=make_timestamp(msmt),
            test_runtime=msmt.test_runtime,
            annotations=msmt.annotations,
            target="",
            **make_base_observation_meta(msmt, netinfodb),
        )


@dataclass
class HTTPObservation(Observation):
    __table_name__ = "obs_http"

    domain_name: str
    request_url: str

    network: str
    alpn: Optional[str]

    failure: Failure

    request_body_length: int
    # request_headers_list: Optional[List[Tuple[str, bytes]]]
    request_method: str

    response_fingerprints: List[str]

    ip: Optional[str] = None
    port: Optional[int] = None

    runtime: Optional[float] = None

    response_body_length: Optional[int] = None
    response_body_is_truncated: Optional[bool] = None
    response_body_sha1: Optional[str] = None
    response_body_title: Optional[str] = None
    response_body_meta_title: Optional[str] = None

    response_status_code: Optional[int] = None
    # response_headers_list: Optional[List[Tuple[str, bytes]]]
    response_header_location: Optional[bytes] = None
    response_header_server: Optional[bytes] = None
    request_redirect_from: Optional[str] = None
    request_body_is_truncated: Optional[bool] = None

    fingerprint_country_consistent: Optional[bool] = None
    response_matches_blockpage: bool = False
    response_matches_false_positive: bool = False

    transaction_id: Optional[int] = None

    @property
    def request_is_encrypted(self):
        return self.request_url.startswith("https://")

    @staticmethod
    def from_measurement(
        msmt: BaseMeasurement,
        netinfodb: NetinfoDB,
        idx: int,
        requests_list: Optional[List[HTTPTransaction]],
        http_transaction: HTTPTransaction,
        fingerprintdb: FingerprintDB,
        target: str = "",
    ) -> Optional["HTTPObservation"]:
        if not http_transaction.request:
            # This is a very malformed request, we don't consider it a valid
            # observation as we don't know what it's referring to.
            # XXX maybe log this somewhere
            return None

        network = (
            http_transaction.network or http_transaction.request.x_transport or "tcp"
        )
        # We uniform all observations to the new data format
        if network == "quic":
            network = "udp"

        parsed_url = urlparse(http_transaction.request.url)
        hrro = HTTPObservation(
            observation_id=f"{msmt.measurement_uid}_http_{idx}",
            request_url=http_transaction.request.url,
            domain_name=parsed_url.hostname or "",
            request_body_is_truncated=http_transaction.request.body_is_truncated,
            # hrro.request_headers_list = http_transaction.request.headers_list_bytes
            request_method=http_transaction.request.method or "",
            request_body_length=len(http_transaction.request.body_bytes)
            if http_transaction.request.body_bytes
            else 0,
            response_fingerprints=[],
            network=network,
            alpn=http_transaction.alpn,
            failure=normalize_failure(http_transaction.failure),
            timestamp=make_timestamp(msmt, http_transaction.t),
            target=target,
            transaction_id=http_transaction.transaction_id,
            **make_base_observation_meta(msmt, netinfodb),
        )

        if http_transaction.address:
            p = urlsplit("//" + http_transaction.address)
            hrro.ip = p.hostname
            hrro.port = p.port

        if http_transaction.t is not None and http_transaction.t0 is not None:
            hrro.runtime = http_transaction.t - http_transaction.t0

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
            "location", http_transaction.response.headers_list_bytes or []
        )
        hrro.response_header_server = get_first_http_header(
            "server", http_transaction.response.headers_list_bytes or []
        )

        try:
            # We add type: ignore in here, because requests_lists is an optional
            # field and the fact it might not be defined is handled by the
            # except block below, yet pylint is not able to figure that out.
            # TODO: maybe refactor this handle it better by checking if these are defined
            prev_request = requests_list[idx + 1]  # type: ignore
            prev_location = get_first_http_header_str(
                "location", prev_request.response.headers_list_str or []  # type: ignore
            )
            if prev_location == hrro.request_url:
                hrro.request_redirect_from = prev_request.request.url  # type: ignore
        except (IndexError, UnicodeDecodeError, AttributeError):
            pass
        return hrro


def make_http_observations(
    msmt: BaseMeasurement,
    requests_list: Optional[List[HTTPTransaction]],
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
    target: str = "",
) -> List[HTTPObservation]:
    obs_list = []
    if not requests_list:
        return obs_list

    for idx, http_transaction in enumerate(requests_list):
        httpo = HTTPObservation.from_measurement(
            msmt, netinfodb, idx, requests_list, http_transaction, fingerprintdb, target
        )
        if httpo:
            obs_list.append(httpo)
    return obs_list


@dataclass
class DNSObservation(Observation):
    __table_name__ = "obs_dns"

    domain_name: str

    query_type: str
    failure: Failure
    engine: Optional[str]
    engine_resolver_address: Optional[str]

    answer_type: Optional[str] = None
    answer: Optional[str] = None
    answer_asn: Optional[int] = None
    answer_as_org_name: Optional[str] = None
    answer_as_cc: Optional[str] = None
    answer_cc: Optional[str] = None
    answer_is_bogon: Optional[bool] = None

    fingerprint_id: Optional[str] = None
    fingerprint_country_consistent: Optional[bool] = None

    is_tls_consistent: Optional[bool] = None

    transaction_id: Optional[int] = None

    @staticmethod
    def from_measurement(
        msmt: BaseMeasurement,
        query: DNSQuery,
        answer: Optional[DNSAnswer],
        idx: int,
        fingerprintdb: FingerprintDB,
        netinfodb: NetinfoDB,
        target: str = "",
    ) -> "DNSObservation":
        dnso = DNSObservation(
            observation_id=f"{msmt.measurement_uid}_dns_{idx}",
            engine=query.engine,
            engine_resolver_address=query.resolver_address,
            query_type=query.query_type,
            domain_name=query.hostname,
            failure=normalize_failure(query.failure),
            timestamp=make_timestamp(msmt, query.t),
            target=target,
            transaction_id=query.transaction_id,
            **make_base_observation_meta(msmt, netinfodb),
        )

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
            # This is guaranteed to be the correct type since we set it's value
            # based on answer.ipv4 or answer.ipv6 being set in the previous
            # blocks
            answer_meta = netinfodb.lookup_ip(dnso.timestamp, dnso.answer)  # type: ignore
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
    target: str = "",
) -> List[DNSObservation]:
    obs_dns = []
    if not queries:
        return obs_dns

    idx = 0
    for query in queries:
        answer_list = query.answers
        if not answer_list:
            answer_list = [None]
        for answer in answer_list:
            obs_dns.append(
                DNSObservation.from_measurement(
                    msmt, query, answer, idx, fingerprintdb, netinfodb, target
                )
            )
            idx += 1

    return obs_dns


@dataclass
class TCPObservation(Observation):
    __table_name__ = "obs_tcp"

    domain_name: str

    ip: str
    port: int

    failure: Failure

    ip_asn: Optional[int] = None
    ip_as_org_name: Optional[str] = None
    ip_as_cc: Optional[str] = None
    ip_cc: Optional[str] = None

    transaction_id: Optional[int] = None

    @staticmethod
    def from_measurement(
        msmt: BaseMeasurement,
        res: TCPConnect,
        idx: int,
        ip_to_domain: Dict[str, str],
        netinfodb: NetinfoDB,
        target: str,
    ) -> "TCPObservation":
        tcpo = TCPObservation(
            observation_id=f"{msmt.measurement_uid}_tcp_{idx}",
            timestamp=make_timestamp(msmt, res.t),
            ip=res.ip,
            port=res.port,
            failure=normalize_failure(res.status.failure),
            domain_name=ip_to_domain.get(res.ip, ""),
            target=target,
            transaction_id=res.transaction_id,
            **make_base_observation_meta(msmt, netinfodb),
        )

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
    target: str = "",
) -> List[TCPObservation]:
    obs_tcp = []
    if not tcp_connect:
        return obs_tcp

    for idx, res in enumerate(tcp_connect):
        obs_tcp.append(
            TCPObservation.from_measurement(
                msmt, res, idx, ip_to_domain, netinfodb, target
            )
        )
    return obs_tcp


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
    tls_handshake: TLSHandshake,
    src_idx: int,
    network_events: Optional[List[NetworkEvent]],
) -> Optional[List[NetworkEvent]]:
    if not network_events:
        return None

    all_event_windows = []
    matched_event_windows = []

    current_event_window = []
    for idx, ne in enumerate(network_events):
        if ne.operation == "connect":
            current_event_window = []
        current_event_window.append(ne)
        if ne.operation == "tls_handshake_done":
            # We identify the network_event for the given TLS handshake based on the
            # fact that the timestamp on tls_handshake_done event is the same as the
            # tls_handshake time.
            # In case of duplicates we also look for the index of the tls
            # handshake inside of the list of event windows.
            if ne.t == tls_handshake.t:
                matched_event_windows.append(len(all_event_windows))
            current_event_window += network_events_until_connect(network_events[idx:])
            all_event_windows.append(current_event_window)

    # We do this because there are cases such as
    # https://explorer.ooni.org/measurement/20221114T002124Z_webconnectivity_BR_27699_n1_knqvcofoEIxHMpzj?input=https://cdt.org/
    # where there are conflicts in the end time of the event window, so in order
    # to handle that we assume that the relative ordering of the network_events
    # is correct.
    # If that doesn't work, then we just bail.
    if len(matched_event_windows) == 1:
        return all_event_windows[matched_event_windows[0]]
    elif len(matched_event_windows) > 1 and src_idx in matched_event_windows:
        return all_event_windows[src_idx]

    return None


@dataclass
class TLSObservation(Observation):
    __table_name__ = "obs_tls"

    domain_name: str

    failure: Failure

    server_name: str
    version: str
    cipher_suite: str

    ip: Optional[str] = None
    port: Optional[int] = None

    ip_asn: Optional[int] = None
    ip_as_org_name: Optional[str] = None
    ip_as_cc: Optional[str] = None
    ip_cc: Optional[str] = None

    is_certificate_valid: Optional[bool] = None

    end_entity_certificate_fingerprint: Optional[str] = None
    end_entity_certificate_subject: Optional[str] = None
    end_entity_certificate_subject_common_name: Optional[str] = None
    end_entity_certificate_issuer: Optional[str] = None
    end_entity_certificate_issuer_common_name: Optional[str] = None
    end_entity_certificate_san_list: List[str] = field(default_factory=list)
    end_entity_certificate_not_valid_after: Optional[datetime] = None
    end_entity_certificate_not_valid_before: Optional[datetime] = None
    peer_certificates: List[bytes] = field(default_factory=list)
    certificate_chain_length: Optional[int] = None

    handshake_read_count: Optional[int] = None
    handshake_write_count: Optional[int] = None
    handshake_read_bytes: Optional[float] = None
    handshake_write_bytes: Optional[float] = None
    handshake_last_operation: Optional[str] = None
    handshake_time: Optional[float] = None

    transaction_id: Optional[int] = None

    @staticmethod
    def from_measurement(
        msmt: BaseMeasurement,
        tls_h: TLSHandshake,
        network_events: Optional[List[NetworkEvent]],
        idx: int,
        ip_to_domain: Dict[str, str],
        netinfodb: NetinfoDB,
        cert_store: Optional[TLSCertStore] = None,
        validate_domain: Callable[[str, str, List[str]], bool] = lambda x, y, z: True,
        target: str = "",
    ) -> "TLSObservation":
        tlso = TLSObservation(
            observation_id=f"{msmt.measurement_uid}_tls_{idx}",
            timestamp=make_timestamp(msmt, tls_h.t),
            server_name=tls_h.server_name if tls_h.server_name else "",
            domain_name=tls_h.server_name if tls_h.server_name else "",
            version=tls_h.tls_version if tls_h.tls_version else "",
            cipher_suite=tls_h.cipher_suite if tls_h.cipher_suite else "",
            end_entity_certificate_san_list=[],
            failure=normalize_failure(tls_h.failure),
            target=target,
            transaction_id=tls_h.transaction_id,
            **make_base_observation_meta(msmt, netinfodb),
        )

        if tls_h.address:
            p = urlsplit("//" + tls_h.address)
            tlso.ip = p.hostname
            tlso.port = p.port

        tls_network_events = find_tls_handshake_network_events(
            tls_h, idx, network_events
        )
        if tls_network_events:
            if tls_network_events[0].address:
                p = urlsplit("//" + tls_network_events[0].address)
                tlso.ip = p.hostname
                tlso.port = p.port
                if tlso.ip and tlso.ip in ip_to_domain:
                    tlso.domain_name = ip_to_domain[tlso.ip]

            tlso.handshake_time = tls_network_events[-1].t - tls_network_events[0].t
            tlso.handshake_read_count = 0
            tlso.handshake_write_count = 0
            tlso.handshake_read_bytes = 0
            tlso.handshake_write_bytes = 0
            for ne in tls_network_events:
                if ne.operation == "write":
                    if ne.num_bytes:
                        tlso.handshake_write_count += 1
                        tlso.handshake_write_bytes += ne.num_bytes
                    tlso.handshake_last_operation = (
                        f"write_{tlso.handshake_write_count}"
                    )
                elif ne.operation == "read" and ne.num_bytes:
                    if ne.num_bytes:
                        tlso.handshake_read_count += 1
                        tlso.handshake_read_bytes += ne.num_bytes
                    tlso.handshake_last_operation = f"read_{tlso.handshake_read_count}"

        if tls_h.peer_certificates:
            try:
                tlso.peer_certificates = list(
                    map(lambda c: b64decode(c.data), tls_h.peer_certificates)
                )
            except Exception:
                log.error("failed to decode peer_certificates")

            tlso.certificate_chain_length = len(tls_h.peer_certificates)
            try:
                cert_meta = get_certificate_meta(tls_h.peer_certificates[0])
                tlso.end_entity_certificate_fingerprint = cert_meta.fingerprint
                tlso.end_entity_certificate_subject = cert_meta.subject
                tlso.end_entity_certificate_subject_common_name = (
                    cert_meta.subject_common_name
                )
                tlso.end_entity_certificate_issuer = cert_meta.issuer
                tlso.end_entity_certificate_issuer_common_name = (
                    cert_meta.issuer_common_name
                )
                tlso.end_entity_certificate_not_valid_after = cert_meta.not_valid_after
                tlso.end_entity_certificate_not_valid_before = (
                    cert_meta.not_valid_before
                )
                tlso.end_entity_certificate_san_list = cert_meta.san_list
            except Exception as exc:
                log.error(exc)
                log.error(
                    f"Failed to extract certificate meta for {msmt.measurement_uid}"
                )

        if cert_store and tlso.peer_certificates:
            try:
                cn, san_list = cert_store.validate_cert_chain(
                    tlso.timestamp, tlso.peer_certificates
                )
                tlso.is_certificate_valid = validate_domain(
                    tlso.server_name, cn, san_list
                )
            except InvalidCertificateChain:
                tlso.is_certificate_valid = False

        elif tls_h.no_tls_verify == False:
            if tlso.failure in (
                "ssl_invalid_hostname",
                "ssl_unknown_authority",
                "ssl_invalid_certificate",
            ):
                tlso.is_certificate_valid = False
            elif not tlso.failure:
                tlso.is_certificate_valid = True

        return tlso


def make_tls_observations(
    msmt: BaseMeasurement,
    tls_handshakes: Optional[List[TLSHandshake]],
    network_events: Optional[List[NetworkEvent]],
    netinfodb: NetinfoDB,
    ip_to_domain: Dict[str, str] = {},
    cert_store: Optional[TLSCertStore] = None,
    validate_domain: Callable[[str, str, List[str]], bool] = lambda x, y, z: True,
    target: str = "",
) -> List[TLSObservation]:
    obs_tls = []
    if not tls_handshakes:
        return obs_tls

    for idx, tls_h in enumerate(tls_handshakes):
        obs_tls.append(
            TLSObservation.from_measurement(
                msmt,
                tls_h,
                network_events,
                idx,
                ip_to_domain,
                netinfodb,
                cert_store,
                validate_domain,
                target,
            )
        )
    return obs_tls


@dataclass
class ChainedObservation(Observation):
    __table_name__ = "obs_chained"

    domain_name: Optional[str] = None

    transaction_id: Optional[int] = None

    ip: Optional[str] = None
    port: Optional[int] = None

    ip_asn: Optional[int] = None
    ip_as_org_name: Optional[str] = None
    ip_as_cc: Optional[str] = None
    ip_cc: Optional[str] = None

    # DNS related observation
    dns_query_type: Optional[str] = None
    dns_failure: Failure = None
    dns_engine: Optional[str] = None
    dns_engine_resolver_address: Optional[str] = None

    dns_answer_type: Optional[str] = None
    dns_answer: Optional[str] = None
    dns_answer_asn: Optional[int] = None
    dns_answer_as_org_name: Optional[str] = None
    dns_answer_as_cc: Optional[str] = None
    dns_answer_cc: Optional[str] = None
    dns_answer_is_bogon: Optional[bool] = None

    dns_fingerprint_id: Optional[str] = None
    dns_fingerprint_country_consistent: Optional[bool] = None

    dns_is_tls_consistent: Optional[bool] = None

    # TCP related observation
    tcp_failure: Optional[Failure] = None

    # TLS related observation
    tls_failure: Optional[Failure] = None

    tls_server_name: Optional[str] = None
    tls_version: Optional[str] = None
    tls_cipher_suite: Optional[str] = None
    tls_is_certificate_valid: Optional[bool] = None

    tls_end_entity_certificate_fingerprint: Optional[str] = None
    tls_end_entity_certificate_subject: Optional[str] = None
    tls_end_entity_certificate_subject_common_name: Optional[str] = None
    tls_end_entity_certificate_issuer: Optional[str] = None
    tls_end_entity_certificate_issuer_common_name: Optional[str] = None
    tls_end_entity_certificate_san_list: List[str] = field(default_factory=list)
    tls_end_entity_certificate_not_valid_after: Optional[datetime] = None
    tls_end_entity_certificate_not_valid_before: Optional[datetime] = None
    tls_certificate_chain_length: Optional[int] = None

    tls_handshake_read_count: Optional[int] = None
    tls_handshake_write_count: Optional[int] = None
    tls_handshake_read_bytes: Optional[float] = None
    tls_handshake_write_bytes: Optional[float] = None
    tls_handshake_last_operation: Optional[str] = None
    tls_handshake_time: Optional[float] = None

    # HTTP related observation
    http_request_url: Optional[str] = None

    http_network: Optional[str] = None
    http_alpn: Optional[str] = None

    http_failure: Failure = None

    http_request_body_length: Optional[int] = None
    http_request_method: Optional[str] = None

    http_response_fingerprints: List[str] = field(default_factory=list)

    http_runtime: Optional[float] = None

    http_response_body_length: Optional[int] = None
    http_response_body_is_truncated: Optional[bool] = None
    http_response_body_sha1: Optional[str] = None
    http_response_body_title: Optional[str] = None
    http_response_body_meta_title: Optional[str] = None

    http_response_status_code: Optional[int] = None
    http_response_header_location: Optional[bytes] = None
    http_response_header_server: Optional[bytes] = None
    http_request_redirect_from: Optional[str] = None
    http_request_body_is_truncated: Optional[bool] = None

    http_fingerprint_country_consistent: Optional[bool] = None
    http_response_matches_blockpage: bool = False
    http_response_matches_false_positive: bool = False


def maybe_set_chained_fields(
    src_obs: Union[
        DNSObservation, TCPObservation, TLSObservation, HTTPObservation, None
    ],
    chained: ChainedObservation,
    prefix: str,
):
    if not src_obs:
        return
    for f in dataclasses.fields(chained):
        if f.name.startswith(prefix):
            src_field_name = removeprefix(f.name, prefix)
            setattr(chained, f.name, getattr(src_obs, src_field_name))


def make_chained_observation(
    dns_o: Optional[DNSObservation] = None,
    tcp_o: Optional[TCPObservation] = None,
    tls_o: Optional[TLSObservation] = None,
    http_o: Optional[HTTPObservation] = None,
) -> ChainedObservation:
    assert (
        dns_o or tcp_o or tls_o or http_o
    ), "dns_o or tcp_o or tls_o or http_o should be not null"
    base_o = dns_o or tcp_o or tls_o or http_o

    # XXX This is terrible, but doing it better will probably require some
    # smarter refactoring. Need to come up with a better was of handling this.
    base_dict = dataclasses.asdict(base_o)
    chained_dict = {}
    for field in dataclasses.fields(Observation):
        chained_dict[field.name] = base_dict[field.name]

    chained = ChainedObservation(**chained_dict)
    chained.ip = (
        (dns_o and dns_o.answer)
        or (tcp_o and tcp_o.ip)
        or (tls_o and tls_o.ip)
        or (http_o and http_o.ip)
    )
    chained.port = (
        (tcp_o and tcp_o.port) or (tls_o and tls_o.port) or (http_o and http_o.port)
    )
    chained.ip_asn = (tcp_o and tcp_o.ip_asn) or (tls_o and tls_o.ip_asn)
    chained.ip_as_org_name = (tcp_o and tcp_o.ip_as_org_name) or (
        tls_o and tls_o.ip_as_org_name
    )
    chained.ip_as_cc = (tcp_o and tcp_o.ip_as_cc) or (tls_o and tls_o.ip_as_cc)
    chained.ip_cc = (tcp_o and tcp_o.ip_cc) or (tls_o and tls_o.ip_cc)
    chained.transaction_id = (
        (dns_o and dns_o.transaction_id)
        or (tcp_o and tcp_o.transaction_id)
        or (tls_o and tls_o.transaction_id)
        or (http_o and http_o.transaction_id)
    )

    maybe_set_chained_fields(dns_o, chained, "dns_")
    maybe_set_chained_fields(tcp_o, chained, "tcp_")
    maybe_set_chained_fields(tls_o, chained, "tls_")
    maybe_set_chained_fields(http_o, chained, "http_")
    return chained


def find_observation_by_transaction_id(
    transaction_id: Optional[int],
    obs_list: Union[List[TCPObservation], List[TLSObservation], List[HTTPObservation]],
) -> Optional[Union[TCPObservation, TLSObservation, HTTPObservation]]:
    found_obs = None
    if not transaction_id:
        return found_obs
    for obs in obs_list:
        if obs.transaction_id == transaction_id:
            # XXX maybe in the future we can remove this
            assert found_obs is None, f"{obs} with duplicate transaction_id"
            found_obs = obs
    return found_obs


def find_observation_by_ip(
    ip: Optional[str],
    obs_list: Union[List[TCPObservation], List[TLSObservation], List[HTTPObservation]],
) -> Optional[Union[TCPObservation, TLSObservation, HTTPObservation]]:
    found_obs = None
    for obs in obs_list:
        if ip == obs.ip:
            # XXX maybe in the future we can remove this
            assert found_obs is None, f"{obs} with duplicate ip:port combo"
            found_obs = obs
    return found_obs


def find_relevant_observations(
    transaction_id: Optional[int],
    ip: Optional[str],
    tcp_observations: Optional[List[TCPObservation]] = None,
    tls_observations: Optional[List[TLSObservation]] = None,
    http_observations: Optional[List[HTTPObservation]] = None,
) -> Tuple[
    Optional[TCPObservation], Optional[TLSObservation], Optional[HTTPObservation]
]:
    found_tcp_obs = None
    found_tls_obs = None
    found_http_obs = None
    if tcp_observations:
        found_tcp_obs = find_observation_by_transaction_id(
            transaction_id, tcp_observations
        )

    if tls_observations:
        found_tls_obs = find_observation_by_transaction_id(
            transaction_id, tls_observations
        )
    if http_observations:
        found_http_obs = find_observation_by_transaction_id(
            transaction_id, http_observations
        )

    if not found_tcp_obs and tcp_observations and ip:
        found_tcp_obs = find_observation_by_ip(ip, tcp_observations)
    if not found_tls_obs and tls_observations and ip:
        found_tls_obs = find_observation_by_ip(ip, tls_observations)
    if not found_http_obs and http_observations and ip:
        found_http_obs = find_observation_by_ip(ip, http_observations)

    assert found_tls_obs is None or isinstance(found_tls_obs, TLSObservation)
    assert found_tcp_obs is None or isinstance(found_tcp_obs, TCPObservation)
    assert found_http_obs is None or isinstance(found_http_obs, HTTPObservation)

    return found_tcp_obs, found_tls_obs, found_http_obs


def consume_chained_observations(
    dns_observations: List[DNSObservation],
    tcp_observations: List[TCPObservation],
    tls_observations: List[TLSObservation],
    http_observations: List[HTTPObservation],
) -> List[ChainedObservation]:
    obs_chain = []
    # TODO: surely there is some way to refactor this into a better pattern
    for dns_o in dns_observations:
        tcp_o, tls_o, http_o = find_relevant_observations(
            transaction_id=dns_o.transaction_id,
            ip=dns_o.answer,
            tcp_observations=tcp_observations,
            tls_observations=tls_observations,
            http_observations=http_observations,
        )
        obs_chain.append(
            make_chained_observation(
                dns_o=dns_o, tcp_o=tcp_o, tls_o=tls_o, http_o=http_o
            )
        )
        if tcp_o:
            tcp_observations.remove(tcp_o)
        if tls_o:
            tls_observations.remove(tls_o)
        if http_o:
            http_observations.remove(http_o)

    for tcp_o in tcp_observations:
        _, tls_o, http_o = find_relevant_observations(
            transaction_id=tcp_o.transaction_id,
            ip=tcp_o.ip,
            tls_observations=tls_observations,
            http_observations=http_observations,
        )
        if tls_o:
            tls_observations.remove(tls_o)
        if http_o:
            http_observations.remove(http_o)
        obs_chain.append(
            make_chained_observation(tcp_o=tcp_o, tls_o=tls_o, http_o=http_o)
        )

    for tls_o in tls_observations:
        _, _, http_o = find_relevant_observations(
            transaction_id=tls_o.transaction_id,
            ip=tls_o.ip,
            http_observations=http_observations,
        )
        if http_o:
            http_observations.remove(http_o)
        obs_chain.append(make_chained_observation(tls_o=tls_o, http_o=http_o))

    for http_o in http_observations:
        obs_chain.append(make_chained_observation(http_o=http_o))

    return obs_chain


def make_ip_to_domain(dns_observations: List[DNSObservation]) -> Dict[str, str]:
    ip_to_domain = {}
    for obs in dns_observations:
        # TODO: do we want to filter out also CNAMEs?
        if not obs.answer:
            continue
        # TODO: this is only really valid for web_connectivity and even there it
        # only works if there isn't a redirect chain with domains that map to
        # different domains.
        # What we should do is make this into a list and then figure out which
        # is the relevant domain for a particular resolution by looking at other data.
        # Better yet, this should be marked inside of the measurement itself.
        # TODO(sbs): what happens in the engine if I encounter in a redirect chain something like:
        # https://example.com/ -> https://www.example.com/ where both
        # www.example.com and example.com map to the same IP 1.2.3.4?
        # Will we record perform two tcp_connect measurements or only one?
        # If it's two we need to tell which one is pertaining to one or the other.
        # If it's one, then we need to make changes in the base dataformat so
        # that we can express that a single tcp_connect experiment is pertaining
        # to two different domains.
        if obs.answer in ip_to_domain:
            log.error(
                f"multiple resolutions for the same IP {obs.answer}:{obs.domain_name}"
            )
        ip_to_domain[obs.answer] = obs.domain_name
    return ip_to_domain


def make_web_connectivity_observations(
    msmt: WebConnectivity,
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
    target: str = "",
) -> Tuple[
    List[DNSObservation],
    List[TCPObservation],
    List[TLSObservation],
    List[HTTPObservation],
]:
    http_observations = make_http_observations(
        msmt, msmt.test_keys.requests, fingerprintdb, netinfodb, target
    )

    dns_observations = make_dns_observations(
        msmt, msmt.test_keys.queries, fingerprintdb, netinfodb
    )
    ip_to_domain = make_ip_to_domain(dns_observations)
    tcp_observations = make_tcp_observations(
        msmt, msmt.test_keys.tcp_connect, netinfodb, ip_to_domain
    )

    tls_observations = make_tls_observations(
        msmt,
        msmt.test_keys.tls_handshakes,
        msmt.test_keys.network_events,
        netinfodb,
        ip_to_domain,
    )

    # Here we take dns measurements and compare them to what we see in the tls
    # data and check for TLS consistency.
    tls_valid_ip_to_domain = {}
    for obs in filter(
        lambda o: o.ip and o.domain_name,
        tls_observations,
    ):
        tls_valid_ip_to_domain[obs.ip] = tls_valid_ip_to_domain.get(obs.ip, {})
        tls_valid_ip_to_domain[obs.ip][obs.domain_name] = obs.is_certificate_valid
    enriched_dns_observations = []
    for dns_obs in dns_observations:
        if dns_obs.answer:
            valid_domains = tls_valid_ip_to_domain.get(dns_obs.answer, {})
            dns_obs.is_tls_consistent = valid_domains.get(dns_obs.domain_name, None)
        enriched_dns_observations.append(dns_obs)

    return (
        enriched_dns_observations,
        tcp_observations,
        tls_observations,
        http_observations,
    )


def make_signal_observations(
    msmt: Signal, fingerprintdb: FingerprintDB, netinfodb: NetinfoDB
) -> Tuple[
    List[DNSObservation],
    List[TCPObservation],
    List[TLSObservation],
    List[HTTPObservation],
]:
    cert_store = TLSCertStore(SIGNAL_PEM_STORE)
    http_observations = make_http_observations(
        msmt, msmt.test_keys.requests, fingerprintdb, netinfodb
    )

    dns_observations = make_dns_observations(
        msmt, msmt.test_keys.queries, fingerprintdb, netinfodb
    )

    ip_to_domain = make_ip_to_domain(dns_observations)
    tcp_observations = make_tcp_observations(
        msmt, msmt.test_keys.tcp_connect, netinfodb, ip_to_domain
    )

    tls_observations = list(
        make_tls_observations(
            msmt,
            msmt.test_keys.tls_handshakes,
            msmt.test_keys.network_events,
            netinfodb,
            ip_to_domain,
            cert_store,
        )
    )

    # Because we are using certificate pinning for Signal, if we got a
    # successful TLS handshake with some endpoint, it's bound to be TLS
    # consistent.
    tls_consistency_map = {}
    for tls_obs in tls_observations:
        if tls_obs.ip and tls_obs.domain_name:
            tls_consistency_map[tls_obs.ip] = tls_obs.is_certificate_valid

    enriched_dns_observations = []
    for dns_obs in dns_observations:
        if dns_obs.answer:
            dns_obs.is_tls_consistent = tls_consistency_map.get(dns_obs.answer, None)
        enriched_dns_observations.append(dns_obs)

    return (
        enriched_dns_observations,
        tcp_observations,
        tls_observations,
        http_observations,
    )


def make_dnscheck_observations(
    msmt: DNSCheck,
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
) -> Tuple[
    List[DNSObservation],
    List[TCPObservation],
    List[TLSObservation],
    List[HTTPObservation],
]:
    dns_observations = []
    http_observations = []
    tcp_observations = []
    tls_observations = []

    ip_to_domain = {}
    if msmt.test_keys.bootstrap:
        dns_observations += make_dns_observations(
            msmt, msmt.test_keys.bootstrap.queries, fingerprintdb, netinfodb
        )
        ip_to_domain = make_ip_to_domain(dns_observations)

    lookup_map = msmt.test_keys.lookups or {}
    for lookup in lookup_map.values():
        dns_observations += make_dns_observations(
            msmt, lookup.queries, fingerprintdb, netinfodb
        )

        http_observations += make_http_observations(
            msmt, lookup.requests, fingerprintdb, netinfodb
        )

        tcp_observations += make_tcp_observations(
            msmt, lookup.tcp_connect, netinfodb, ip_to_domain
        )

        tls_observations += make_tls_observations(
            msmt, lookup.tls_handshakes, lookup.network_events, netinfodb, ip_to_domain
        )

    return dns_observations, tcp_observations, tls_observations, http_observations


def make_tor_observations(
    msmt: Tor,
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
) -> Tuple[
    List[DNSObservation],
    List[TCPObservation],
    List[TLSObservation],
    List[HTTPObservation],
]:
    dns_observations = []
    http_observations = []
    tcp_observations = []
    tls_observations = []

    ip_to_domain = {}
    for target_id, target_msmt in msmt.test_keys.targets.items():
        http_observations += make_http_observations(
            msmt, target_msmt.requests, fingerprintdb, netinfodb, target=target_id
        )
        dns_observations += make_dns_observations(
            msmt, target_msmt.queries, fingerprintdb, netinfodb, target=target_id
        )
        tcp_observations += make_tcp_observations(
            msmt, target_msmt.tcp_connect, netinfodb, ip_to_domain, target=target_id
        )
        tls_observations += make_tls_observations(
            msmt,
            target_msmt.tls_handshakes,
            target_msmt.network_events,
            netinfodb,
            ip_to_domain,
        )

    return dns_observations, tcp_observations, tls_observations, http_observations
