from base64 import b64decode
import hashlib
import ipaddress
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
)

from tabulate import tabulate

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
    is_ip_bogon,
    get_certificate_meta,
    removeprefix,
)
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


def maybe_elipse(s, max_len=16):
    if isinstance(s, str) and len(s) > max_len:
        return s[:max_len] + "…"
    return s


def print_nice(obs):
    rows = []
    meta_fields = [f.name for f in dataclasses.fields(MeasurementMeta)]
    headers = [f.name for f in dataclasses.fields(obs[0])]
    headers = list(filter(lambda k: k not in meta_fields, headers))
    for o in obs:
        rows.append([maybe_elipse(getattr(o, k)) for k in headers])
    headers = [maybe_elipse(h, 5) for h in headers]
    print(tabulate(rows, headers=headers))


@dataclass
class MeasurementMeta:
    __table_name__ = "obs_generic"

    measurement_uid: str

    input: Optional[str]
    report_id: str

    measurement_start_time: datetime

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


def make_measurement_meta(
    msmt: BaseMeasurement, netinfodb: NetinfoDB
) -> MeasurementMeta:
    assert msmt.measurement_uid is not None
    probe_asn = int(msmt.probe_asn[len("AS") :])
    measurement_start_time = datetime.strptime(
        msmt.measurement_start_time, "%Y-%m-%d %H:%M:%S"
    )
    probe_as_info = netinfodb.lookup_asn(measurement_start_time, probe_asn)

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

    return MeasurementMeta(
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
        measurement_start_time=measurement_start_time,
    )


def make_timestamp(msmt: BaseMeasurement, t: Optional[float] = None):
    timestamp = datetime.strptime(msmt.measurement_start_time, "%Y-%m-%d %H:%M:%S")
    if t:
        timestamp += timedelta(seconds=t)
    return timestamp


@dataclass
class HTTPObservation:
    timestamp: datetime

    hostname: str
    request_url: str

    network: str
    alpn: Optional[str]

    failure: Failure

    request_body_length: int
    request_method: str
    request_headers_list: Optional[List[Tuple[str, bytes]]] = field(
        default_factory=list
    )

    ip: Optional[str] = None
    port: Optional[int] = None

    runtime: Optional[float] = None

    response_body_length: Optional[int] = None
    response_body_is_truncated: Optional[bool] = None
    response_body_sha1: Optional[str] = None
    response_body_bytes: Optional[bytes] = None

    response_status_code: Optional[int] = None
    response_headers_list: Optional[List[Tuple[str, bytes]]] = field(
        default_factory=list
    )
    response_header_location: Optional[bytes] = None
    response_header_server: Optional[bytes] = None
    request_redirect_from: Optional[str] = None
    request_body_is_truncated: Optional[bool] = None

    transaction_id: Optional[int] = None

    @property
    def request_is_encrypted(self):
        return self.request_url.startswith("https://")

    @staticmethod
    def from_measurement(
        msmt: BaseMeasurement,
        requests_list: List[HTTPTransaction],
        idx: int,
        http_transaction: HTTPTransaction,
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
            request_url=http_transaction.request.url,
            hostname=parsed_url.hostname or "",
            request_body_is_truncated=http_transaction.request.body_is_truncated,
            request_headers_list=http_transaction.request.headers_list_bytes,
            request_method=http_transaction.request.method or "",
            request_body_length=len(http_transaction.request.body_bytes)
            if http_transaction.request.body_bytes
            else 0,
            network=network,
            alpn=http_transaction.alpn,
            failure=normalize_failure(http_transaction.failure),
            timestamp=make_timestamp(msmt, http_transaction.t),
            transaction_id=http_transaction.transaction_id,
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

        if http_transaction.response.body_bytes:
            hrro.response_body_length = len(http_transaction.response.body_bytes)
            hrro.response_body_sha1 = hashlib.sha1(
                http_transaction.response.body_bytes
            ).hexdigest()
            hrro.response_body_bytes = http_transaction.response.body_bytes

        hrro.response_status_code = http_transaction.response.code
        hrro.response_headers_list = http_transaction.response.headers_list_bytes

        hrro.response_header_location = get_first_http_header(
            "location", http_transaction.response.headers_list_bytes or []
        )
        hrro.response_header_server = get_first_http_header(
            "server", http_transaction.response.headers_list_bytes or []
        )

        try:
            prev_request = requests_list[idx + 1]
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
) -> List[HTTPObservation]:
    obs_list = []
    if not requests_list:
        return obs_list

    for idx, http_transaction in enumerate(requests_list):
        httpo = HTTPObservation.from_measurement(
            msmt=msmt,
            idx=idx,
            requests_list=requests_list,
            http_transaction=http_transaction,
        )
        if httpo:
            obs_list.append(httpo)
    return obs_list


@dataclass
class DNSObservation:
    timestamp: datetime

    hostname: str

    query_type: str
    failure: Failure
    engine: Optional[str]
    engine_resolver_address: Optional[str]

    answer_type: Optional[str] = None
    answer: Optional[str] = None
    answer_asn: Optional[int] = None
    answer_as_org_name: Optional[str] = None

    transaction_id: Optional[int] = None

    @staticmethod
    def from_measurement(
        msmt: BaseMeasurement,
        query: DNSQuery,
        answer: Optional[DNSAnswer],
    ) -> "DNSObservation":
        dnso = DNSObservation(
            engine=query.engine,
            engine_resolver_address=query.resolver_address,
            query_type=query.query_type,
            hostname=query.hostname,
            failure=normalize_failure(query.failure),
            timestamp=make_timestamp(msmt, query.t),
            transaction_id=query.transaction_id,
        )

        if not answer:
            return dnso

        dnso.answer_type = answer.answer_type
        if answer.ipv4:
            dnso.answer = answer.ipv4
        elif answer.ipv6:
            dnso.answer = answer.ipv6
        elif answer.hostname:
            dnso.answer = answer.hostname

        dnso.answer_as_org_name = answer.as_org_name or ""
        dnso.answer_asn = answer.asn or 0

        return dnso


def make_dns_observations(
    msmt: BaseMeasurement,
    queries: Optional[List[DNSQuery]],
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
            obs_dns.append(DNSObservation.from_measurement(msmt, query, answer))
            idx += 1

    return obs_dns


@dataclass
class TCPObservation:
    timestamp: datetime

    ip: str
    port: int

    success: bool
    failure: Failure

    transaction_id: Optional[int] = None

    @staticmethod
    def from_measurement(
        msmt: BaseMeasurement,
        res: TCPConnect,
    ) -> "TCPObservation":
        tcpo = TCPObservation(
            timestamp=make_timestamp(msmt, res.t),
            ip=res.ip,
            port=res.port,
            failure=normalize_failure(res.status.failure),
            success=res.status.success,
            transaction_id=res.transaction_id,
        )

        return tcpo


def make_tcp_observations(
    msmt: BaseMeasurement,
    tcp_connect: Optional[List[TCPConnect]],
) -> List[TCPObservation]:
    obs_tcp = []
    if not tcp_connect:
        return obs_tcp

    for res in tcp_connect:
        obs_tcp.append(TCPObservation.from_measurement(msmt, res))
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
class TLSObservation:
    timestamp: datetime

    failure: Failure

    server_name: str
    version: str
    cipher_suite: str

    ip: Optional[str] = None
    port: Optional[int] = None

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
    certificate_chain_fingerprints: List[str] = field(default_factory=list)

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
        cert_store: Optional[TLSCertStore] = None,
        validate_domain: Callable[[str, str, List[str]], bool] = lambda x, y, z: True,
    ) -> "TLSObservation":
        tlso = TLSObservation(
            timestamp=make_timestamp(msmt, tls_h.t),
            server_name=tls_h.server_name if tls_h.server_name else "",
            version=tls_h.tls_version if tls_h.tls_version else "",
            cipher_suite=tls_h.cipher_suite if tls_h.cipher_suite else "",
            end_entity_certificate_san_list=[],
            failure=normalize_failure(tls_h.failure),
            transaction_id=tls_h.transaction_id,
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

            try:
                tlso.certificate_chain_fingerprints = list(
                    map(lambda d: hashlib.sha256(d).hexdigest(), tlso.peer_certificates)
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
    cert_store: Optional[TLSCertStore] = None,
    validate_domain: Callable[[str, str, List[str]], bool] = lambda x, y, z: True,
) -> List[TLSObservation]:
    obs_tls = []
    if not tls_handshakes:
        return obs_tls

    for idx, tls_h in enumerate(tls_handshakes):
        obs_tls.append(
            TLSObservation.from_measurement(
                msmt=msmt,
                tls_h=tls_h,
                idx=idx,
                network_events=network_events,
                cert_store=cert_store,
                validate_domain=validate_domain,
            )
        )
    return obs_tls


@dataclass
class WebObservation(MeasurementMeta):
    __table_name__ = "obs_web"

    # These fields are added by the processor
    observation_id: str = ""
    bucket_date: Optional[str] = None
    created_at: Optional[datetime] = None
    post_processed_at: Optional[datetime] = None

    target_id: Optional[str] = None
    hostname: Optional[str] = None

    transaction_id: Optional[int] = None

    ip: Optional[str] = None
    port: Optional[int] = None

    ip_asn: Optional[int] = None
    ip_as_org_name: Optional[str] = None
    ip_as_cc: Optional[str] = None
    ip_cc: Optional[str] = None
    ip_is_bogon: Optional[bool] = None

    # DNS related observation
    dns_query_type: Optional[str] = None
    dns_failure: Failure = None
    dns_engine: Optional[str] = None
    dns_engine_resolver_address: Optional[str] = None

    dns_answer_type: Optional[str] = None
    dns_answer: Optional[str] = None
    # These should match those in the IP field, but are the annotations coming
    # from the probe
    dns_answer_asn: Optional[int] = None
    dns_answer_as_org_name: Optional[str] = None

    # TCP related observation
    tcp_failure: Optional[Failure] = None
    tcp_success: Optional[bool] = None

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
    tls_certificate_chain_fingerprints: List[str] = field(default_factory=list)

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

    http_runtime: Optional[float] = None

    http_response_body_length: Optional[int] = None
    http_response_body_is_truncated: Optional[bool] = None
    http_response_body_sha1: Optional[str] = None

    http_response_status_code: Optional[int] = None
    http_response_header_location: Optional[bytes] = None
    http_response_header_server: Optional[bytes] = None
    http_request_redirect_from: Optional[str] = None
    http_request_body_is_truncated: Optional[bool] = None

    # All of these fields are added as part of a post-processing stage
    pp_http_response_fingerprints: List[str] = field(default_factory=list)
    pp_http_fingerprint_country_consistent: Optional[bool] = None
    pp_http_response_matches_blockpage: bool = False
    pp_http_response_matches_false_positive: bool = False
    pp_http_response_body_title: Optional[str] = None
    pp_http_response_body_meta_title: Optional[str] = None

    pp_dns_fingerprint_id: Optional[str] = None
    pp_dns_fingerprint_country_consistent: Optional[bool] = None


def maybe_set_web_fields(
    src_obs: Union[
        DNSObservation, TCPObservation, TLSObservation, HTTPObservation, None
    ],
    chained: WebObservation,
    prefix: str,
):
    if not src_obs:
        return
    for f in dataclasses.fields(chained):
        if f.name.startswith(prefix):
            src_field_name = removeprefix(f.name, prefix)
            setattr(chained, f.name, getattr(src_obs, src_field_name))


def make_web_observation(
    msmt_meta: MeasurementMeta,
    netinfodb: NetinfoDB,
    dns_o: Optional[DNSObservation] = None,
    tcp_o: Optional[TCPObservation] = None,
    tls_o: Optional[TLSObservation] = None,
    http_o: Optional[HTTPObservation] = None,
    target_id: Optional[str] = None,
) -> WebObservation:
    assert (
        dns_o or tcp_o or tls_o or http_o
    ), "dns_o or tcp_o or tls_o or http_o should be not null"

    web_obs = WebObservation(target_id=target_id, **dataclasses.asdict(msmt_meta))
    dns_ip = None
    if dns_o and dns_o.answer:
        try:
            ipaddress.ip_address(dns_o.answer)
            dns_ip = dns_o.answer
        except ValueError:
            pass
    web_obs.ip = (
        dns_ip or (tcp_o and tcp_o.ip) or (tls_o and tls_o.ip) or (http_o and http_o.ip)
    )
    web_obs.port = (
        (tcp_o and tcp_o.port) or (tls_o and tls_o.port) or (http_o and http_o.port)
    )
    web_obs.hostname = (dns_o and dns_o.hostname) or (http_o and http_o.hostname)
    if web_obs.ip:
        web_obs.ip_is_bogon = is_ip_bogon(web_obs.ip)
        ip_info = netinfodb.lookup_ip(web_obs.measurement_start_time, web_obs.ip)
        if ip_info:
            web_obs.ip_cc = ip_info.cc
            web_obs.ip_asn = ip_info.as_info.asn
            web_obs.ip_as_org_name = ip_info.as_info.as_org_name
            web_obs.ip_as_cc = ip_info.as_info.as_cc

    maybe_set_web_fields(dns_o, web_obs, "dns_")
    maybe_set_web_fields(tcp_o, web_obs, "tcp_")
    maybe_set_web_fields(tls_o, web_obs, "tls_")
    maybe_set_web_fields(http_o, web_obs, "http_")
    return web_obs


def find_observation_by_transaction_id(
    transaction_id: Optional[int],
    obs_list: Union[List[TCPObservation], List[TLSObservation], List[HTTPObservation]],
) -> Optional[Union[TCPObservation, TLSObservation, HTTPObservation]]:
    if not transaction_id:
        return None
    for obs in obs_list:
        if obs.transaction_id == transaction_id:
            # TODO: do we care that there may be collisions in this?
            return obs
    return None


def find_observation_by_ip(
    ip: Optional[str],
    obs_list: Union[List[TCPObservation], List[TLSObservation], List[HTTPObservation]],
) -> Optional[Union[TCPObservation, TLSObservation, HTTPObservation]]:
    for obs in obs_list:
        if ip == obs.ip:
            # TODO: do we care that there may be collisions in this?
            return obs
    return None


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


def consume_web_observations(
    msmt_meta: MeasurementMeta,
    netinfodb: NetinfoDB,
    dns_observations: List[DNSObservation] = [],
    tcp_observations: List[TCPObservation] = [],
    tls_observations: List[TLSObservation] = [],
    http_observations: List[HTTPObservation] = [],
    target_id: Optional[str] = None,
) -> List[WebObservation]:
    web_obs_list = []
    # TODO: surely there is some way to refactor this into a better pattern
    for dns_o in dns_observations:
        tcp_o, tls_o, http_o = find_relevant_observations(
            transaction_id=dns_o.transaction_id,
            ip=dns_o.answer,
            tcp_observations=tcp_observations,
            tls_observations=tls_observations,
            http_observations=http_observations,
        )
        web_obs_list.append(
            make_web_observation(
                msmt_meta=msmt_meta,
                netinfodb=netinfodb,
                dns_o=dns_o,
                tcp_o=tcp_o,
                tls_o=tls_o,
                http_o=http_o,
                target_id=target_id,
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
        web_obs_list.append(
            make_web_observation(
                msmt_meta=msmt_meta,
                netinfodb=netinfodb,
                tcp_o=tcp_o,
                tls_o=tls_o,
                http_o=http_o,
                target_id=target_id,
            )
        )

    for tls_o in tls_observations:
        _, _, http_o = find_relevant_observations(
            transaction_id=tls_o.transaction_id,
            ip=tls_o.ip,
            http_observations=http_observations,
        )
        if http_o:
            http_observations.remove(http_o)
        web_obs_list.append(
            make_web_observation(
                msmt_meta=msmt_meta,
                netinfodb=netinfodb,
                tls_o=tls_o,
                http_o=http_o,
                target_id=target_id,
            )
        )

    for http_o in http_observations:
        web_obs_list.append(
            make_web_observation(
                msmt_meta=msmt_meta,
                netinfodb=netinfodb,
                http_o=http_o,
                target_id=target_id,
            )
        )

    return web_obs_list


def make_web_connectivity_observations(
    msmt: WebConnectivity,
    netinfodb: NetinfoDB,
) -> List[WebObservation]:
    msmt_meta = make_measurement_meta(msmt=msmt, netinfodb=netinfodb)

    http_observations = make_http_observations(msmt, msmt.test_keys.requests)
    dns_observations = make_dns_observations(msmt, msmt.test_keys.queries)
    tcp_observations = make_tcp_observations(msmt, msmt.test_keys.tcp_connect)
    tls_observations = make_tls_observations(
        msmt,
        msmt.test_keys.tls_handshakes,
        msmt.test_keys.network_events,
    )
    return consume_web_observations(
        msmt_meta=msmt_meta,
        netinfodb=netinfodb,
        dns_observations=dns_observations,
        tcp_observations=tcp_observations,
        tls_observations=tls_observations,
        http_observations=http_observations,
    )


def make_signal_observations(
    msmt: Signal, netinfodb: NetinfoDB
) -> List[WebObservation]:
    cert_store = TLSCertStore(SIGNAL_PEM_STORE)

    msmt_meta = make_measurement_meta(msmt=msmt, netinfodb=netinfodb)

    dns_observations = make_dns_observations(msmt, msmt.test_keys.queries)
    tcp_observations = make_tcp_observations(msmt, msmt.test_keys.tcp_connect)
    tls_observations = make_tls_observations(
        msmt,
        msmt.test_keys.tls_handshakes,
        msmt.test_keys.network_events,
        cert_store,
    )
    http_observations = make_http_observations(msmt, msmt.test_keys.requests)

    return consume_web_observations(
        msmt_meta=msmt_meta,
        netinfodb=netinfodb,
        dns_observations=dns_observations,
        tcp_observations=tcp_observations,
        tls_observations=tls_observations,
        http_observations=http_observations,
    )


def make_dnscheck_observations(
    msmt: DNSCheck,
    netinfodb: NetinfoDB,
) -> List[WebObservation]:
    web_obs_list = []

    msmt_meta = make_measurement_meta(msmt=msmt, netinfodb=netinfodb)

    if msmt.test_keys.bootstrap:
        web_obs_list += consume_web_observations(
            msmt_meta=msmt_meta,
            netinfodb=netinfodb,
            dns_observations=make_dns_observations(
                msmt, msmt.test_keys.bootstrap.queries
            ),
        )

    lookup_map = msmt.test_keys.lookups or {}
    for lookup in lookup_map.values():
        web_obs_list += consume_web_observations(
            msmt_meta=msmt_meta,
            netinfodb=netinfodb,
            dns_observations=make_dns_observations(msmt, lookup.queries),
            http_observations=make_http_observations(msmt, lookup.requests),
            tcp_observations=make_tcp_observations(msmt, lookup.tcp_connect),
            tls_observations=make_tls_observations(
                msmt, lookup.tls_handshakes, lookup.network_events
            ),
        )

    return web_obs_list


def make_tor_observations(
    msmt: Tor,
    netinfodb: NetinfoDB,
) -> List[WebObservation]:
    web_obs_list = []
    msmt_meta = make_measurement_meta(msmt=msmt, netinfodb=netinfodb)

    for target_id, target_msmt in msmt.test_keys.targets.items():
        http_observations = make_http_observations(msmt, target_msmt.requests)
        dns_observations = make_dns_observations(msmt, target_msmt.queries)
        tcp_observations = make_tcp_observations(msmt, target_msmt.tcp_connect)
        tls_observations = make_tls_observations(
            msmt,
            target_msmt.tls_handshakes,
            target_msmt.network_events,
        )
        web_obs_list += consume_web_observations(
            msmt_meta=msmt_meta,
            netinfodb=netinfodb,
            dns_observations=dns_observations,
            tcp_observations=tcp_observations,
            tls_observations=tls_observations,
            http_observations=http_observations,
            target_id=target_id,
        )

    return web_obs_list


nettest_make_obs_map = {
    "web_connectivity": make_web_connectivity_observations,
    "dnscheck": make_dnscheck_observations,
    "tor": make_tor_observations,
    "signal": make_signal_observations,
}


def make_observations(msmt, netinfodb: NetinfoDB):
    if msmt.test_name in nettest_make_obs_map:
        return nettest_make_obs_map[msmt.test_name](msmt, netinfodb)
    return []
