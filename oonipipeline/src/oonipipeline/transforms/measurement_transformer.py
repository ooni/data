from base64 import b64decode
import hashlib
import ipaddress

import dataclasses
import logging
from urllib.parse import urlparse, urlsplit
from datetime import datetime, timedelta, timezone
from typing import (
    Callable,
    Optional,
    List,
    Tuple,
    Union,
    Dict,
)
from collections import defaultdict

from oonidata.models.dataformats import (
    DNSAnswer,
    DNSQuery,
    HTTPTransaction,
    Failure,
    NetworkEvent,
    TCPConnect,
    TLSHandshake,
    OpenVPNHandshake,
    OpenVPNNetworkEvent,
    maybe_binary_data_to_bytes,
)
from oonidata.models.nettests.base_measurement import BaseMeasurement
from oonidata.models.observations import (
    DNSObservation,
    HTTPObservation,
    MeasurementMeta,
    ProbeMeta,
    TCPObservation,
    TLSObservation,
    WebObservation,
    OpenVPNObservation,
)
from oonidata.datautils import (
    InvalidCertificateChain,
    TLSCertStore,
    is_ip_bogon,
    get_certificate_meta,
    removeprefix,
)
from ..netinfo import NetinfoDB


log = logging.getLogger("oonidata.transforms")

unknown_failure_map = (
    (
        "A socket operation was attempted to an unreachable network",
        "network_unreachable",
    ),
    ("connect: network is unreachable", "network_unreachable"),
    (
        "No connection could be made because the target machine actively refused it",
        "connection_refused",
    ),
    ("connect: can't assign requested address", "address_not_available"),
    (": server misbehaving", "dns_server_misbehaving"),
    ("tls: first record does not look like a TLS handshake", "invalid_record"),
    ("remote error: tls: handshake failure", "tls_handshake_failure"),
    ("remote error: tls: illegal parameter", "tls_illegal_parameter"),
    ("certificate has expired or is not yet valid", "ssl_invalid_certificate"),
    ("tls: internal error", "internal_error"),
    ("tls: access denied", "access_denied"),
    (": read: connection refused", "connection_refused"),
    (
        "connectex: No connection could be made because the target machine actively refused it",
        "connection_refused",
    ),
    ("read: connection refused", "connection_refused"),
    (
        "HTTP/1.x transport connection broken: malformed HTTP version",
        "http_malformed_response",
    ),
    ("net/http: timeout awaiting response headers", "http_timeout"),
    ("read: operation timed out", "timed_out"),
    ("connect: operation timed out", "timed_out"),
    (": No address associated with hostname", "dns_nxdomain_error"),
    (": connect: bad file descriptor", "bad_file_descriptor"),
    ("stream error: stream ID", "http_stream_error"),
    # This looks more like a golang-bug: https://github.com/golang/go/issues/31259
    ("readLoopPeekFailLocked: <nil>", "http_golang_bug"),
    ("connect: no route to host", "host_unreachable"),
    (
        "getaddrinfow: The requested name is valid, but no data of the requested type was found.",
        "dns_no_answer",
    ),
    (
        "An existing connection was forcibly closed by the remote host",
        "connection_reset",
    ),
    (
        "wsarecv: Se ha forzado la interrupción de una conexión existente por el host remoto.",
        "connection_reset",
    ),
    (
        "wsarecv: An existing connection was forcibly closed by the remote host.",
        "connection_reset",
    ),
    (
        "wsarecv: Connessione in corso interrotta forzatamente dall'host remoto.",
        "connection_reset",
    ),
    (
        "wsarecv: Uma ligação existente foi forçada a fechar pelo anfitrião remoto",
        "connection_reset",
    ),
    (
        "This is usually a temporary error during hostname resolution and means that the local server did not receive a response from an authoritative server",
        "dns_temporary_failure",
    ),
    (
        "Der angeforderte Name ist gültig, es wurden jedoch keine Daten des angeforderten Typs gefunden",
        "dns_temporary_failure",
    ),
    (
        "getaddrinfow: Ceci est habituellement une erreur temporaire qui se produit durant la résolution du nom d’hôte et qui signifie que le serveur local n’a pas reçu de réponse d’un serveur faisant autorité",
        "dns_temporary_failure",
    ),
    (
        "getaddrinfow: Dies ist normalerweise ein zeitweiliger Fehler bei der Auflösung von Hostnamen. Grund ist, dass der lokale Server keine Rückmeldung vom autorisierenden Server erhalten hat.",
        "dns_temporary_failure",
    ),
    (
        "getaddrinfow: Este é geralmente um erro temporário durante a resolução de nomes de anfitrião e significa que o servidor local não recebeu uma resposta de um servidor autoritário",
        "dns_temporary_failure",
    ),
    (
        "getaddrinfow: Éste es normalmente un error temporal durante la resolución de nombres de host y significa que el servidor local no recibió una respuesta de un servidor autoritativo",
        "dns_temporary_failure",
    ),
    ("address family not supported by protocol", "address_family_not_supported"),
)


def normalize_failure(failure: Union[Failure, bool]) -> Failure:
    if not failure:
        # This will set it to None even when it's false
        return None

    if failure is True:
        return "true"

    if failure.startswith("unknown_failure"):
        for substring, new_failure in unknown_failure_map:
            if substring in failure:
                return new_failure
    return failure


def make_timestamp(measurement_start_time: datetime, t: Optional[float] = None):
    timestamp = measurement_start_time
    if t:
        timestamp += timedelta(seconds=t)
    return timestamp


def measurement_to_http_observation(
    msmt_meta: MeasurementMeta,
    requests_list: List[HTTPTransaction],
    idx: int,
    http_transaction: HTTPTransaction,
) -> Optional[HTTPObservation]:
    if not http_transaction.request:
        # This is a very malformed request, we don't consider it a valid
        # observation as we don't know what it's referring to.
        # XXX maybe log this somewhere
        return None

    network = http_transaction.network or http_transaction.request.x_transport or "tcp"
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
        request_body_length=(
            len(http_transaction.request.body_bytes)
            if http_transaction.request.body_bytes
            else 0
        ),
        network=network,
        alpn=http_transaction.alpn,
        failure=normalize_failure(http_transaction.failure),
        timestamp=make_timestamp(msmt_meta.measurement_start_time, http_transaction.t),
        transaction_id=http_transaction.transaction_id,
        t=http_transaction.t,
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

    hrro.response_header_location = http_transaction.response.get_first_http_header_str(
        "location"
    )
    hrro.response_header_server = http_transaction.response.get_first_http_header_str(
        "server"
    )

    try:
        prev_request = requests_list[idx + 1]
        if prev_request and prev_request.response:
            prev_location = prev_request.response.get_first_http_header_str("location")
            if prev_location == hrro.request_url:
                assert prev_request.request
                hrro.request_redirect_from = prev_request.request.url
    except (IndexError, UnicodeDecodeError, AttributeError):
        pass
    return hrro


def measurement_to_dns_observation(
    msmt_meta: MeasurementMeta,
    query: DNSQuery,
    answer: Optional[DNSAnswer],
) -> DNSObservation:
    dnso = DNSObservation(
        engine=query.engine,
        engine_resolver_address=query.resolver_address,
        query_type=query.query_type,
        hostname=query.hostname,
        failure=normalize_failure(query.failure),
        timestamp=make_timestamp(msmt_meta.measurement_start_time, query.t),
        transaction_id=query.transaction_id,
        t=query.t,
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


def measurement_to_tcp_observation(
    msmt_meta: MeasurementMeta,
    res: TCPConnect,
) -> TCPObservation:
    tcpo = TCPObservation(
        timestamp=make_timestamp(msmt_meta.measurement_start_time, res.t),
        ip=res.ip,
        port=res.port,
        failure=normalize_failure(res.status.failure),
        success=res.status.success,
        transaction_id=res.transaction_id,
        t=res.t,
    )

    return tcpo


def network_events_until_connect(
    network_events: List[NetworkEvent],
) -> List[NetworkEvent]:
    ne_list = []
    for ne in network_events:
        if ne.operation == "connect":
            break
        ne_list.append(ne)
    return ne_list


def find_tls_handshake_events_without_transaction_id(
    tls_handshake: TLSHandshake,
    src_idx: int,
    network_events: List[NetworkEvent],
) -> Optional[List[NetworkEvent]]:
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


def find_tls_handshake_network_events_with_transaction_id(
    tls_handshake: TLSHandshake,
    network_events: List[NetworkEvent],
) -> List[NetworkEvent]:
    relevant_network_events = sorted(
        filter(
            lambda ne: ne.transaction_id == tls_handshake.transaction_id, network_events
        ),
        key=lambda ne: ne.t,
    )
    assert (
        relevant_network_events[0].address == tls_handshake.address
    ), "inconsistent address detected"
    return relevant_network_events


def measurement_to_tls_observation(
    msmt_meta: MeasurementMeta,
    tls_h: TLSHandshake,
    network_events: Optional[List[NetworkEvent]],
    idx: int,
    cert_store: Optional[TLSCertStore] = None,
    validate_domain: Callable[[str, str, List[str]], bool] = lambda x, y, z: True,
) -> TLSObservation:
    tlso = TLSObservation(
        timestamp=make_timestamp(msmt_meta.measurement_start_time, tls_h.t),
        server_name=tls_h.server_name if tls_h.server_name else "",
        version=tls_h.tls_version if tls_h.tls_version else "",
        cipher_suite=tls_h.cipher_suite if tls_h.cipher_suite else "",
        end_entity_certificate_san_list=[],
        failure=normalize_failure(tls_h.failure),
        transaction_id=tls_h.transaction_id,
        t=tls_h.t,
    )

    if tls_h.address:
        p = urlsplit("//" + tls_h.address)
        tlso.ip = p.hostname
        tlso.port = p.port

    tls_network_events: Optional[List[NetworkEvent]] = None
    if network_events:
        # TODO(decfox): We check the first network event for the transaction_id and
        # find tls handshake network events based on this. This is a weak check and
        # somewhat sketchy
        if network_events[0] and network_events[0].transaction_id is None:
            tls_network_events = find_tls_handshake_events_without_transaction_id(
                tls_h, idx, network_events
            )
        else:
            tls_network_events = find_tls_handshake_network_events_with_transaction_id(
                tls_h, network_events
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
                tlso.handshake_last_operation = f"write_{tlso.handshake_write_count}"
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
            log.warning("failed to decode peer_certificates")

        try:
            tlso.certificate_chain_fingerprints = list(
                map(lambda d: hashlib.sha256(d).hexdigest(), tlso.peer_certificates)
            )
        except Exception:
            log.warning("failed to decode peer_certificates")

        tlso.certificate_chain_length = len(tls_h.peer_certificates)
        try:
            raw_cert = maybe_binary_data_to_bytes(tls_h.peer_certificates[0])
            cert_meta = get_certificate_meta(raw_cert)
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
            tlso.end_entity_certificate_not_valid_before = cert_meta.not_valid_before
            tlso.end_entity_certificate_san_list = cert_meta.san_list
        except Exception as exc:
            log.warning(exc)
            log.warning(
                f"Failed to extract certificate meta for {msmt_meta.measurement_uid}"
            )

    if cert_store and tlso.peer_certificates:
        try:
            cn, san_list = cert_store.validate_cert_chain(
                tlso.timestamp, tlso.peer_certificates
            )
            tlso.is_certificate_valid = validate_domain(tlso.server_name, cn, san_list)
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


def maybe_set_web_fields(
    src_obs: Union[
        DNSObservation, TCPObservation, TLSObservation, HTTPObservation, None
    ],
    web_obs: WebObservation,
    prefix: str,
    field_names: Tuple[str, ...],
):
    # TODO: the fact we have to do this is an artifact of the original
    # one-observation per type model. Once we decide we don't want to go for
    # that, the rest of the code can be refactored to not make use of that
    # anymore and we shouldn't need this anymore.
    if not src_obs:
        return

    for fname in field_names:
        if fname.startswith(prefix):
            src_field_name = removeprefix(fname, prefix)
            setattr(web_obs, fname, getattr(src_obs, src_field_name))


WEB_OBS_FIELDS = tuple(f.name for f in dataclasses.fields(WebObservation))


def make_web_observation(
    msmt_meta: MeasurementMeta,
    probe_meta: ProbeMeta,
    netinfodb: NetinfoDB,
    observation_idx: int = 0,
    dns_o: Optional[DNSObservation] = None,
    tcp_o: Optional[TCPObservation] = None,
    tls_o: Optional[TLSObservation] = None,
    http_o: Optional[HTTPObservation] = None,
    target_id: Optional[str] = None,
    probe_analysis: Optional[str] = None,
) -> WebObservation:
    assert (
        dns_o or tcp_o or tls_o or http_o
    ), "dns_o or tcp_o or tls_o or http_o should be not null"

    web_obs = WebObservation(
        target_id=target_id,
        probe_analysis=probe_analysis,
        measurement_meta=msmt_meta,
        probe_meta=probe_meta,
        observation_idx=observation_idx,
        created_at=datetime.now(timezone.utc),
    )
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
        ip_info = netinfodb.lookup_ip(msmt_meta.measurement_start_time, web_obs.ip)
        if ip_info:
            web_obs.ip_cc = ip_info.cc
            web_obs.ip_asn = ip_info.as_info.asn
            web_obs.ip_as_org_name = ip_info.as_info.as_org_name
            web_obs.ip_as_cc = ip_info.as_info.as_cc

    if tcp_o and tcp_o.transaction_id:
        web_obs.transaction_id = tcp_o.transaction_id
    elif tls_o and tls_o.transaction_id:
        web_obs.transaction_id = tls_o.transaction_id
    elif http_o and http_o.transaction_id:
        web_obs.transaction_id = http_o.transaction_id

    maybe_set_web_fields(
        src_obs=dns_o, prefix="dns_", web_obs=web_obs, field_names=WEB_OBS_FIELDS
    )
    maybe_set_web_fields(
        src_obs=tcp_o, prefix="tcp_", web_obs=web_obs, field_names=WEB_OBS_FIELDS
    )
    maybe_set_web_fields(
        src_obs=tls_o, prefix="tls_", web_obs=web_obs, field_names=WEB_OBS_FIELDS
    )
    maybe_set_web_fields(
        src_obs=http_o, prefix="http_", web_obs=web_obs, field_names=WEB_OBS_FIELDS
    )
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


def make_probe_meta(msmt: BaseMeasurement, netinfodb: NetinfoDB) -> ProbeMeta:
    assert msmt.measurement_uid is not None
    probe_asn = int(msmt.probe_asn[len("AS") :])
    measurement_start_time = datetime.strptime(
        msmt.measurement_start_time, "%Y-%m-%d %H:%M:%S"
    )
    probe_as_info = netinfodb.lookup_asn(measurement_start_time, probe_asn)

    resolver_ip = msmt.resolver_ip
    resolver_is_scrubbed = False
    try:
        client_resolver = msmt.test_keys.client_resolver
    except AttributeError:
        # Not all tests have in their test_keys client_resolver
        client_resolver = None

    if client_resolver == "[scrubbed]" or resolver_ip == "[scrubbed]":
        resolver_is_scrubbed = True

    resolver_ip = resolver_ip or client_resolver or ""
    resolver_cc = ""
    resolver_asn = 0
    resolver_as_org_name = ""
    resolver_as_cc = ""

    resolver_asn_probe = msmt.resolver_asn
    if resolver_asn_probe in (None, ""):
        resolver_asn_probe = 0
    else:
        assert resolver_asn_probe is not None
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

    annotations = msmt.annotations or {}
    return ProbeMeta(
        probe_asn=probe_asn,
        probe_cc=msmt.probe_cc,
        probe_as_org_name=probe_as_info.as_org_name if probe_as_info else "",
        probe_as_cc=probe_as_info.as_cc if probe_as_info else "",
        probe_as_name=probe_as_info.as_name if probe_as_info else "",
        network_type=annotations.get("network_type", "unknown"),
        platform=annotations.get("platform", "unknown"),
        origin=annotations.get("origin", "unknown"),
        engine_name=annotations.get("engine_name", "unknown"),
        engine_version=annotations.get("engine_version", "unknown"),
        architecture=annotations.get("architecture", "unknown"),
        resolver_ip=resolver_ip,
        resolver_cc=resolver_cc,
        resolver_asn=resolver_asn,
        resolver_as_org_name=resolver_as_org_name,
        resolver_as_cc=resolver_as_cc,
        resolver_asn_probe=resolver_asn_probe,
        resolver_as_org_name_probe=resolver_as_org_name_probe,
        resolver_is_scrubbed=resolver_is_scrubbed,
    )


def make_measurement_meta(msmt: BaseMeasurement, bucket_date: str) -> MeasurementMeta:
    assert msmt.measurement_uid is not None
    measurement_start_time = datetime.strptime(
        msmt.measurement_start_time, "%Y-%m-%d %H:%M:%S"
    )

    input_ = msmt.input
    if isinstance(input_, list):
        input_ = ":".join(input_)

    return MeasurementMeta(
        measurement_uid=msmt.measurement_uid,
        report_id=msmt.report_id,
        input=input_,
        software_name=msmt.software_name,
        software_version=msmt.software_version,
        test_name=msmt.test_name,
        test_version=msmt.test_version,
        bucket_date=bucket_date,
        measurement_start_time=measurement_start_time,
    )

def count_key_exchange_packets(network_events: List[OpenVPNNetworkEvent]) -> int:
    """
    return number of packets exchanged in the SENT_KEY state
    """
    n = 0
    for evt in network_events:
        if evt.stage == "SENT_KEY" and evt.operation.startswith("packet_"):
            n+=1
    return n

def measurement_to_openvpn_observation(
    msmt_meta: MeasurementMeta,
    probe_meta: ProbeMeta,
    netinfodb: NetinfoDB,
    openvpn_h: OpenVPNHandshake,
    tcp_connect: Optional[List[TCPConnect]],
    network_events: Optional[List[OpenVPNNetworkEvent]],
    bootstrap_time: float,
) -> OpenVPNObservation:

    oo = OpenVPNObservation(
        measurement_meta=msmt_meta,
        probe_meta=probe_meta,
        failure=normalize_failure(openvpn_h.failure),
        timestamp=make_timestamp(msmt_meta.measurement_start_time, openvpn_h.t),
        success=openvpn_h.failure == None,
        protocol="openvpn",
        transport = openvpn_h.transport,
        ip = openvpn_h.ip,
        port = openvpn_h.port,
        openvpn_bootstrap_time=bootstrap_time,
    )

    if len(tcp_connect) != 0:
        tcp = tcp_connect[0]
        oo.tcp_success = tcp.success
        oo.tcp_failure = tcp.failure
        oo.tcp_t = tcp.t

    oo.handshake_failure = openvpn_h.failure
    oo.handshake_t = openvpn_h.t
    oo.handshake_t0 = openvpn_h.t0

    # TODO(ain): condition to test version >= xyz
    if len(network_events) != 0:
        for evt in network_events:
            if evt.packet is not None:
                if evt.packet.opcode == "P_CONTROL_HARD_RESET_CLIENT_V2":
                    oo.openvpn_handshake_hr_client_t = evt.t
                elif evt.packet.opcode == "P_CONTROL_HARD_RESET_SERVER_V2":
                    oo.openvpn_handshake_hr_server_t = evt.t
                elif "client_hello" in evt.tags:
                    oo.openvpn_handshake_clt_hello_t = evt.t
                elif "server_hello" in evt.tags:
                    oo.openvpn_handshake_srv_hello_t = evt.t
            if evt.operation == "state" and evt.stage == "GOT_KEY":
                oo.openvpn_handshake_got_keys__t = evt.t
            if evt.operation == "state" and evt.stage == "GENERATED_KEYS":
                oo.openvpn_handshake_gen_keys__t = evt.t

        oo.openvpn_handshake_key_exchg_n = count_key_exchange_packets(network_events)

    return oo


class MeasurementTransformer:
    """
    MeasurementTransformer is responsible for taking a measurement and
    transforming it into a list of observations.

    This class is an abstract class which should have the make_observations
    method implemented for each measurement (i.e. nettest) type.

    It provides a series of class methods that are helpful to make
    sub-observations that can then be composed together in order to build the
    final observation model that's going to be written to the desired database.
    """

    def __init__(
        self,
        measurement: BaseMeasurement,
        bucket_date: str,
        netinfodb: NetinfoDB,
    ):
        self.netinfodb = netinfodb
        self.measurement_meta = make_measurement_meta(
            msmt=measurement, bucket_date=bucket_date
        )
        self.probe_meta = make_probe_meta(msmt=measurement, netinfodb=netinfodb)
        self.observation_idx = 1

    def make_http_observations(
        self,
        requests_list: Optional[List[HTTPTransaction]],
    ) -> List[HTTPObservation]:
        """
        Returns a list of HTTP Observations which are usually found inside
        of the `requests` test_key.
        """
        obs_list = []
        if not requests_list:
            return obs_list

        for idx, http_transaction in enumerate(requests_list):
            httpo = measurement_to_http_observation(
                msmt_meta=self.measurement_meta,
                idx=idx,
                requests_list=requests_list,
                http_transaction=http_transaction,
            )
            if httpo:
                obs_list.append(httpo)
        return obs_list

    def make_tls_observations(
        self,
        tls_handshakes: Optional[List[TLSHandshake]],
        network_events: Optional[List[NetworkEvent]],
        cert_store: Optional[TLSCertStore] = None,
        validate_domain: Callable[[str, str, List[str]], bool] = lambda x, y, z: True,
    ) -> List[TLSObservation]:
        """
        Returns a list of TLSObservations, which are usually found inside
        of the `tls_handshakes` test.

        The optional arguments cert_store and validate_domain are used to TLS
        certificate validation using a custom certificate store and custom
        domain validation function.
        This is useful when dealing with tests that are measuring TLS targets
        that are using a custom CA.
        """
        obs_tls = []
        if not tls_handshakes:
            return obs_tls

        for idx, tls_h in enumerate(tls_handshakes):
            obs_tls.append(
                measurement_to_tls_observation(
                    msmt_meta=self.measurement_meta,
                    tls_h=tls_h,
                    idx=idx,
                    network_events=network_events,
                    cert_store=cert_store,
                    validate_domain=validate_domain,
                )
            )
        return obs_tls

    def make_tcp_observations(
        self,
        tcp_connect: Optional[List[TCPConnect]],
    ) -> List[TCPObservation]:
        """
        Returns a list of TCPObservations usually found under the `tcp_connect` test_keys
        """
        obs_tcp = []
        if not tcp_connect:
            return obs_tcp

        for res in tcp_connect:
            # Older OONI Probes will put things that aren't IPs inside of TCP connect
            # see: https://explorer.ooni.org/measurement/20221014T000036Z_webconnectivity_RU_42668_n1_XdKjqrsbSmryZHho?input=http://www.newnownext.com/franchise/the-backlot/
            # TODO: we currently ignore these cases as the measurement is not really
            # that useful. Maybe we should do something better about it.
            try:
                ipaddress.ip_address(res.ip)
            except ValueError:
                continue
            obs_tcp.append(measurement_to_tcp_observation(self.measurement_meta, res))
        return obs_tcp

    def make_dns_observations(
        self,
        queries: Optional[List[DNSQuery]],
    ) -> List[DNSObservation]:
        """
        Returns a list of DNSObservations usually found under the `queries` test_keys
        """
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
                    measurement_to_dns_observation(
                        msmt_meta=self.measurement_meta, query=query, answer=answer
                    )
                )
                idx += 1

        return obs_dns

    def consume_web_observations(
        self,
        dns_observations: List[DNSObservation] = [],
        tcp_observations: List[TCPObservation] = [],
        tls_observations: List[TLSObservation] = [],
        http_observations: List[HTTPObservation] = [],
        target_id: Optional[str] = None,
        probe_analysis: Optional[str] = None,
    ) -> List[WebObservation]:
        """
        Returns a list of WebObservations by mapping all related
        DNSObservations, TCPObservations, TLSObservations and HTTPObservations.

        It's called "consume_" instead of "make_", because the *_observations
        lists are modified during the mapping process, so the values of the
        lists passed as input should be discarded.

        It will attempt to map them via the transaction_id or ip:port tuple.

        Any observation that cannot be mapped will be returned inside of its
        own WebObservation with all other columns set to None.
        """
        web_obs_list: List[WebObservation] = []
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
                    msmt_meta=self.measurement_meta,
                    probe_meta=self.probe_meta,
                    netinfodb=self.netinfodb,
                    dns_o=dns_o,
                    tcp_o=tcp_o,
                    tls_o=tls_o,
                    http_o=http_o,
                    target_id=target_id,
                    probe_analysis=probe_analysis,
                    observation_idx=self.observation_idx,
                )
            )
            if tcp_o:
                tcp_observations.remove(tcp_o)
            if tls_o:
                tls_observations.remove(tls_o)
            if http_o:
                http_observations.remove(http_o)
            self.observation_idx += 1

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
                    msmt_meta=self.measurement_meta,
                    probe_meta=self.probe_meta,
                    netinfodb=self.netinfodb,
                    tcp_o=tcp_o,
                    tls_o=tls_o,
                    http_o=http_o,
                    target_id=target_id,
                    probe_analysis=probe_analysis,
                    observation_idx=self.observation_idx,
                )
            )
            self.observation_idx += 1

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
                    msmt_meta=self.measurement_meta,
                    probe_meta=self.probe_meta,
                    netinfodb=self.netinfodb,
                    tls_o=tls_o,
                    http_o=http_o,
                    target_id=target_id,
                    probe_analysis=probe_analysis,
                    observation_idx=self.observation_idx,
                )
            )
            self.observation_idx += 1

        for http_o in http_observations:
            web_obs_list.append(
                make_web_observation(
                    msmt_meta=self.measurement_meta,
                    probe_meta=self.probe_meta,
                    netinfodb=self.netinfodb,
                    http_o=http_o,
                    target_id=target_id,
                    probe_analysis=probe_analysis,
                    observation_idx=self.observation_idx,
                )
            )
            self.observation_idx += 1

        return web_obs_list

    def make_openvpn_observations(self,
        tcp_observations: Optional[List[TCPConnect]],
        openvpn_handshakes: Optional[List[OpenVPNHandshake]],
        network_events: Optional[List[OpenVPNNetworkEvent]],
        bootstrap_time: float,
    ) -> List[OpenVPNObservation]:
        """
        Returns a list of OpenVPNObservations by mapping all related
        TCPObservations, OpenVPNNetworkevents and OpenVPNHandshakes.
        """
        openvpn_obs_list: List[OpenVPNObservation] = []

        for openvpn_handshake in openvpn_handshakes:
            openvpn_obs_list.append(
                measurement_to_openvpn_observation(
                    msmt_meta=self.measurement_meta,
                    probe_meta=self.probe_meta,
                    netinfodb=self.netinfodb,
                    tcp_connect=tcp_observations,
                    openvpn_h=openvpn_handshake,
                    network_events=network_events,
                    bootstrap_time=bootstrap_time,
                )
            )

        # TODO: can factor out function with web_observation
        for idx, obs in enumerate(openvpn_obs_list):
            obs.observation_id = f"{obs.measurement_meta.measurement_uid}_{idx}"
            obs.created_at = datetime.now(timezone.utc).replace(
                microsecond=0, tzinfo=None
            )

        return openvpn_obs_list

    def make_observations(self, measurement):
        assert RuntimeError("make_observations is not implemented")
