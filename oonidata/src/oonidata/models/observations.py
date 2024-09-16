import dataclasses
from dataclasses import dataclass, field
from datetime import datetime
from typing import (
    Optional,
    List,
    Tuple,
)

from oonidata.models.base import table_model
from oonidata.models.dataformats import Failure


## These two classes are special, and it's essential that the columns don't clash with the classes that compose them.
# TODO(art): we should eventually add a prefix to these columns in the clickhouse map to avoid that.
@dataclass
class MeasurementMeta:
    measurement_uid: str
    input: Optional[str]
    report_id: str

    measurement_start_time: datetime

    software_name: str
    software_version: str
    test_name: str
    test_version: str

    bucket_date: str


@dataclass
class ProbeMeta:
    probe_asn: int
    probe_cc: str

    probe_as_org_name: str
    probe_as_cc: str
    probe_as_name: str

    network_type: str
    platform: str
    origin: str
    engine_name: str
    engine_version: str
    architecture: str

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
    response_header_location: Optional[str] = None
    response_header_server: Optional[str] = None
    request_redirect_from: Optional[str] = None
    request_body_is_truncated: Optional[bool] = None

    transaction_id: Optional[int] = None
    t: Optional[float] = None

    @property
    def request_is_encrypted(self):
        return self.request_url.startswith("https://")


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
    t: Optional[float] = None


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
    t: Optional[float] = None


@dataclass
class TCPObservation:
    timestamp: datetime

    ip: str
    port: int

    success: bool
    failure: Failure

    t: Optional[float] = None
    transaction_id: Optional[int] = None


@table_model(
    table_name="obs_web_ctrl",
    table_index=(
        "measurement_start_time",
        "hostname",
        "measurement_uid",
        "observation_idx",
    ),
    partition_key="concat(substring(bucket_date, 1, 4), substring(bucket_date, 6, 2))",
)
@dataclass
class WebControlObservation:
    measurement_meta: MeasurementMeta

    hostname: str
    observation_idx: int = 0

    created_at: Optional[datetime] = None

    ip: str = ""
    port: Optional[int] = None

    ip_asn: Optional[int] = None
    ip_as_org_name: Optional[str] = None
    ip_as_cc: Optional[str] = None
    ip_cc: Optional[str] = None
    ip_is_bogon: Optional[bool] = None

    dns_failure: Optional[str] = None
    dns_success: Optional[bool] = None

    tcp_failure: Optional[str] = None
    tcp_success: Optional[bool] = None

    tls_failure: Optional[str] = None
    tls_success: Optional[bool] = None
    tls_server_name: Optional[str] = None

    http_request_url: Optional[str] = None
    http_failure: Optional[str] = None
    http_success: Optional[bool] = None
    http_response_body_length: Optional[int] = None


@table_model(
    table_name="obs_web",
    table_index=(
        "measurement_start_time",
        "probe_cc",
        "probe_asn",
        "measurement_uid",
        "observation_idx",
    ),
    partition_key="concat(substring(bucket_date, 1, 4), substring(bucket_date, 6, 2))",
)
@dataclass
class WebObservation:
    measurement_meta: MeasurementMeta
    probe_meta: ProbeMeta

    # These fields are added by the processor
    observation_idx: int = 0
    created_at: Optional[datetime] = None

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
    dns_t: Optional[float] = None

    # TCP related observation
    tcp_failure: Optional[Failure] = None
    tcp_success: Optional[bool] = None
    tcp_t: Optional[float] = None

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
    tls_t: Optional[float] = None

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
    http_response_header_location: Optional[str] = None
    http_response_header_server: Optional[str] = None
    http_request_redirect_from: Optional[str] = None
    http_request_body_is_truncated: Optional[bool] = None
    http_t: Optional[float] = None

    # probe level analysis
    probe_analysis: Optional[str] = None

    # Removed in v5.0.0-alpha.1
    # post_processed_at: Optional[datetime] = None
    # pp_http_response_fingerprints: List[str] = field(default_factory=list)
    # pp_http_fingerprint_country_consistent: Optional[bool] = None
    # pp_http_response_matches_blockpage: bool = False
    # pp_http_response_matches_false_positive: bool = False
    # pp_http_response_body_title: Optional[str] = None
    # pp_http_response_body_meta_title: Optional[str] = None

    # pp_dns_fingerprint_id: Optional[str] = None
    # pp_dns_fingerprint_country_consistent: Optional[bool] = None

    # removed in v5.0.0-alpha.2
    # post_processed_at: Optional[datetime] = None


@table_model(
    table_name="obs_http_middlebox",
    table_index=(
        "measurement_start_time",
        "measurement_uid",
        "observation_idx",
    ),
    partition_key="concat(substring(bucket_date, 1, 4), substring(bucket_date, 6, 2))",
)
@dataclass
class HTTPMiddleboxObservation:
    measurement_meta: MeasurementMeta
    probe_meta: ProbeMeta

    observation_idx: int = 0

    created_at: Optional[datetime] = None

    # Set the payload returned by the HTTP Invalid Request Line test
    hirl_sent_0: Optional[str] = None
    hirl_sent_1: Optional[str] = None
    hirl_sent_2: Optional[str] = None
    hirl_sent_3: Optional[str] = None
    hirl_sent_4: Optional[str] = None

    hirl_received_0: Optional[str] = None
    hirl_received_1: Optional[str] = None
    hirl_received_2: Optional[str] = None
    hirl_received_3: Optional[str] = None
    hirl_received_4: Optional[str] = None

    hirl_failure: Optional[str] = None
    hirl_success: Optional[bool] = None

    hfm_diff: Optional[str] = None
    hfm_failure: Optional[str] = None
    hfm_success: Optional[bool] = None
