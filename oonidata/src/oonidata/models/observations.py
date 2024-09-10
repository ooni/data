import dataclasses
from dataclasses import dataclass, field
from datetime import datetime
from typing import (
    Annotated,
    Optional,
    List,
    Tuple,
)

from oonidata.models.base import (
    ArrayString,
    Float64,
    OptionalDatetime,
    UInt16,
    UInt32,
    UInt8,
    table_model,
    ProcessingMeta,
)
from oonidata.models.dataformats import Failure


## These two classes are special, and it's essential that the columns don't clash with the classes that compose them.
# TODO(art): we should eventually add a prefix to these columns in the clickhouse map to avoid that.
@dataclass
class MeasurementMeta:
    measurement_uid: str
    report_id: str

    measurement_start_time: datetime
    bucket_datetime: datetime

    software_name: str
    software_version: str
    test_name: str
    test_version: str
    test_runtime: Float64

    test_helper_address: str = ""
    input: str = ""


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

    fqdn: str
    request_url: str

    network: str
    alpn: str

    failure: str

    request_body_length: int
    request_method: str
    request_headers_list: List[Tuple[str, bytes]] = field(default_factory=list)

    ip: str = ""
    port: int = 0

    runtime: float = 0

    response_body_length: int = 0
    response_body_is_truncated: bool = False
    response_body_sha1: str = ""
    response_body_bytes: bytes = b""

    response_status_code: int = 0
    response_headers_list: List[Tuple[str, bytes]] = field(default_factory=list)
    response_header_location: str = ""
    response_header_server: str = ""
    request_redirect_from: str = ""
    request_body_is_truncated: bool = False

    transaction_id: int = 0
    t: float = 0

    @property
    def request_is_encrypted(self):
        return self.request_url.startswith("https://")


@dataclass
class TLSObservation:
    timestamp: datetime

    failure: Failure
    success: bool

    server_name: str
    version: str
    cipher_suite: str

    ip: str = ""
    port: int = 0

    is_certificate_valid: bool = False

    end_entity_certificate_fingerprint: str = ""
    end_entity_certificate_subject: str = ""
    end_entity_certificate_subject_common_name: str = ""
    end_entity_certificate_issuer: str = ""
    end_entity_certificate_issuer_common_name: str = ""
    end_entity_certificate_san_list: List[str] = field(default_factory=list)
    end_entity_certificate_not_valid_after: Optional[datetime] = None
    end_entity_certificate_not_valid_before: Optional[datetime] = None
    peer_certificates: List[bytes] = field(default_factory=list)
    certificate_chain_length: int = 0
    certificate_chain_fingerprints: List[str] = field(default_factory=list)

    handshake_read_count: int = 0
    handshake_write_count: int = 0
    handshake_read_bytes: float = 0
    handshake_write_bytes: float = 0
    handshake_last_operation: str = ""
    handshake_time: float = 0

    transaction_id: int = 0
    t: float = 0


@dataclass
class DNSObservation:
    timestamp: datetime

    fqdn: str

    query_type: str
    failure: str = ""
    engine: str = ""
    engine_resolver_address: str = ""

    answer_type: str = ""
    answer: str = ""
    answer_asn: int = 0
    answer_as_org_name: str = ""

    transaction_id: int = 0
    t: float = 0


@dataclass
class TCPObservation:
    timestamp: datetime

    ip: str
    port: int

    success: bool
    failure: Failure

    t: float = 0
    transaction_id: int = 0


@table_model(
    table_name="obs_web_ctrl",
    table_index=(
        "measurement_start_time",
        "fqdn",
        "ip",
        "measurement_uid",
        "observation_idx",
    ),
)
@dataclass
class WebControlObservation:
    measurement_meta: MeasurementMeta
    processing_meta: ProcessingMeta

    fqdn: str = ""
    observation_idx: UInt8 = 0

    ip: str = ""
    port: UInt16 = 0

    ip_asn: UInt32 = 0
    ip_as_org_name: str = ""
    ip_as_cc: str = ""
    ip_cc: str = ""
    ip_is_bogon: bool = False

    dns_failure: str = ""
    dns_success: bool = False

    tcp_failure: str = ""
    tcp_success: bool = False

    tls_failure: str = ""
    tls_success: bool = False
    tls_server_name: str = ""

    http_request_url: str = ""
    http_failure: str = ""
    http_success: bool = False
    http_response_body_length: UInt32 = 0


@table_model(
    table_name="obs_web",
    table_index=(
        "measurement_start_time",
        "probe_cc",
        "probe_asn",
        "fqdn",
        "observation_idx",
        "measurement_uid",
    ),
)
@dataclass
class WebObservation:
    measurement_meta: MeasurementMeta
    probe_meta: ProbeMeta
    processing_meta: ProcessingMeta

    observation_idx: UInt16 = 0

    fqdn: str = ""
    target_id: str = ""

    transaction_id: UInt16 = 0

    ip: str = ""
    port: UInt16 = 0

    ip_asn: UInt32 = 0
    ip_as_org_name: str = ""
    ip_as_cc: str = ""
    ip_cc: str = ""
    ip_is_bogon: bool = False

    # DNS related observation
    dns_query_type: str = ""
    dns_failure: str = ""
    dns_engine: str = ""
    dns_engine_resolver_address: str = ""

    dns_answer_type: str = ""
    dns_answer: str = ""
    # These should match those in the IP field, but are the annotations coming
    # from the probe
    dns_answer_asn: UInt32 = 0
    dns_answer_as_org_name: str = ""
    dns_t: Float64 = 0

    # TCP related observation
    tcp_failure: str = ""
    tcp_success: bool = False
    tcp_t: Float64 = 0

    # TLS related observation
    tls_failure: str = ""
    tls_success: bool = False

    tls_server_name: str = ""
    tls_version: str = ""
    tls_cipher_suite: str = ""
    tls_is_certificate_valid: bool = False

    tls_end_entity_certificate_fingerprint: str = ""
    tls_end_entity_certificate_subject: str = ""
    tls_end_entity_certificate_subject_common_name: str = ""
    tls_end_entity_certificate_issuer: str = ""
    tls_end_entity_certificate_issuer_common_name: str = ""
    tls_end_entity_certificate_san_list: ArrayString = field(default_factory=list)
    tls_end_entity_certificate_not_valid_after: OptionalDatetime = None
    tls_end_entity_certificate_not_valid_before: OptionalDatetime = None
    tls_certificate_chain_length: int = 0
    tls_certificate_chain_fingerprints: ArrayString = field(default_factory=list)

    tls_handshake_read_count: UInt8 = 0
    tls_handshake_write_count: UInt8 = 0
    tls_handshake_read_bytes: UInt32 = 0
    tls_handshake_write_bytes: UInt32 = 0
    tls_handshake_last_operation: str = ""
    tls_handshake_time: Float64 = 0
    tls_t: Float64 = 0

    # HTTP related observation
    http_request_url: str = ""

    http_network: str = ""
    http_alpn: str = ""

    http_failure: str = ""

    http_request_body_length: UInt32 = 0
    http_request_method: str = ""

    http_runtime: Float64 = 0

    http_response_body_length: UInt32 = 0
    http_response_body_is_truncated: bool = False
    http_response_body_sha1: str = ""

    http_response_status_code: UInt16 = 0
    http_response_header_location: str = ""
    http_response_header_server: str = ""
    http_request_redirect_from: str = ""
    http_request_body_is_truncated: bool = False
    http_t: Float64 = 0

    # probe level analysis
    probe_analysis: str = ""

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

    # in > v5.0.0-alpha.4
    # important schema changes occurred in this table dropping a lot of nullable
    # columns. See diff for full changes
    # TODO(art): add link to diff


@table_model(
    table_name="obs_http_middlebox",
    table_index=("measurement_uid", "observation_idx", "measurement_start_time"),
)
@dataclass
class HTTPMiddleboxObservation:
    measurement_meta: MeasurementMeta
    probe_meta: ProbeMeta
    processing_meta: ProcessingMeta

    observation_idx: UInt16 = 0

    # Set the payload returned by the HTTP Invalid Request Line test
    hirl_sent_0: str = ""
    hirl_sent_1: str = ""
    hirl_sent_2: str = ""
    hirl_sent_3: str = ""
    hirl_sent_4: str = ""

    hirl_received_0: str = ""
    hirl_received_1: str = ""
    hirl_received_2: str = ""
    hirl_received_3: str = ""
    hirl_received_4: str = ""

    hirl_failure: str = ""
    hirl_success: bool = False

    hfm_diff: str = ""
    hfm_failure: str = ""
    hfm_success: bool = False
