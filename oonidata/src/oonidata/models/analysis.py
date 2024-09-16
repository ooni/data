from dataclasses import dataclass
import dataclasses
from datetime import datetime
from typing import List, Optional

from .base import table_model
from oonidata.models.observations import MeasurementMeta, ProbeMeta


@table_model(
    table_name="obs_web_analysis",
    table_index=(
        "analysis_id",
        "measurement_uid",
        "observation_id",
        "measurement_start_time",
    ),
)
@dataclass
class WebAnalysis:
    probe_meta: ProbeMeta
    measurement_meta: MeasurementMeta

    analysis_id: str
    observation_id: str

    created_at: datetime

    # This is the domain name associated with the target, for example for
    # facebook it will be www.facebook.com, but also edge-mqtt.facebook.com
    target_domain_name: str
    # This is the more granular level associated with a target, for example the IP, port tuple
    target_detail: str

    # dns_ground_truth_nxdomain_cc_asn: Optional[set] = None
    # dns_ground_truth_failure_cc_asn: Optional[set] = None
    # dns_ground_truth_ok_cc_asn: Optional[set] = None
    # dns_ground_truth_other_ips: Optional[Dict[str, set]] = None
    # dns_ground_truth_other_asns: Optional[Dict[str, set]] = None
    # dns_ground_truth_trusted_answers: Optional[Dict] = None
    dns_ground_truth_nxdomain_count: Optional[int] = None
    dns_ground_truth_failure_count: Optional[int] = None
    dns_ground_truth_ok_count: Optional[int] = None
    dns_ground_truth_ok_cc_asn_count: Optional[int] = None
    dns_ground_truth_failure_cc_asn_count: Optional[int] = None
    dns_ground_truth_nxdomain_cc_asn_count: Optional[int] = None
    dns_consistency_system_answers: List[str] = dataclasses.field(default_factory=list)
    dns_consistency_system_success: Optional[bool] = None
    dns_consistency_system_failure: Optional[str] = None
    dns_consistency_system_answer_count: Optional[int] = None
    dns_consistency_system_is_answer_tls_consistent: Optional[bool] = None
    dns_consistency_system_is_answer_tls_inconsistent: Optional[bool] = None
    dns_consistency_system_is_answer_ip_in_trusted_answers: Optional[bool] = None
    dns_consistency_system_is_answer_asn_in_trusted_answers: Optional[bool] = None
    dns_consistency_system_is_answer_asorg_in_trusted_answers: Optional[bool] = None
    dns_consistency_system_is_answer_cloud_provider: Optional[bool] = None
    dns_consistency_system_is_answer_probe_asn_match: Optional[bool] = None
    dns_consistency_system_is_answer_probe_cc_match: Optional[bool] = None
    dns_consistency_system_is_answer_bogon: Optional[bool] = None
    dns_consistency_system_answer_fp_name: Optional[str] = None
    dns_consistency_system_answer_fp_scope: Optional[str] = None
    dns_consistency_system_is_answer_fp_match: Optional[bool] = None
    dns_consistency_system_is_answer_fp_country_consistent: Optional[bool] = None
    dns_consistency_system_is_answer_fp_false_positive: Optional[bool] = None
    dns_consistency_system_is_resolver_probe_asn_match: Optional[bool] = None
    dns_consistency_system_is_resolver_probe_cc_match: Optional[bool] = None
    dns_consistency_system_answer_ip_ground_truth_asn_count: Optional[int] = None
    dns_consistency_system_answer_asn_ground_truth_asn_count: Optional[int] = None
    dns_consistency_other_answers: List[str] = dataclasses.field(default_factory=list)
    dns_consistency_other_success: Optional[bool] = None
    dns_consistency_other_failure: Optional[str] = None
    dns_consistency_other_answer_count: Optional[int] = None
    dns_consistency_other_is_answer_tls_consistent: Optional[bool] = None
    dns_consistency_other_is_answer_tls_inconsistent: Optional[bool] = None
    dns_consistency_other_is_answer_ip_in_trusted_answers: Optional[bool] = None
    dns_consistency_other_is_answer_asn_in_trusted_answers: Optional[bool] = None
    dns_consistency_other_is_answer_asorg_in_trusted_answers: Optional[bool] = None
    dns_consistency_other_is_answer_cloud_provider: Optional[bool] = None
    dns_consistency_other_is_answer_probe_asn_match: Optional[bool] = None
    dns_consistency_other_is_answer_probe_cc_match: Optional[bool] = None
    dns_consistency_other_is_answer_bogon: Optional[bool] = None
    dns_consistency_other_answer_fp_name: Optional[str] = None
    dns_consistency_other_answer_fp_scope: Optional[str] = None
    dns_consistency_other_is_answer_fp_match: Optional[bool] = None
    dns_consistency_other_is_answer_fp_country_consistent: Optional[bool] = None
    dns_consistency_other_is_answer_fp_false_positive: Optional[bool] = None
    dns_consistency_other_is_resolver_probe_asn_match: Optional[bool] = None
    dns_consistency_other_is_resolver_probe_cc_match: Optional[bool] = None
    dns_consistency_other_answer_ip_ground_truth_asn_count: Optional[int] = None
    dns_consistency_other_answer_asn_ground_truth_asn_count: Optional[int] = None
    tls_success: Optional[bool] = None
    tls_failure: Optional[str] = None
    tls_is_tls_certificate_valid: Optional[bool] = None
    tls_is_tls_certificate_invalid: Optional[bool] = None
    tls_handshake_read_count: Optional[int] = None
    tls_handshake_write_count: Optional[int] = None
    tls_handshake_read_bytes: Optional[float] = None
    tls_handshake_write_bytes: Optional[float] = None
    tls_handshake_time: Optional[float] = None
    tls_ground_truth_failure_count: Optional[int] = None
    tls_ground_truth_failure_asn_cc_count: Optional[int] = None
    tls_ground_truth_ok_count: Optional[int] = None
    tls_ground_truth_ok_asn_cc_count: Optional[int] = None
    tls_ground_truth_trusted_failure_count: Optional[int] = None
    tls_ground_truth_trusted_ok_count: Optional[int] = None
    tcp_address: Optional[str] = None
    tcp_success: Optional[bool] = None
    tcp_failure: Optional[str] = None
    tcp_ground_truth_failure_count: Optional[int] = None
    tcp_ground_truth_failure_asn_cc_count: Optional[int] = None
    tcp_ground_truth_ok_count: Optional[int] = None
    tcp_ground_truth_ok_asn_cc_count: Optional[int] = None
    tcp_ground_truth_trusted_failure_count: Optional[int] = None
    tcp_ground_truth_trusted_ok_count: Optional[int] = None
    http_success: Optional[bool] = None
    http_failure: Optional[str] = None
    http_is_http_request_encrypted: Optional[bool] = None
    http_response_body_proportion: Optional[float] = None
    http_response_body_length: Optional[int] = None
    http_response_status_code: Optional[int] = None
    http_ground_truth_failure_count: Optional[int] = None
    http_ground_truth_failure_asn_cc_count: Optional[int] = None
    http_ground_truth_ok_count: Optional[int] = None
    http_ground_truth_ok_asn_cc_count: Optional[int] = None
    http_ground_truth_trusted_ok_count: Optional[int] = None
    http_ground_truth_trusted_failure_count: Optional[int] = None
    http_ground_truth_body_length: Optional[int] = None
    http_fp_name: Optional[str] = None
    http_fp_scope: Optional[str] = None
    http_is_http_fp_match: Optional[bool] = None
    http_is_http_fp_country_consistent: Optional[bool] = None
    http_is_http_fp_false_positive: Optional[bool] = None
