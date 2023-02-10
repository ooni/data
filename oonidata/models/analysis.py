from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional


@dataclass
class WebsiteAnalysis:
    __table_name__ = "website_analysis"
    __table_index__ = (
        "analysis_id",
        "measurement_uid",
        "observation_id",
        "measurement_start_time",
    )

    analysis_id: str
    measurement_uid: str
    observation_id: str
    report_id: str
    input: Optional[str]
    timestamp: datetime
    created_at: datetime

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

    ## These fields will be shared by multiple experiment results in a given
    ## measurement
    # Indicates the experiment group for this particular result, ex. im,
    # websites, circumvention
    experiment_group: str
    # The domain name for the specified target
    domain_name: str
    # A string indicating the name of the target, ex. Signal, Facebook website
    target_name: str

    ## These fields are unique to a particular experiment result
    # A string indicating the subject of this experiment result, for example an
    # IP:port combination.
    subject: str

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
    dns_consistency_system_answers: Optional[List[str]] = None
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
    dns_consistency_system_is_answer_fp_match: Optional[bool] = None
    dns_consistency_system_is_answer_fp_country_consistent: Optional[bool] = None
    dns_consistency_system_is_answer_fp_false_positive: Optional[bool] = None
    dns_consistency_system_is_resolver_probe_asn_match: Optional[bool] = None
    dns_consistency_system_is_resolver_probe_cc_match: Optional[bool] = None
    dns_consistency_system_answer_ip_ground_truth_asn_count: Optional[int] = None
    dns_consistency_system_answer_asn_ground_truth_asn_count: Optional[int] = None
    dns_consistency_other_answers: Optional[List[str]] = None
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
    http_is_http_fp_match: Optional[bool] = None
    http_is_http_fp_country_consistent: Optional[bool] = None
    http_is_http_fp_false_positive: Optional[bool] = None
