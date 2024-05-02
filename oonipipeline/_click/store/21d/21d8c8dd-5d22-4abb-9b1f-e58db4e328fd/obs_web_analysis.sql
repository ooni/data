ATTACH TABLE _ UUID 'd179d5c4-a446-4ed0-9ba1-211afb536c90'
(
    `analysis_id` String,
    `measurement_uid` String,
    `observation_id` String,
    `measurement_start_time` DateTime64(3, 'UTC'),
    `created_at` DateTime64(3, 'UTC'),
    `probe_asn` Int32,
    `probe_cc` String,
    `probe_as_org_name` String,
    `probe_as_cc` String,
    `network_type` String,
    `resolver_ip` Nullable(String),
    `resolver_asn` Nullable(Int32),
    `resolver_as_org_name` Nullable(String),
    `resolver_as_cc` Nullable(String),
    `resolver_cc` Nullable(String),
    `target_domain_name` String,
    `target_detail` String,
    `dns_ground_truth_nxdomain_count` Nullable(Int32),
    `dns_ground_truth_failure_count` Nullable(Int32),
    `dns_ground_truth_ok_count` Nullable(Int32),
    `dns_ground_truth_ok_cc_asn_count` Nullable(Int32),
    `dns_ground_truth_failure_cc_asn_count` Nullable(Int32),
    `dns_ground_truth_nxdomain_cc_asn_count` Nullable(Int32),
    `dns_consistency_system_answers` Array(String),
    `dns_consistency_system_success` Nullable(Int8),
    `dns_consistency_system_failure` Nullable(String),
    `dns_consistency_system_answer_count` Nullable(Int32),
    `dns_consistency_system_is_answer_tls_consistent` Nullable(Int8),
    `dns_consistency_system_is_answer_tls_inconsistent` Nullable(Int8),
    `dns_consistency_system_is_answer_ip_in_trusted_answers` Nullable(Int8),
    `dns_consistency_system_is_answer_asn_in_trusted_answers` Nullable(Int8),
    `dns_consistency_system_is_answer_asorg_in_trusted_answers` Nullable(Int8),
    `dns_consistency_system_is_answer_cloud_provider` Nullable(Int8),
    `dns_consistency_system_is_answer_probe_asn_match` Nullable(Int8),
    `dns_consistency_system_is_answer_probe_cc_match` Nullable(Int8),
    `dns_consistency_system_is_answer_bogon` Nullable(Int8),
    `dns_consistency_system_answer_fp_name` Nullable(String),
    `dns_consistency_system_answer_fp_scope` Nullable(String),
    `dns_consistency_system_is_answer_fp_match` Nullable(Int8),
    `dns_consistency_system_is_answer_fp_country_consistent` Nullable(Int8),
    `dns_consistency_system_is_answer_fp_false_positive` Nullable(Int8),
    `dns_consistency_system_is_resolver_probe_asn_match` Nullable(Int8),
    `dns_consistency_system_is_resolver_probe_cc_match` Nullable(Int8),
    `dns_consistency_system_answer_ip_ground_truth_asn_count` Nullable(Int32),
    `dns_consistency_system_answer_asn_ground_truth_asn_count` Nullable(Int32),
    `dns_consistency_other_answers` Array(String),
    `dns_consistency_other_success` Nullable(Int8),
    `dns_consistency_other_failure` Nullable(String),
    `dns_consistency_other_answer_count` Nullable(Int32),
    `dns_consistency_other_is_answer_tls_consistent` Nullable(Int8),
    `dns_consistency_other_is_answer_tls_inconsistent` Nullable(Int8),
    `dns_consistency_other_is_answer_ip_in_trusted_answers` Nullable(Int8),
    `dns_consistency_other_is_answer_asn_in_trusted_answers` Nullable(Int8),
    `dns_consistency_other_is_answer_asorg_in_trusted_answers` Nullable(Int8),
    `dns_consistency_other_is_answer_cloud_provider` Nullable(Int8),
    `dns_consistency_other_is_answer_probe_asn_match` Nullable(Int8),
    `dns_consistency_other_is_answer_probe_cc_match` Nullable(Int8),
    `dns_consistency_other_is_answer_bogon` Nullable(Int8),
    `dns_consistency_other_answer_fp_name` Nullable(String),
    `dns_consistency_other_answer_fp_scope` Nullable(String),
    `dns_consistency_other_is_answer_fp_match` Nullable(Int8),
    `dns_consistency_other_is_answer_fp_country_consistent` Nullable(Int8),
    `dns_consistency_other_is_answer_fp_false_positive` Nullable(Int8),
    `dns_consistency_other_is_resolver_probe_asn_match` Nullable(Int8),
    `dns_consistency_other_is_resolver_probe_cc_match` Nullable(Int8),
    `dns_consistency_other_answer_ip_ground_truth_asn_count` Nullable(Int32),
    `dns_consistency_other_answer_asn_ground_truth_asn_count` Nullable(Int32),
    `tls_success` Nullable(Int8),
    `tls_failure` Nullable(String),
    `tls_is_tls_certificate_valid` Nullable(Int8),
    `tls_is_tls_certificate_invalid` Nullable(Int8),
    `tls_handshake_read_count` Nullable(Int32),
    `tls_handshake_write_count` Nullable(Int32),
    `tls_handshake_read_bytes` Nullable(Float64),
    `tls_handshake_write_bytes` Nullable(Float64),
    `tls_handshake_time` Nullable(Float64),
    `tls_ground_truth_failure_count` Nullable(Int32),
    `tls_ground_truth_failure_asn_cc_count` Nullable(Int32),
    `tls_ground_truth_ok_count` Nullable(Int32),
    `tls_ground_truth_ok_asn_cc_count` Nullable(Int32),
    `tls_ground_truth_trusted_failure_count` Nullable(Int32),
    `tls_ground_truth_trusted_ok_count` Nullable(Int32),
    `tcp_address` Nullable(String),
    `tcp_success` Nullable(Int8),
    `tcp_failure` Nullable(String),
    `tcp_ground_truth_failure_count` Nullable(Int32),
    `tcp_ground_truth_failure_asn_cc_count` Nullable(Int32),
    `tcp_ground_truth_ok_count` Nullable(Int32),
    `tcp_ground_truth_ok_asn_cc_count` Nullable(Int32),
    `tcp_ground_truth_trusted_failure_count` Nullable(Int32),
    `tcp_ground_truth_trusted_ok_count` Nullable(Int32),
    `http_success` Nullable(Int8),
    `http_failure` Nullable(String),
    `http_is_http_request_encrypted` Nullable(Int8),
    `http_response_body_proportion` Nullable(Float64),
    `http_response_body_length` Nullable(Int32),
    `http_response_status_code` Nullable(Int32),
    `http_ground_truth_failure_count` Nullable(Int32),
    `http_ground_truth_failure_asn_cc_count` Nullable(Int32),
    `http_ground_truth_ok_count` Nullable(Int32),
    `http_ground_truth_ok_asn_cc_count` Nullable(Int32),
    `http_ground_truth_trusted_ok_count` Nullable(Int32),
    `http_ground_truth_trusted_failure_count` Nullable(Int32),
    `http_ground_truth_body_length` Nullable(Int32),
    `http_fp_name` Nullable(String),
    `http_fp_scope` Nullable(String),
    `http_is_http_fp_match` Nullable(Int8),
    `http_is_http_fp_country_consistent` Nullable(Int8),
    `http_is_http_fp_false_positive` Nullable(Int8)
)
ENGINE = ReplacingMergeTree
ORDER BY (analysis_id, measurement_uid, observation_id, measurement_start_time)
SETTINGS index_granularity = 8192