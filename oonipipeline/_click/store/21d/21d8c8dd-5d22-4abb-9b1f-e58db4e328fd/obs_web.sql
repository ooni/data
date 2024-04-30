ATTACH TABLE _ UUID '8b4d8f7e-73cf-400a-80ef-d9b5e012b4d6'
(
    `measurement_uid` String,
    `input` Nullable(String),
    `report_id` String,
    `measurement_start_time` DateTime64(3, 'UTC'),
    `software_name` String,
    `software_version` String,
    `test_name` String,
    `test_version` String,
    `probe_asn` Int32,
    `probe_cc` String,
    `probe_as_org_name` String,
    `probe_as_cc` String,
    `probe_as_name` String,
    `network_type` String,
    `platform` String,
    `origin` String,
    `engine_name` String,
    `engine_version` String,
    `architecture` String,
    `resolver_ip` String,
    `resolver_asn` Int32,
    `resolver_cc` String,
    `resolver_as_org_name` String,
    `resolver_as_cc` String,
    `resolver_is_scrubbed` Int8,
    `resolver_asn_probe` Int32,
    `resolver_as_org_name_probe` String,
    `bucket_date` Nullable(String),
    `observation_id` String,
    `created_at` Nullable(DateTime64(3, 'UTC')),
    `post_processed_at` Nullable(DateTime64(3, 'UTC')),
    `target_id` Nullable(String),
    `hostname` Nullable(String),
    `transaction_id` Nullable(Int32),
    `ip` Nullable(String),
    `port` Nullable(Int32),
    `ip_asn` Nullable(Int32),
    `ip_as_org_name` Nullable(String),
    `ip_as_cc` Nullable(String),
    `ip_cc` Nullable(String),
    `ip_is_bogon` Nullable(Int8),
    `dns_query_type` Nullable(String),
    `dns_failure` Nullable(String),
    `dns_engine` Nullable(String),
    `dns_engine_resolver_address` Nullable(String),
    `dns_answer_type` Nullable(String),
    `dns_answer` Nullable(String),
    `dns_answer_asn` Nullable(Int32),
    `dns_answer_as_org_name` Nullable(String),
    `dns_t` Nullable(Float64),
    `tcp_failure` Nullable(String),
    `tcp_success` Nullable(Int8),
    `tcp_t` Nullable(Float64),
    `tls_failure` Nullable(String),
    `tls_server_name` Nullable(String),
    `tls_version` Nullable(String),
    `tls_cipher_suite` Nullable(String),
    `tls_is_certificate_valid` Nullable(Int8),
    `tls_end_entity_certificate_fingerprint` Nullable(String),
    `tls_end_entity_certificate_subject` Nullable(String),
    `tls_end_entity_certificate_subject_common_name` Nullable(String),
    `tls_end_entity_certificate_issuer` Nullable(String),
    `tls_end_entity_certificate_issuer_common_name` Nullable(String),
    `tls_end_entity_certificate_san_list` Array(String),
    `tls_end_entity_certificate_not_valid_after` Nullable(DateTime64(3, 'UTC')),
    `tls_end_entity_certificate_not_valid_before` Nullable(DateTime64(3, 'UTC')),
    `tls_certificate_chain_length` Nullable(Int32),
    `tls_certificate_chain_fingerprints` Array(String),
    `tls_handshake_read_count` Nullable(Int32),
    `tls_handshake_write_count` Nullable(Int32),
    `tls_handshake_read_bytes` Nullable(Float64),
    `tls_handshake_write_bytes` Nullable(Float64),
    `tls_handshake_last_operation` Nullable(String),
    `tls_handshake_time` Nullable(Float64),
    `tls_t` Nullable(Float64),
    `http_request_url` Nullable(String),
    `http_network` Nullable(String),
    `http_alpn` Nullable(String),
    `http_failure` Nullable(String),
    `http_request_body_length` Nullable(Int32),
    `http_request_method` Nullable(String),
    `http_runtime` Nullable(Float64),
    `http_response_body_length` Nullable(Int32),
    `http_response_body_is_truncated` Nullable(Int8),
    `http_response_body_sha1` Nullable(String),
    `http_response_status_code` Nullable(Int32),
    `http_response_header_location` Nullable(String),
    `http_response_header_server` Nullable(String),
    `http_request_redirect_from` Nullable(String),
    `http_request_body_is_truncated` Nullable(Int8),
    `http_t` Nullable(Float64),
    `probe_analysis` Nullable(String),
    `pp_http_response_fingerprints` Array(String),
    `pp_http_fingerprint_country_consistent` Nullable(Int8),
    `pp_http_response_matches_blockpage` Int8,
    `pp_http_response_matches_false_positive` Int8,
    `pp_http_response_body_title` Nullable(String),
    `pp_http_response_body_meta_title` Nullable(String),
    `pp_dns_fingerprint_id` Nullable(String),
    `pp_dns_fingerprint_country_consistent` Nullable(Int8)
)
ENGINE = ReplacingMergeTree
ORDER BY (measurement_uid, observation_id, measurement_start_time)
SETTINGS index_granularity = 8192
