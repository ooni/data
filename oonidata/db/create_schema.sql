CREATE TABLE IF NOT EXISTS obs_dns (
    `measurement_uid` String,
    `observation_id` String,
    `session_id` String,
    `target` String,
    `timestamp` Datetime64(6),
    `probe_asn` Int32,
    `probe_cc` String,
    `probe_as_org_name` String,
    `probe_as_cc` String,
    `software_name` String,
    `software_version` String,
    `network_type` String,
    `platform` String,
    `origin` String,
    `resolver_asn` String,
    `resolver_ip` String,
    `resolver_cc` String,
    `resolver_as_org_name` String,
    `resolver_as_cc` String,
    `domain_name` String,
    `query_type` String,
    `answer_type` String,
    `answer` String,
    `answer_asn` Nullable(Int32),
    `answer_as_org_name` String,
    `answer_as_cc` String,
    `answer_cc` String,
    `answer_is_bogon` Nullable(bool),
    `failure` String,
    `fingerprint_id` String,
    `fingerprint_country_consistent` Nullable(bool),
    `is_tls_consistent` Nullable(bool)
    )

    ENGINE = ReplacingMergeTree
    ORDER BY (timestamp, measurement_uid, observation_id);

CREATE TABLE IF NOT EXISTS obs_tcp (
`measurement_uid` String,
`observation_id` String,
`session_id` String,
`target` String,
`timestamp` Datetime64(6),
`probe_asn` Int32,
`probe_cc` String,
`probe_as_org_name` String,
`probe_as_cc` String,
`software_name` String,
`software_version` String,
`network_type` String,
`platform` String,
`origin` String,
`resolver_asn` String,
`resolver_ip` String,
`resolver_cc` String,
`resolver_as_org_name` String,
`resolver_as_cc` String,
`domain_name` String,
`ip` String,
`port` Int32,
`ip_asn` Nullable(Int32),
`ip_as_org_name` String,
`ip_as_cc` String,
`ip_cc` String,
`failure` String
)

    ENGINE = ReplacingMergeTree
    ORDER BY (timestamp, measurement_uid, observation_id);

CREATE TABLE IF NOT EXISTS obs_tls (
`measurement_uid` String,
`observation_id` String,
`session_id` String,
`target` String,
`timestamp` Datetime64(6),
`probe_asn` Int32,
`probe_cc` String,
`probe_as_org_name` String,
`probe_as_cc` String,
`software_name` String,
`software_version` String,
`network_type` String,
`platform` String,
`origin` String,
`resolver_asn` String,
`resolver_ip` String,
`resolver_cc` String,
`resolver_as_org_name` String,
`resolver_as_cc` String,
`domain_name` String,
`ip` String,
`port` Int32,
`ip_asn` Nullable(Int32),
`ip_as_org_name` String,
`ip_as_cc` String,
`ip_cc` String,
`failure` String,
`server_name` String,
`tls_version` String,
`cipher_suite` String,
`is_certificate_valid` Nullable(bool),
`end_entity_certificate_fingerprint` String,
`end_entity_certificate_subject` String,
`end_entity_certificate_subject_common_name` String,
`end_entity_certificate_issuer` String,
`end_entity_certificate_issuer_common_name` String,
`end_entity_certificate_san_list` Array(String),
`end_entity_certificate_not_valid_after` Nullable(Datetime),
`end_entity_certificate_not_valid_before` Nullable(Datetime),
`certificate_chain_length` Nullable(Int32),
`tls_handshake_read_count` Nullable(Int32),
`tls_handshake_write_count` Nullable(Int32),
`tls_handshake_read_bytes` Nullable(Float64),
`tls_handshake_write_bytes` Nullable(Float64),
`tls_handshake_last_operation` String,
`tls_handshake_time` Nullable(Float64)
)

    ENGINE = ReplacingMergeTree
    ORDER BY (timestamp, measurement_uid, observation_id);

CREATE TABLE IF NOT EXISTS obs_http (
`measurement_uid` String,
`observation_id` String,
`session_id` String,
`target` String,
`timestamp` Datetime64(6),
`probe_asn` Int32,
`probe_cc` String,
`probe_as_org_name` String,
`probe_as_cc` String,
`software_name` String,
`software_version` String,
`network_type` String,
`platform` String,
`origin` String,
`resolver_asn` String,
`resolver_ip` String,
`resolver_cc` String,
`resolver_as_org_name` String,
`resolver_as_cc` String,

`domain_name` String,
`request_url` String,
`request_is_encrypted` bool,
`request_redirect_from` String,
`request_body_length` Int32,
`request_body_is_truncated` Nullable(bool),
`request_headers_list` Array(Array(String)),
`request_method` String,
`response_body_length` Nullable(Int32),
`response_body_is_truncated` Nullable(bool),
`response_body_sha1` String,
`response_body_title` String,
`response_body_meta_title` String,
`response_status_code` Nullable(Int32),
`response_headers_list` Array(Array(String)),
`response_header_location` String,
`response_header_server` String,
`failure` String,
`response_fingerprints` Array(String),
`fingerprint_country_consistent` Nullable(bool),
`response_matches_blockpage` Nullable(bool),
`response_matches_false_positive` Nullable(bool),
`x_transport` String
)

    ENGINE = ReplacingMergeTree
    ORDER BY (timestamp, measurement_uid, observation_id);



CREATE TABLE verdict (
`measurement_uid` String,
`verdict_uid` String,

`timestamp` Datetime64(6),
`probe_asn` Int32,
`probe_cc` String,
`probe_as_org_name` String,
`probe_as_cc` String,
`network_type` String,
`resolver_asn` String,
`resolver_ip` String,
`resolver_cc` String,
`resolver_as_org_name` String,
`resolver_as_cc` String,

`confidence` Float64,
`subject` String,
`subject_category` String,
`subject_detail` String,

`outcome` String,
`outcome_detail` String
)

ENGINE = ReplacingMergeTree
ORDER BY (timestamp, measurement_uid, verdict_uid);
