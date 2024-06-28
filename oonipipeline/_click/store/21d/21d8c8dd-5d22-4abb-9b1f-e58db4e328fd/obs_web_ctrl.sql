ATTACH TABLE _ UUID '468c954c-9185-4d46-970f-f967ccbef749'
(
    `measurement_uid` String,
    `input` Nullable(String),
    `report_id` String,
    `measurement_start_time` DateTime64(3, 'UTC'),
    `software_name` String,
    `software_version` String,
    `test_name` String,
    `test_version` String,
    `hostname` String,
    `observation_id` String,
    `bucket_date` Nullable(String),
    `created_at` Nullable(DateTime64(3, 'UTC')),
    `ip` String,
    `port` Nullable(Int32),
    `ip_asn` Nullable(Int32),
    `ip_as_org_name` Nullable(String),
    `ip_as_cc` Nullable(String),
    `ip_cc` Nullable(String),
    `ip_is_bogon` Nullable(Int8),
    `dns_failure` Nullable(String),
    `dns_success` Nullable(Int8),
    `tcp_failure` Nullable(String),
    `tcp_success` Nullable(Int8),
    `tls_failure` Nullable(String),
    `tls_success` Nullable(Int8),
    `tls_server_name` Nullable(String),
    `http_request_url` Nullable(String),
    `http_failure` Nullable(String),
    `http_success` Nullable(Int8),
    `http_response_body_length` Nullable(Int32)
)
ENGINE = ReplacingMergeTree
ORDER BY (measurement_uid, observation_id, measurement_start_time)
SETTINGS index_granularity = 8192
