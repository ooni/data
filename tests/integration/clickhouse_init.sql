CREATE TABLE ooni.fingerprints_dns
(
    `name` String,
    `scope` Enum8('nat' = 1, 'isp' = 2, 'prod' = 3, 'inst' = 4, 'vbw' = 5, 'fp' = 6),
    `other_names` String,
    `location_found` String,
    `pattern_type` Enum8('full' = 1, 'prefix' = 2, 'contains' = 3, 'regexp' = 4),
    `pattern` String,
    `confidence_no_fp` UInt8,
    `expected_countries` String,
    `source` String,
    `exp_url` String,
    `notes` String
)
ENGINE = EmbeddedRocksDB
PRIMARY KEY name;

CREATE TABLE ooni.fingerprints_http
(
    `name` String,
    `scope` Enum8('nat' = 1, 'isp' = 2, 'prod' = 3, 'inst' = 4, 'vbw' = 5, 'fp' = 6, 'injb' = 7, 'prov' = 8),
    `other_names` String,
    `location_found` String,
    `pattern_type` Enum8('full' = 1, 'prefix' = 2, 'contains' = 3, 'regexp' = 4),
    `pattern` String,
    `confidence_no_fp` UInt8,
    `expected_countries` String,
    `source` String,
    `exp_url` String,
    `notes` String
)
ENGINE = EmbeddedRocksDB
PRIMARY KEY name;

CREATE TABLE ooni.fastpath
(
    `measurement_uid` String,
    `report_id` String,
    `input` String,
    `probe_cc` LowCardinality(String),
    `probe_asn` Int32,
    `test_name` LowCardinality(String),
    `test_start_time` DateTime,
    `measurement_start_time` DateTime,
    `filename` String,
    `scores` String,
    `platform` String,
    `anomaly` String,
    `confirmed` String,
    `msm_failure` String,
    `domain` String,
    `software_name` String,
    `software_version` String,
    `control_failure` String,
    `blocking_general` Float32,
    `is_ssl_expected` Int8,
    `page_len` Int32,
    `page_len_ratio` Float32,
    `server_cc` String,
    `server_asn` Int8,
    `server_as_name` String,
    `update_time` DateTime64(3) MATERIALIZED now64(),
    `test_version` String,
    `architecture` String,
    `engine_name` LowCardinality(String),
    `engine_version` String,
    `test_runtime` Float32,
    `blocking_type` String,
    `test_helper_address` LowCardinality(String),
    `test_helper_type` LowCardinality(String),
    `ooni_run_link_id` Nullable(UInt64),
    `is_verified` LowCardinality(String) DEFAULT 'u',
    INDEX fastpath_rid_idx report_id TYPE minmax GRANULARITY 1,
    INDEX measurement_uid_idx measurement_uid TYPE minmax GRANULARITY 8
)
ENGINE = ReplacingMergeTree(update_time)
ORDER BY (measurement_start_time, report_id, input, measurement_uid)
SETTINGS index_granularity = 8192;

CREATE TABLE ooni.obs_openvpn
(
    `anomaly` Int8,
    `bootstrap_time` Float32,
    `confirmed` Int8,
    `error` String,
    `failure` String,
    `input` String,
    `last_handshake_transaction_id` Int32,
    `measurement_start_time` DateTime,
    `measurement_uid` String,
    `minivpn_version` String,
    `obfs4_version` String,
    `obfuscation` String,
    `platform` String,
    `probe_asn` Int32,
    `probe_cc` String,
    `probe_network_name` String,
    `provider` String,
    `remote` String,
    `report_id` String,
    `resolver_asn` Int32,
    `resolver_ip` String,
    `resolver_network_name` String,
    `software_name` String,
    `software_version` String,
    `success` Int8,
    `success_handshake` Int8,
    `success_icmp` Int8,
    `success_urlgrab` Int8,
    `tcp_connect_status_success` Int8,
    `test_runtime` Float32,
    `test_start_time` DateTime,
    `transport` String
)
ENGINE = ReplacingMergeTree(measurement_start_time)
ORDER BY (measurement_start_time, report_id, input)
SETTINGS index_granularity = 8;

CREATE TABLE ooni.event_detector_cusums
(
    `probe_asn` UInt32,
    `probe_cc` String,
    `domain` String,
    `ts` DateTime64(3, 'UTC'),
    `dns_isp_blocked_current_state` String DEFAULT 'ok',
    `dns_isp_blocked_s_pos` Nullable(Float64),
    `dns_isp_blocked_s_neg` Nullable(Float64),
    `dns_other_blocked_current_state` String DEFAULT 'ok',
    `dns_other_blocked_s_pos` Nullable(Float64),
    `dns_other_blocked_s_neg` Nullable(Float64),
    `tcp_blocked_current_state` String DEFAULT 'ok',
    `tcp_blocked_s_pos` Nullable(Float64),
    `tcp_blocked_s_neg` Nullable(Float64),
    `tls_blocked_current_state` String DEFAULT 'ok',
    `tls_blocked_s_pos` Nullable(Float64),
    `tls_blocked_s_neg` Nullable(Float64),
    `dns_isp_blocked_last_change` Int8 DEFAULT 0,
    `dns_isp_blocked_last_ts` Nullable(DateTime64(3, 'UTC')),
    `dns_other_blocked_last_change` Int8 DEFAULT 0,
    `dns_other_blocked_last_ts` Nullable(DateTime64(3, 'UTC')),
    `tcp_blocked_last_change` Int8 DEFAULT 0,
    `tcp_blocked_last_ts` Nullable(DateTime64(3, 'UTC')),
    `tls_blocked_last_change` Int8 DEFAULT 0,
    `tls_blocked_last_ts` Nullable(DateTime64(3, 'UTC'))
)
ENGINE = ReplacingMergeTree(ts)
ORDER BY (probe_asn, probe_cc, domain)
SETTINGS index_granularity = 8192;
