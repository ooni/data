ATTACH TABLE _ UUID '31cf36e4-07e0-4445-96b7-34e2f7d8b551'
(
    `measurement_uid` String,
    `observation_id_list` Array(String),
    `timeofday` DateTime64(3, 'UTC'),
    `created_at` DateTime64(3, 'UTC'),
    `location_network_type` String,
    `location_network_asn` Int32,
    `location_network_cc` String,
    `location_network_as_org_name` String,
    `location_network_as_cc` String,
    `location_resolver_asn` Nullable(Int32),
    `location_resolver_as_org_name` Nullable(String),
    `location_resolver_as_cc` Nullable(String),
    `location_resolver_cc` Nullable(String),
    `location_blocking_scope` Nullable(String),
    `target_nettest_group` String,
    `target_category` String,
    `target_name` String,
    `target_domain_name` String,
    `target_detail` String,
    `loni_ok_value` Float64,
    `loni_down_keys` Array(String),
    `loni_down_values` Array(Float64),
    `loni_blocked_keys` Array(String),
    `loni_blocked_values` Array(Float64),
    `loni_ok_keys` Array(String),
    `loni_ok_values` Array(Float64),
    `loni_list` String,
    `analysis_transcript_list` Array(Array(String)),
    `measurement_count` Int32,
    `observation_count` Int32,
    `vp_count` Int32,
    `anomaly` Nullable(Int8),
    `confirmed` Nullable(Int8)
)
ENGINE = ReplacingMergeTree
ORDER BY (measurement_uid, timeofday)
SETTINGS index_granularity = 8192
