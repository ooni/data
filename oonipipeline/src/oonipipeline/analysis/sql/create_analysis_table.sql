CREATE TABLE ooni.analysis_web_measurement ON CLUSTER oonidata_cluster
(
    `domain` String, `input` String, `test_name` String,
    `probe_asn` UInt32, `probe_cc` String,
    `resolver_asn` UInt32, `resolver_as_cc` String, `network_type` String, 
    `measurement_start_time` DateTime64(3, 'UTC'), 
    `measurement_uid` String, `top_probe_analysis` Nullable(String), 
    `top_dns_failure` Nullable(String), 
    `top_tcp_failure` Nullable(String), `top_tls_failure` Nullable(String), 
    `dns_blocked_max` Float32, `dns_down_max` Float32, `dns_ok_max` Float32, 
    `tcp_blocked_max` Float32, `tcp_down_max` Float32, `tcp_ok_max` Float32, 
    `tls_blocked_max` Float32, `tls_down_max` Float32, `tls_ok_max` Float32
)
ENGINE = ReplacingMergeTree
PRIMARY KEY measurement_uid
ORDER BY (measurement_uid, measurement_start_time, probe_cc, probe_asn)
SETTINGS index_granularity = 8192