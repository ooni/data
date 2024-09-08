CLOUD_PROVIDERS_ASNS = [
    13335,  # Cloudflare: https://www.peeringdb.com/net/4224
    209242, #	Cloudflare London, LLC	
    20940,  # Akamai: https://www.peeringdb.com/net/2
    9002,  # Akamai RETN
    16625, # Akamai Technologies, Inc.	
    63949, # Akamai Technologies, Inc.	
    16509, #	Amazon.com, Inc.
    14618, #	Amazon.com, Inc.	
    15169, #	Google LLC
    396982,  # Google Cloud: https://www.peeringdb.com/net/30878
    54113, #	Fastly, Inc
    8075, # Microsoft Corporation
    8068, #	Microsoft Corporation
]

df_ctrl_exp = click_query("""
WITH
mapFilter((ip, _) -> (has(exp_dns_answer_records, ip) = 1), ctrl_tls_inconsistent_ips_map) as ctrl_tls_inconsistent_map,
mapFilter((ip, _) -> (has(exp_dns_answer_records, ip) = 1), ctrl_tls_consistent_ips_map) as ctrl_tls_consistent_map
SELECT
hostname,
measurement_uid,
probe_cc,
probe_asn,
exp_dns_answer_cloud_provider,
exp_dns_answer_matches_probe_cc,
exp_dns_answer_matches_probe_asn,
exp_dns_answer_bogon,
exp_dns_answer_record_count,
exp_dns_tls_consistent,
hasAny(ctrl_top8_ips, exp_dns_answer_records) as exp_dns_answer_matches_top8_ip_ctrl,
hasAny(ctrl_top3_asns, exp_dns_answer_asns) as exp_dns_answer_matches_top3_asn_ctrl,
ctrl_hostname,
ctrl_dns_answer_asns,
ctrl_dns_answer_ccs,
ctrl_dns_answer_bogon,
ctrl_dns_answer_record_count_q50,
ctrl_dns_answer_cloud_provider,
arraySum(
    mapValues(ctrl_tls_inconsistent_map)
) as ctrl_tls_inconsistent_datum_count,

arraySum(
    mapValues(ctrl_tls_consistent_map)
) as ctrl_tls_consistent_datum_count,
length(mapKeys(ctrl_tls_inconsistent_map)) as ctrl_tls_inconsistent_ip_count,
length(mapKeys(ctrl_tls_consistent_map)) as ctrl_tls_consistent_ip_count
FROM (
    WITH 
    groupUniqArray(ip_cc) as exp_dns_answer_ccs,
    max(ip_is_bogon) as exp_dns_answer_bogon,
    max(tls_is_certificate_valid) as exp_dns_tls_consistent
    SELECT 
    hostname,
    measurement_uid,
    probe_cc, 
    probe_asn,
    groupArray(dns_answer) as exp_dns_answer_records,
    groupUniqArray(ip_asn) as exp_dns_answer_asns,
    max(IF(ip_asn IN %(cloud_provider_asns)s, 1, 0)) exp_dns_answer_cloud_provider,
    has(exp_dns_answer_ccs, probe_cc) as exp_dns_answer_matches_probe_cc,
    has(exp_dns_answer_asns, probe_asn) as exp_dns_answer_matches_probe_asn,
    exp_dns_answer_bogon,
    --multiIf(answer_count_num <= 1, 'low', answer_count_num <= 4, 'med', 'high') as answer_count
    length(exp_dns_answer_records) exp_dns_answer_record_count,
    exp_dns_answer_records,
    exp_dns_tls_consistent
    FROM obs_web
    WHERE 
    dns_engine IN ('getaddrinfo', 'system', 'golang_net_resolver')
    AND measurement_start_time > '2024-08-01'
    AND measurement_start_time <= '2024-08-02'
    AND dns_answer IS NOT NULL
    GROUP BY measurement_uid, hostname, probe_cc, probe_asn
) AS exp
LEFT OUTER JOIN (
    SELECT 
    hostname as ctrl_hostname,
    groupUniqArrayArray(ctrl_dns_answer_ip_asns) as ctrl_dns_answer_asns,
    groupUniqArrayArray(ctrl_dns_answer_ccs) as ctrl_dns_answer_ccs,
    MAX(ctrl_dns_answer_bogon) as ctrl_dns_answer_bogon,
    quantile(0.5)(ctrl_dns_answer_record_count) as ctrl_dns_answer_record_count_q50,
    MAX(ctrl_dns_answer_cloud_provider) as ctrl_dns_answer_cloud_provider,
    CAST(sumMap(
        ctrl_tls_consistent_ips, arrayResize(CAST([], 'Array(UInt64)'), length(ctrl_tls_consistent_ips), 1)
    ), 'Map(String, UInt32)') as ctrl_tls_consistent_ips_map,
    CAST(sumMap(
        ctrl_tls_inconsistent_ips, arrayResize(CAST([], 'Array(UInt64)'), length(ctrl_tls_inconsistent_ips), 1)
    ), 'Map(String, UInt32)') as ctrl_tls_inconsistent_ips_map,
    topK(8)(arrayJoin(ctrl_dns_answer_records)) as ctrl_top8_ips,
    topK(3)(arrayJoin(ctrl_dns_answer_ip_asns)) as ctrl_top3_asns
    FROM (
        SELECT
        hostname,
        groupUniqArray(ip_cc) as ctrl_dns_answer_ccs,
        max(ip_is_bogon) as ctrl_dns_answer_bogon,
        groupArray(ip) as ctrl_dns_answer_records,
        groupUniqArray(ip_asn) as ctrl_dns_answer_ip_asns,
        length(ctrl_dns_answer_records) ctrl_dns_answer_record_count,
        max(IF(ip_asn IN %(cloud_provider_asns)s, 1, 0)) ctrl_dns_answer_cloud_provider,
        groupArrayIf(ip, tls_success = 1) as ctrl_tls_consistent_ips,
        groupArrayIf(ip, tls_success = 0 AND tls_failure LIKE 'ssl_%%') as ctrl_tls_inconsistent_ips
        FROM
        obs_web_ctrl 
        WHERE measurement_start_time > '2024-08-01'
        AND measurement_start_time <= '2024-08-02'
        AND dns_success = 1
        GROUP BY hostname, measurement_uid
    ) as t 
    GROUP BY hostname
) AS ctrl
ON ctrl.ctrl_hostname = exp.hostname
""", params={"cloud_provider_asns": CLOUD_PROVIDERS_ASNS})
