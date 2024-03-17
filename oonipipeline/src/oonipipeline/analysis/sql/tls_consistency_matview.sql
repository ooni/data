-- The mat view can be queried like so:
-- SELECT
--     ip,
--     tls_server_name,
--     anyMerge(ip_cc) as ip_cc,
--     anyMerge(ip_asn) as ip_asn,
--     anyMerge(ip_as_cc) as ip_as_cc,
--     anyMerge(ip_as_org_name) as ip_as_org_name,
--     sumMerge(msmt_cnt) as msmt_cnt,
--     uniqMerge(vp_cnt) as vp_cnt,
--     maxMerge(is_ctrl_vp) as is_ctrl_vp
-- FROM tls_consistency_matview
-- GROUP BY ip, tls_server_name
CREATE MATERIALIZED VIEW tls_consistency_matview
(
    ip String NOT NULL,
    tls_server_name String NOT NULL,
    -- Note: it seems like there are cases where this will change over time, so we are effectively picking any one of them
    ip_cc AggregateFunction(any, Nullable(String)),
    ip_asn AggregateFunction(any, Nullable(Int32)),
    ip_as_cc AggregateFunction(any, Nullable(String)),
    ip_as_org_name AggregateFunction(any, Nullable(String)),
    msmt_cnt AggregateFunction(sum, UInt64),
    vp_cnt AggregateFunction(uniq, UInt64),
    is_ctrl_vp AggregateFunction(max, UInt8)
)
ENGINE = AggregatingMergeTree()
ORDER BY (ip, tls_server_name)
POPULATE
AS SELECT 
IF(
    obs_web_ctrl.ip IS NOT NULL, 
    obs_web_ctrl.ip, 
    ctrl.ip
) as ip, 
IF(
    obs_web_ctrl.tls_server_name IS NOT NULL, 
    obs_web_ctrl.tls_server_name, 
    ctrl.tls_server_name
) as tls_server_name,
anyState(ip_cc) as ip_cc, 
anyState(ip_asn) as ip_asn, 
anyState(ip_as_cc) as ip_as_cc, 
anyState(ip_as_org_name) as ip_as_org_name,
sumState(obs_web_ctrl.msmt_cnt + ctrl.msmt_cnt) as msmt_cnt,
uniqState(obs_web_ctrl.vp_cnt + ctrl.vp_cnt) as vp_cnt,
maxState(IF(is_ctrl_vp = 1, 1, 0)) as is_ctrl_vp
FROM (
    SELECT 
    ip, ip_cc, ip_asn, ip_as_cc, ip_as_org_name, tls_server_name,
    COUNT() as msmt_cnt, 
    COUNT(DISTINCT probe_cc, probe_asn) as vp_cnt
    FROM obs_web
    WHERE tls_server_name IS NOT NULL
    AND tls_failure IS NULL
    AND ip IS NOT NULL
    GROUP BY ip, ip_cc, ip_asn, ip_as_cc, ip_as_org_name, tls_server_name
) as obs_web_ctrl
FULL OUTER JOIN
(
    SELECT 
    ip, tls_server_name, 
    COUNT() as msmt_cnt, 
    1 as vp_cnt,
    1 as is_ctrl_vp
    FROM obs_web_ctrl 
    WHERE 
    tls_success = 1
    AND tls_server_name IS NOT NULL
    AND ip IS NOT NULL
    GROUP BY ip, tls_server_name
) as ctrl
ON (
    ctrl.ip = obs_web_ctrl.ip 
    AND ctrl.tls_server_name = obs_web_ctrl.tls_server_name
)
GROUP BY ip, tls_server_name