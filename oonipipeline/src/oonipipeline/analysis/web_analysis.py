import logging

from datetime import datetime
from typing import Any, Dict, List, Optional

from ..db.connections import ClickhouseConnection
from .rules import (
    DNS_RULES,
    TCP_RULES,
    TLS_RULES,
    render_evidence_multiif,
    render_outcome_multiif,
    render_rule_id_multiif,
    render_top_rule_argmax,
)

log = logging.getLogger(__name__)

CLOUD_PROVIDERS_ASNS = [
    13335,  # Cloudflare: https://www.peeringdb.com/net/4224
    209242,  # 	Cloudflare London, LLC
    20940,  # Akamai: https://www.peeringdb.com/net/2
    9002,  # Akamai RETN
    16625,  # Akamai Technologies, Inc.
    63949,  # Akamai Technologies, Inc.
    16509,  # 	Amazon.com, Inc.
    14618,  # 	Amazon.com, Inc.
    15169,  # 	Google LLC
    396982,  # Google Cloud: https://www.peeringdb.com/net/30878
    54113,  # 	Fastly, Inc
    8075,  # Microsoft Corporation
    8068,  # 	Microsoft Corporation
]


def format_query_analysis_web_fuzzy_logic(
    start_time: datetime,
    end_time: datetime,
    probe_cc: List[str],
    # We are only doing web_connectivity for the moment
    test_name: List[str] = ["web_connectivity"],
    measurement_uid: Optional[str] = None,
):
    q_params: Dict[str, Any] = {
        "start_time": start_time,
        "end_time": end_time,
        "cloud_provider_asns": CLOUD_PROVIDERS_ASNS,
    }
    and_where = [
        "measurement_start_time > %(start_time)s",
        "measurement_start_time <= %(end_time)s",
    ]
    if len(probe_cc) > 0:
        and_where.append("probe_cc IN %(probe_cc)s")
        q_params["probe_cc"] = probe_cc
    if len(test_name) > 0:
        and_where.append("test_name IN %(test_name)s")
        q_params["test_name"] = test_name
    if measurement_uid is not None:
        and_where.append("measurement_uid = %(measurement_uid)s")
        q_params["measurement_uid"] = measurement_uid

    where_clause = " AND ".join(and_where)

    SQL = f"""
    WITH
    hasAny(union_tls_consistent_ips, dns_answers) as dns_tls_consistent,
    hasAny(mapKeys(ctrl_tls_inconsistent_ips), dns_answers) as dns_tls_inconsistent,
    hasAny(mapKeys(ctrl_dns_answers), dns_answers) as dns_answer_matches_ctrl,
    hasAny(mapKeys(ctrl_dns_answers_asns), dns_answers_asns) as dns_answer_asn_matches_ctrl,
    IF(dns_answers_contain_bogon IS NULL, 0, dns_answers_contain_bogon) as dns_answers_contain_bogon,

    cloud_provider_ips_count,
    not_cloud_provider_ips_count,

    --union_tls_consistent_ips,
    --ctrl_dns_answers,

    ctrl_dns_failure_count,
    ctrl_dns_success_count,
    ctrl_dns_success_count/(ctrl_dns_failure_count+ctrl_dns_success_count) as ctrl_dns_success_rate,

    --ctrl_tls_success_ips,
    ctrl_tls_success_ips[ip] as ctrl_tls_success_count,
    arraySum(mapValues(ctrl_tls_success_ips)) as ctrl_tls_success_sum,
    length(mapValues(ctrl_tls_success_ips)) as ctrl_tls_success_ip_count,

    --ctrl_tls_inconsistent_ips,

    ctrl_tls_inconsistent_ips[ip] as ctrl_tls_inconsistent_count,
    arraySum(mapValues(ctrl_tls_inconsistent_ips)) as ctrl_tls_inconsistent_sum,

    --ctrl_tls_failing_ips,
    ctrl_tls_failing_ips[ip] as ctrl_tls_failing_count,
    arraySum(mapValues(ctrl_tls_failing_ips)) as ctrl_tls_failing_sum,
    length(mapValues(ctrl_tls_failing_ips)) as ctrl_tls_failing_ip_count,

    --ctrl_tls_success_rates,
    ctrl_tls_success_rates[ip] as ctrl_tls_success_rate,

    --ctrl_tcp_success_ips,
    ctrl_tcp_success_ips[ip] as ctrl_tcp_success_count,
    arraySum(mapValues(ctrl_tcp_success_ips)) as ctrl_tcp_success_sum,
    length(mapValues(ctrl_tcp_success_ips)) as ctrl_tcp_success_ip_count,

    --ctrl_tcp_failing_ips,
    ctrl_tcp_failing_ips[ip] as ctrl_tcp_failing_count,
    arraySum(mapValues(ctrl_tcp_failing_ips)) as ctrl_tcp_failing_sum,
    length(mapValues(ctrl_tcp_failing_ips)) as ctrl_tcp_failing_ip_count,

    --ctrl_tcp_success_rates,
    ctrl_tcp_success_rates[ip] as ctrl_tcp_success_rate,

    expected_countries,
    dns_blocking_scope,
    -- A 'fp' scope marks a fingerprint that is known to produce false
    -- positives, so matching one is evidence *against* blocking and must not
    -- trigger the blockpage rule. The DNS fingerprint set happens to carry no
    -- 'fp' rows today, but the HTTP set does and the schema permits them here.
    -- On a LEFT JOIN miss dns_blocking_scope is '' and expected_countries is
    -- empty, so the has() below is false either way.
    dns_blocking_scope != 'fp'
        AND has(expected_countries, probe_cc) as dns_blocking_country_consistent,

    -- Possibility distributions of states (blocking, down, ok). The rule set and
    -- its weights live in analysis/rules.py; all three cascades below are
    -- generated from there off the same conditions in the same order, so a row's
    -- rule id and evidence level always belong to the rule that scored it.
    -- *_evidence says whether the layer produced data at all, which the (0, 0, 0)
    -- outcome cannot distinguish from a clean result.
    {render_outcome_multiif(DNS_RULES)} as dns_outcome,
    {render_rule_id_multiif(DNS_RULES)} as dns_rule_id,
    {render_evidence_multiif(DNS_RULES)} as dns_evidence,

    {render_outcome_multiif(TCP_RULES)} as tcp_outcome,
    {render_rule_id_multiif(TCP_RULES)} as tcp_rule_id,
    {render_evidence_multiif(TCP_RULES)} as tcp_evidence,

    {render_outcome_multiif(TLS_RULES)} as tls_outcome,
    {render_rule_id_multiif(TLS_RULES)} as tls_rule_id,
    {render_evidence_multiif(TLS_RULES)} as tls_evidence,

    ip,
    ip_asn,
    ip_is_bogon,
    ip_is_v6,

    tcp_ipv6_failure_rate,
    tcp_ipv4_failure_rate,
    tcp_success,
    tcp_t,
    http_failure,

    dns_outcome.1 as dns_blocked,
    dns_outcome.2 as dns_down,
    dns_outcome.3 as dns_ok,

    tcp_failure,
    tcp_outcome.1 as tcp_blocked,
    tcp_outcome.2 as tcp_down,
    tcp_outcome.3 as tcp_ok,

    tls_failure,
    tls_outcome.1 as tls_blocked,
    tls_outcome.2 as tls_down,
    tls_outcome.3 as tls_ok

    SELECT
    -- We parse the domain from the input, like the current pipeline would.
    -- It's not possible to get it from the hostname column, because if the
    -- measurement included a redirect chain, we might have tested domains different
    -- than that inside of the input field.
    domain(input) as domain,
    input, test_name,
    probe_asn, probe_as_org_name, probe_cc,
    resolver_asn, resolver_as_cc,
    network_type,
    measurement_start_time,
    measurement_uid,
    ooni_run_link_id,

    anyHeavy(probe_analysis) as top_probe_analysis,

    anyHeavy(dns_failure) as top_dns_failure,
    anyHeavy(tcp_failure) as top_tcp_failure,
    anyHeavy(tls_failure) as top_tls_failure,

    max(dns_blocked) as dns_blocked_max,
    max(dns_down) as dns_down_max,
    max(dns_ok) as dns_ok_max,
    -- IF(
    --     dns_blocked > (dns_down + dns_ok),
    --     concat('dns.', IF(top_dns_failure IS NOT NULL, top_dns_failure, 'none')
    -- ), ''),

    max(tcp_blocked) as tcp_blocked_max,
    max(tcp_down) as tcp_down_max,
    max(tcp_ok) as tcp_ok_max,

    max(tls_blocked) as tls_blocked_max,
    max(tls_down) as tls_down_max,
    max(tls_ok) as tls_ok_max,

    -- The rule that drove this measurement's verdict, ranked so that the rows
    -- carrying no data for a layer cannot outrank the rows that do. See
    -- render_top_rule_argmax.
    {render_top_rule_argmax("dns")},
    {render_top_rule_argmax("tcp")},
    {render_top_rule_argmax("tls")},

    -- Constant within a measurement, so it rides along in the GROUP BY rather
    -- than needing an aggregate.
    probe_id

    FROM (
        WITH
        isIPv4String(ip) as ip_is_v4,
        isIPv6String(ip) as ip_is_v6

        SELECT
        measurement_uid,
        ooni_run_link_id,
        report_id,
        hostname,
        input,
        probe_asn, probe_as_org_name, probe_cc, resolver_asn, resolver_as_cc, network_type,
        probe_id,
        measurement_start_time, test_name,
        toStartOfDay(measurement_start_time) as measurement_day,

        ip,
        ip_asn,
        ip_is_bogon,
        ip_is_v6,
        dns_failure,
        dns_answer,

        -- We limit this to only the system resolver
        -- TODO: in order to fully support web_connectivity 0.5 we should ideally
        -- parse this as well.
        groupArrayIf(dns_answer, dns_engine IN ('getaddrinfo', 'system') AND (ip_is_v6 OR ip_is_v4)) over (partition by measurement_uid, hostname, ip_is_v6) as dns_answers,
        groupArrayIf(ip_asn, dns_engine IN ('getaddrinfo', 'system') AND (ip_is_v6 OR ip_is_v4)) over (partition by measurement_uid, hostname, ip_is_v6) as dns_answers_asns,
        maxIf(ip_is_bogon, dns_engine IN ('getaddrinfo', 'system') AND (ip_is_v6 OR ip_is_v4)) over (partition by measurement_uid, hostname, ip_is_v6) as dns_answers_contain_bogon,

        countIf(ip_asn IN %(cloud_provider_asns)s) over (partition by measurement_uid) as dns_answers_cloud,

        -- We use these to get an indication of whether IPv6 is entirely broken in
        -- this probe.
        -- TODO: in the future we could use something other than report_id, but
        -- closer to "run_id" to get all measurements from a particular probe at a
        -- given time interval
        countIf(ip_is_v6 AND tcp_failure IS NOT NULL) over (partition by report_id) as tcp_ipv6_failure_count,
        countIf(ip_is_v6 AND tcp_success = 1) over (partition by report_id) as tcp_ipv6_success_count,

        countIf(ip_is_v4 AND tcp_success = 1) over (partition by report_id) as tcp_ipv4_success_count,
        countIf(ip_is_v4 AND tcp_failure IS NOT NULL) over (partition by report_id) as tcp_ipv4_failure_count,

        tcp_ipv6_failure_count/(tcp_ipv6_success_count+tcp_ipv6_failure_count) as tcp_ipv6_failure_rate,
        tcp_ipv4_failure_count/(tcp_ipv4_success_count+tcp_ipv4_failure_count) as tcp_ipv4_failure_rate,

        tcp_success,
        tcp_failure,
        tcp_t,
        tls_is_certificate_valid,
        tls_failure,
        tls_handshake_time,
        http_failure,
        probe_analysis

        FROM
        obs_web
        WHERE

        {where_clause}
    ) as experiment

    LEFT OUTER JOIN (
        SELECT
        -- expected_countries is a comma-separated string upstream, documented
        -- with a space after the comma (e.g. "IT, IR"). groupArray alone would
        -- produce ['IT, IR'], against which has(..., 'IR') is false — so split
        -- and trim before the membership test. Every current DNS fingerprint
        -- names a single country, which is why this has not bitten yet.
        arrayDistinct(
            arrayFlatten(
                groupArray(
                    arrayMap(
                        c -> trim(BOTH ' ' FROM c),
                        splitByChar(',', expected_countries)
                    )
                )
            )
        ) as expected_countries,
        pattern,
        any(scope) as dns_blocking_scope
        FROM fingerprints_dns
        -- The join below is an equality match, which only implements
        -- pattern_type = 'full'. Restricting here keeps that explicit rather
        -- than silently never matching a 'prefix'/'contains'/'regexp' row.
        -- All 227 current DNS fingerprints are 'full'; tests/test_fingerprints.py
        -- fails if upstream introduces a type this query cannot evaluate.
        WHERE pattern_type = 'full'
        GROUP BY pattern
    ) as fingerprints_dns
    ON fingerprints_dns.pattern = experiment.dns_answer

    -- CTRL subquery
    LEFT OUTER JOIN (
        SELECT
        hostname,
        measurement_day,
        cloud_provider_ips_count,
        not_cloud_provider_ips_count,

        arrayDistinct(
            arrayConcat(mapKeys(ctrl_tls_success_ips), other_tls_consistent_ips)
        ) as union_tls_consistent_ips,

        ctrl_dns_answers,
        ctrl_dns_answers_asns,
        ctrl_dns_failure_count,
        ctrl_dns_success_count,
        ctrl_tls_success_ips,
        ctrl_tls_inconsistent_ips,
        ctrl_tls_failing_ips,

        CAST(
            arrayMap(
                (ip) -> (ip, (ctrl_tls_success_ips[ip]/(ctrl_tls_success_ips[ip] + ctrl_tls_failing_ips[ip]))),
                arrayConcat(mapKeys(ctrl_tls_success_ips), mapKeys(ctrl_tls_failing_ips))
            ),
            'Map(String, Float32)'
        ) as ctrl_tls_success_rates,

        ctrl_tcp_success_ips,
        ctrl_tcp_failing_ips,
        CAST(
            arrayMap(
                (ip) -> (ip, (ctrl_tcp_success_ips[ip]/(ctrl_tcp_success_ips[ip] + ctrl_tcp_failing_ips[ip]))),
                arrayConcat(mapKeys(ctrl_tcp_success_ips), mapKeys(ctrl_tcp_failing_ips))
            ),
            'Map(String, Float32)'
        ) as ctrl_tcp_success_rates

        FROM
        (
            WITH
            CAST(
                ([ip], [1]),
                'Map(String, UInt32)'
            ) as ip_map,

            CAST(
                ([IF(ip_asn IS NULL, 0, ip_asn)], [1]),
                'Map(UInt32, UInt32)'
            ) as ip_asn_map

            SELECT
            hostname,
            toStartOfDay(measurement_start_time) as measurement_day,

            -- if the answer was inside of a cloud provider ASN
            -- TODO: we aren't using it as part of the analysis.
            length(groupUniqArrayIf(ip, ip_asn IN %(cloud_provider_asns)s)) as cloud_provider_ips_count,
            length(groupUniqArrayIf(ip, ip_asn NOT IN %(cloud_provider_asns)s)) as not_cloud_provider_ips_count,

            -- list of DNS failures observed in the control for a given hostname
            countIf(dns_failure IS NOT NULL) as ctrl_dns_failure_count,
            countIf(dns_success = 1) as ctrl_dns_success_count,

            sumMapIf(ip_asn_map, dns_success = 1 AND ip_asn != 0) as ctrl_dns_answers_asns,
            sumMapIf(ip_map, dns_success = 1) as ctrl_dns_answers,

            -- list of IPs that are TLS consistent for a given hostname (i.e. a TLS handshake succeeds)
            --groupUniqArrayIf(ip, tls_success = 1) as ctrl_tls_success_ips,
            sumMapIf(ip_map, tls_success = 1) as ctrl_tls_success_ips,

            -- list of IPs that are TLS inconsistent for a given hostname
            -- (i.e. a TLS handshake fails with a certificate error)
            --groupUniqArrayIf(ip,
            sumMapIf(ip_map,
                tls_success = 0
                AND tls_failure LIKE 'ssl_%%'
            ) as ctrl_tls_inconsistent_ips,

            -- list of IPs that are TLS failing
            --groupUniqArrayIf(ip,
            sumMapIf(ip_map,
                tls_success = 0 AND tls_failure IS NOT NULL
            ) as ctrl_tls_failing_ips,

            -- list of IPs that are successful via TCP
            --groupUniqArrayIf(ip, tcp_success = 1) as ctrl_tcp_success_ips,
            sumMapIf(
                ip_map,
                tcp_success = 1
            ) as ctrl_tcp_success_ips,

            -- list of IPs that are failing
            --groupUniqArrayIf(ip, tcp_success = 0) as ctrl_tcp_failing_ips
            sumMapIf(ip_map, tcp_success = 0) as ctrl_tcp_failing_ips

            FROM
            obs_web_ctrl
            WHERE measurement_start_time > %(start_time)s
            AND measurement_start_time <= %(end_time)s
            GROUP BY hostname, measurement_day
        ) AS ctrl

        LEFT OUTER JOIN
        (
            SELECT
            hostname,
            toStartOfDay(measurement_start_time) as measurement_day,
            groupArrayIf(ip, tls_is_certificate_valid = 1) as other_tls_consistent_ips

            FROM
            obs_web
            WHERE measurement_start_time > %(start_time)s
            AND measurement_start_time <= %(end_time)s
            GROUP BY hostname, measurement_day
        ) as other
        ON ctrl.hostname = other.hostname AND ctrl.measurement_day = other.measurement_day
        SETTINGS join_algorithm = 'grace_hash', grace_hash_join_initial_buckets = 8
    ) as full_ctrl
    ON full_ctrl.hostname = experiment.hostname AND full_ctrl.measurement_day = experiment.measurement_day
    GROUP BY domain,
    input,
    probe_asn, probe_as_org_name, probe_cc,
    resolver_asn, resolver_as_cc,
    network_type, test_name,
    measurement_start_time,
    measurement_uid,
    ooni_run_link_id,
    probe_id
    SETTINGS join_algorithm = 'grace_hash', grace_hash_join_initial_buckets = 8
    """
    return SQL, q_params


def get_analysis_web_fuzzy_logic(
    db: ClickhouseConnection,
    start_time: datetime,
    end_time: datetime,
    probe_cc: List[str],
    # We are only doing web_connectivity for the moment
    test_name: List[str] = ["web_connectivity"],
    measurement_uid: Optional[str] = None,
):
    SQL, q_params = format_query_analysis_web_fuzzy_logic(
        start_time=start_time,
        end_time=end_time,
        probe_cc=probe_cc,
        test_name=test_name,
        measurement_uid=measurement_uid,
    )
    res = db.execute_iter(SQL, params=q_params, with_column_types=True)
    column_names = list(map(lambda x: x[0], next(res)))
    for row in res:
        row = dict(zip(column_names, row))
        yield row


def write_analysis_web_fuzzy_logic(
    db: ClickhouseConnection,
    start_time: datetime,
    end_time: datetime,
    probe_cc: List[str],
    # We are only doing web_connectivity for the moment
    test_name: List[str] = ["web_connectivity"],
    measurement_uid: Optional[str] = None,
):
    SQL, q_params = format_query_analysis_web_fuzzy_logic(
        start_time=start_time,
        end_time=end_time,
        probe_cc=probe_cc,
        test_name=test_name,
        measurement_uid=measurement_uid,
    )
    INSERT_SQL = f"""
    INSERT INTO analysis_web_measurement
    SELECT * FROM (
        {SQL}
    )
    """
    # TODO(art): this is currently a pretty sub-optimal workaround to the whole
    # database class needing to be refactored
    return db._execute(INSERT_SQL, params=q_params)
