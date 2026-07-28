"""
Incrementally-maintained control baseline.

The analysis query derives its control by aggregating a full day of
obs_web_ctrl, plus a second full-day scan of obs_web for the IPs any probe
found TLS-consistent. Since make_analysis runs hourly, that has two costs:

1. Every hourly run rescans the same day, so the work is done ~24 times over,
   and both joins need grace_hash to fit.
2. The control a measurement is scored against depends on *when the job ran*.
   The 01:00 run sees roughly an hour of control data, the 23:00 run sees
   twenty-three — so `ctrl_dns_success_rate > 0.5` is a threshold over wildly
   different sample sizes depending on time of day, and re-running a backfill
   produces different scores than the original run. analysis_web_measurement is
   a ReplacingMergeTree keyed on measurement_uid, so the newer value silently
   wins and the drift is invisible.

This module precomputes the baseline into obs_web_ctrl_rollup, keyed by
(hostname, ts_hour, ip). Consumers then read a *closed* trailing window rather
than "whatever has landed for today so far", which makes scoring reproducible:
re-running hour H at any later date reads exactly the same buckets.

The rollup is long-form — one row per address rather than a Map per hostname —
because SummingMergeTree can then merge partial writes for free, and because
the two sources (obs_web_ctrl and obs_web) can be written independently and
summed together at merge time.
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Tuple

log = logging.getLogger(__name__)

# How far back a consumer looks when assembling the control for a given
# analysis window. One day matches the granularity the previous same-day
# aggregation effectively had, without the partial-day dependence on run time.
DEFAULT_CTRL_LOOKBACK = timedelta(days=1)


def _floor_hour(ts: datetime) -> datetime:
    return ts.replace(minute=0, second=0, microsecond=0)


def _ceil_hour(ts: datetime) -> datetime:
    floored = _floor_hour(ts)
    return floored if floored == ts else floored + timedelta(hours=1)


def format_query_ctrl_rollup(
    start_time: datetime, end_time: datetime
) -> Tuple[str, Dict[str, Any]]:
    """
    Build the rollup rows for one window.

    Both sources are unioned and aggregated in a single pass so that one key
    produces exactly one row. That is what makes re-running a window a
    replacement rather than an accumulation, and it is why the table is a
    ReplacingMergeTree — a SummingMergeTree would double every count on a
    backfill unless the window were deleted first.

    In obs_web_ctrl the DNS resolution failures carry no address, so they land
    on the ip = '' row; that is how the hostname-level failure count survives
    the per-address grain.
    """
    sql = """
    SELECT
        hostname,
        ts_hour,
        ip,
        ip_asn,
        toUInt32(sum(dns_success_count)) as dns_success_count,
        toUInt32(sum(dns_failure_count)) as dns_failure_count,
        toUInt32(sum(tcp_success_count)) as tcp_success_count,
        toUInt32(sum(tcp_failure_count)) as tcp_failure_count,
        toUInt32(sum(tls_success_count)) as tls_success_count,
        toUInt32(sum(tls_failure_count)) as tls_failure_count,
        toUInt32(sum(tls_inconsistent_count)) as tls_inconsistent_count,
        toUInt32(sum(tls_consistent_probe_count)) as tls_consistent_probe_count
    FROM (
        SELECT
            hostname,
            toStartOfHour(measurement_start_time) as ts_hour,
            ip,
            ifNull(toUInt32OrNull(toString(ip_asn)), 0) as ip_asn,
            countIf(dns_success = 1) as dns_success_count,
            countIf(dns_failure IS NOT NULL) as dns_failure_count,
            countIf(tcp_success = 1) as tcp_success_count,
            countIf(tcp_success = 0) as tcp_failure_count,
            countIf(tls_success = 1) as tls_success_count,
            countIf(tls_success = 0 AND tls_failure IS NOT NULL)
                as tls_failure_count,
            countIf(tls_success = 0 AND tls_failure LIKE 'ssl_%%')
                as tls_inconsistent_count,
            0 as tls_consistent_probe_count
        FROM obs_web_ctrl
        WHERE measurement_start_time >= %(start_time)s
          AND measurement_start_time < %(end_time)s
        GROUP BY hostname, ts_hour, ip, ip_asn

        UNION ALL

        -- The other half of the baseline: addresses on which some probe
        -- completed a TLS handshake with a valid certificate. This is evidence
        -- that a DNS answer is genuine which does not depend on the test helper
        -- having seen it — useful for hostnames the helper resolves differently
        -- (CDN, geo-DNS), and later for the tests that have no helper at all.
        SELECT
            hostname,
            toStartOfHour(measurement_start_time) as ts_hour,
            ip,
            ifNull(toUInt32OrNull(toString(ip_asn)), 0) as ip_asn,
            0 as dns_success_count,
            0 as dns_failure_count,
            0 as tcp_success_count,
            0 as tcp_failure_count,
            0 as tls_success_count,
            0 as tls_failure_count,
            0 as tls_inconsistent_count,
            countIf(tls_is_certificate_valid = 1) as tls_consistent_probe_count
        FROM obs_web
        WHERE measurement_start_time >= %(start_time)s
          AND measurement_start_time < %(end_time)s
          AND hostname IS NOT NULL
          AND ip IS NOT NULL
          AND tls_is_certificate_valid = 1
        GROUP BY hostname, ts_hour, ip, ip_asn
    )
    GROUP BY hostname, ts_hour, ip, ip_asn
    """
    return sql, {"start_time": start_time, "end_time": end_time}


ROLLUP_COLUMNS = [
    "hostname",
    "ts_hour",
    "ip",
    "ip_asn",
    "dns_success_count",
    "dns_failure_count",
    "tcp_success_count",
    "tcp_failure_count",
    "tls_success_count",
    "tls_failure_count",
    "tls_inconsistent_count",
    "tls_consistent_probe_count",
]


def write_ctrl_rollup(db, start_time: datetime, end_time: datetime) -> None:
    """
    Populate obs_web_ctrl_rollup for [start_time, end_time).

    Safe to re-run: one row per key per write, into a ReplacingMergeTree.
    """
    col_str = ", ".join(ROLLUP_COLUMNS)
    select_sql, params = format_query_ctrl_rollup(
        start_time=start_time, end_time=end_time
    )
    log.info(f"writing obs_web_ctrl_rollup for {start_time} - {end_time}")
    db.execute(f"INSERT INTO obs_web_ctrl_rollup ({col_str}) {select_sql}", params)


def format_query_ctrl_from_rollup(
    start_time: datetime,
    end_time: datetime,
    lookback: timedelta = DEFAULT_CTRL_LOOKBACK,
) -> Tuple[str, Dict[str, Any]]:
    """
    Assemble the per-hostname control from the rollup, in the same shape the
    analysis query's WITH clause already expects.

    The window is [start_time - lookback, end_time) — closed and derived only
    from the analysis window, never from wall-clock time, which is what makes
    a re-run reproduce the original scores.

    The bounds are snapped to hour boundaries because the rollup is bucketed by
    hour: comparing an unaligned bound against ts_hour would drop the bucket
    the window starts inside. The start floors and the end ceils, so the
    control window is always a superset of the analysis window. For the hourly
    schedule both bounds are already aligned and this is a no-op.
    """
    sql = """
    SELECT
        hostname,

        sum(dns_failure_count) as ctrl_dns_failure_count,
        sum(dns_success_count) as ctrl_dns_success_count,

        sumMap(
            CAST(([ip], [dns_success_count]), 'Map(String, UInt32)')
        ) as ctrl_dns_answers,
        -- ip_asn = 0 stands in for "no ASN known", and is excluded rather than
        -- becoming a bucket of its own — matching what the inline control did
        -- with its `ip_asn != 0` guard.
        sumMapIf(
            CAST(([ip_asn], [dns_success_count]), 'Map(UInt32, UInt32)'),
            ip_asn != 0
        ) as ctrl_dns_answers_asns,

        sumMap(
            CAST(([ip], [tls_success_count]), 'Map(String, UInt32)')
        ) as ctrl_tls_success_ips,
        sumMap(
            CAST(([ip], [tls_inconsistent_count]), 'Map(String, UInt32)')
        ) as ctrl_tls_inconsistent_ips,
        sumMap(
            CAST(([ip], [tls_failure_count]), 'Map(String, UInt32)')
        ) as ctrl_tls_failing_ips,
        sumMap(
            CAST(([ip], [tcp_success_count]), 'Map(String, UInt32)')
        ) as ctrl_tcp_success_ips,
        sumMap(
            CAST(([ip], [tcp_failure_count]), 'Map(String, UInt32)')
        ) as ctrl_tcp_failing_ips,

        -- Addresses considered TLS-consistent: the helper handshook with them
        -- successfully, or some probe did with a valid certificate.
        arrayDistinct(
            arrayConcat(
                groupArrayIf(ip, tls_success_count > 0),
                groupArrayIf(ip, tls_consistent_probe_count > 0)
            )
        ) as union_tls_consistent_ips

    -- FINAL because the table is a ReplacingMergeTree: without it a window
    -- that has been re-run but not yet merged would be counted twice.
    FROM obs_web_ctrl_rollup FINAL
    WHERE ts_hour >= %(ctrl_start_time)s AND ts_hour < %(ctrl_end_time)s
    GROUP BY hostname
    """
    return sql, {
        "ctrl_start_time": _floor_hour(start_time - lookback),
        "ctrl_end_time": _ceil_hour(end_time),
    }
