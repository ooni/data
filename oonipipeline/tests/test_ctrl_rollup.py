"""
Tests for the incrementally-maintained control baseline.

The important one is test_rollup_control_matches_inline_control: it runs the
rollup-derived control and the analysis query's current inline control over the
same observations and asserts they agree. That is the parity gate for switching
the analysis query over — without it, the swap is a guess.
"""

from datetime import datetime, timedelta

import pytest

from oonidata.dataclient import load_measurement
from oonipipeline.analysis.ctrl_rollup import (
    DEFAULT_CTRL_LOOKBACK,
    format_query_ctrl_from_rollup,
    write_ctrl_rollup,
)
from oonipipeline.tasks.observations import write_observations_to_db

# A handful of web_connectivity fixtures, which are the only test that produces
# obs_web_ctrl rows at all.
CTRL_MEASUREMENTS = [
    "20221110235922.335062_IR_webconnectivity_e4114ee32b8dbf74",
    "20220608132401.787399_AM_webconnectivity_2285fc373f62729e",
    "20220627030703.592775_IR_webconnectivity_80e199b3c572f8d3",
    "20220625234824.235023_HU_webconnectivity_3435a5df0e743d39",
]


def _load_ctrl_fixtures(db, netinfodb, measurements):
    """Write the fixture observations and return the covered time window."""
    timestamps = []
    for measurement_uid in CTRL_MEASUREMENTS:
        msmt = load_measurement(msmt_path=measurements[measurement_uid])
        timestamps.append(
            datetime.strptime(msmt.measurement_start_time, "%Y-%m-%d %H:%M:%S")
        )
        write_observations_to_db(
            db=db, netinfodb=netinfodb, msmt=msmt, bucket_date="1984-01-01"
        )
    db.flush()
    return min(timestamps), max(timestamps) + timedelta(hours=1)


# The control subquery as the analysis query computes it today, reduced to the
# fields the rollup reproduces. Kept verbatim here rather than imported so the
# parity check compares against the real thing rather than a shared helper that
# could drift with it.
INLINE_CTRL_SQL = """
    SELECT
    hostname,
    countIf(dns_failure IS NOT NULL) as ctrl_dns_failure_count,
    countIf(dns_success = 1) as ctrl_dns_success_count,
    sumMapIf(ip_map, dns_success = 1) as ctrl_dns_answers,
    sumMapIf(ip_asn_map, dns_success = 1 AND ip_asn != 0) as ctrl_dns_answers_asns,
    sumMapIf(ip_map, tls_success = 1) as ctrl_tls_success_ips,
    sumMapIf(ip_map, tls_success = 0 AND tls_failure LIKE 'ssl_%%')
        as ctrl_tls_inconsistent_ips,
    sumMapIf(ip_map, tls_success = 0 AND tls_failure IS NOT NULL)
        as ctrl_tls_failing_ips,
    sumMapIf(ip_map, tcp_success = 1) as ctrl_tcp_success_ips,
    sumMapIf(ip_map, tcp_success = 0) as ctrl_tcp_failing_ips
    FROM (
        WITH
        CAST(([ip], [1]), 'Map(String, UInt32)') as ip_map,
        CAST(([IF(ip_asn IS NULL, 0, ip_asn)], [1]), 'Map(UInt32, UInt32)')
            as ip_asn_map
        SELECT *, ip_map, ip_asn_map
        FROM obs_web_ctrl
        WHERE measurement_start_time >= %(start_time)s
          AND measurement_start_time < %(end_time)s
    )
    GROUP BY hostname
"""


def _rows_by_hostname(rows, columns):
    return {row[0]: dict(zip(columns, row)) for row in rows}


def test_rollup_is_written(db, netinfodb, measurements):
    start_time, end_time = _load_ctrl_fixtures(db, netinfodb, measurements)
    write_ctrl_rollup(db=db, start_time=start_time, end_time=end_time)

    rows = db.execute("SELECT count() FROM obs_web_ctrl_rollup")
    assert rows[0][0] > 0, "rollup is empty for fixtures that have control data"


def test_rollup_is_idempotent(db, netinfodb, measurements):
    """
    SummingMergeTree would double-count a re-run, so write_ctrl_rollup clears
    the window first. A backfill re-running a window must not inflate counts.
    """
    start_time, end_time = _load_ctrl_fixtures(db, netinfodb, measurements)

    write_ctrl_rollup(db=db, start_time=start_time, end_time=end_time)
    db.execute("OPTIMIZE TABLE obs_web_ctrl_rollup FINAL")
    first = db.execute(
        "SELECT sum(dns_success_count), sum(tcp_success_count), sum(tls_success_count) "
        "FROM obs_web_ctrl_rollup"
    )[0]

    write_ctrl_rollup(db=db, start_time=start_time, end_time=end_time)
    db.execute("OPTIMIZE TABLE obs_web_ctrl_rollup FINAL")
    second = db.execute(
        "SELECT sum(dns_success_count), sum(tcp_success_count), sum(tls_success_count) "
        "FROM obs_web_ctrl_rollup"
    )[0]

    assert first == second, f"re-running the rollup changed counts: {first} -> {second}"


def test_rollup_control_matches_inline_control(db, netinfodb, measurements):
    """
    The rollup-derived control must agree with the aggregation the analysis
    query performs inline today. This is what licenses swapping one for the
    other.
    """
    start_time, end_time = _load_ctrl_fixtures(db, netinfodb, measurements)
    write_ctrl_rollup(db=db, start_time=start_time, end_time=end_time)
    db.execute("OPTIMIZE TABLE obs_web_ctrl_rollup FINAL")

    inline_rows, inline_cols = db.execute(
        INLINE_CTRL_SQL,
        {"start_time": start_time, "end_time": end_time},
        with_column_types=True,
    )
    inline = _rows_by_hostname(inline_rows, [c[0] for c in inline_cols])

    # Look back far enough that the rollup window covers the same rows the
    # inline query saw, so any difference is the aggregation and not the window.
    rollup_sql, rollup_params = format_query_ctrl_from_rollup(
        start_time=start_time,
        end_time=end_time,
        lookback=timedelta(0),
    )
    rollup_rows, rollup_cols = db.execute(
        rollup_sql, rollup_params, with_column_types=True
    )
    rollup = _rows_by_hostname(rollup_rows, [c[0] for c in rollup_cols])

    assert set(inline) == set(rollup), (
        "rollup and inline control cover different hostnames: "
        f"only inline={sorted(set(inline) - set(rollup))} "
        f"only rollup={sorted(set(rollup) - set(inline))}"
    )

    compared = [
        "ctrl_dns_failure_count",
        "ctrl_dns_success_count",
        "ctrl_dns_answers",
        "ctrl_dns_answers_asns",
        "ctrl_tls_success_ips",
        "ctrl_tls_inconsistent_ips",
        "ctrl_tls_failing_ips",
        "ctrl_tcp_success_ips",
        "ctrl_tcp_failing_ips",
    ]

    def drop_zeros(value):
        # The inline version builds maps by summing per-row 1s, so an address
        # with no successes is simply absent. The rollup stores an explicit 0
        # for it. Same information, different representation.
        if isinstance(value, dict):
            return {k: v for k, v in value.items() if v}
        return value

    for hostname in sorted(inline):
        for column in compared:
            assert drop_zeros(inline[hostname][column]) == drop_zeros(
                rollup[hostname][column]
            ), f"{hostname}.{column} differs"


def test_rollup_window_is_closed_and_run_time_independent(db, netinfodb, measurements):
    """
    The control window must depend only on the analysis window, never on when
    the job ran — that is the property the same-day aggregation lacked, and the
    reason re-running a backfill used to produce different scores.
    """
    start = datetime(2024, 3, 5, 13, 0, 0)
    end = start + timedelta(hours=1)

    _, params_a = format_query_ctrl_from_rollup(start_time=start, end_time=end)
    _, params_b = format_query_ctrl_from_rollup(start_time=start, end_time=end)
    assert params_a == params_b

    assert params_a["ctrl_start_time"] == start - DEFAULT_CTRL_LOOKBACK
    assert params_a["ctrl_end_time"] == end

    # A different analysis hour must move the window, and by exactly one hour.
    _, params_next = format_query_ctrl_from_rollup(
        start_time=start + timedelta(hours=1), end_time=end + timedelta(hours=1)
    )
    assert (
        params_next["ctrl_start_time"] - params_a["ctrl_start_time"]
    ) == timedelta(hours=1)
