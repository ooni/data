"""Tests for the quiet-interval estimator.

No database: what is under test is the arithmetic between the labels and the
printed rate. That arithmetic is where a false-alarm number goes quietly wrong
— an unweighted mean over a deliberately unbalanced queue looks exactly like a
weighted one, and is out by whatever the oversampling factor was.
"""

from datetime import datetime

from oonipipeline.analysis.interval_eval import (
    IntervalCard,
    IntervalResult,
    gate,
    volume_band,
)


def result(
    cc="TZ",
    asn=33765,
    domain="telegram.org",
    week="2026-03-02",
    verdict="quiet_observed",
    stratum="random_covered",
    weight=1.0,
    measurements=500,
    alerts=0,
):
    return IntervalResult(
        probe_cc=cc,
        probe_asn=asn,
        domain=domain,
        window_start=datetime.fromisoformat(week),
        verdict=verdict,
        stratum=stratum,
        weight=weight,
        volume_band=volume_band(measurements),
        measurements=measurements,
        alerts=alerts,
    )


def test_rate_is_weighted_not_counted():
    """The queue oversamples alerted weeks on purpose. One alerting row drawn
    from a small stratum must not outweigh a quiet row standing for thousands
    of cell-weeks, or the rate describes the queue instead of the network."""
    card = IntervalCard(results=[
        result(stratum="detector_alerted", weight=10.0, alerts=1),
        result(cc="KE", stratum="random_covered", weight=990.0, alerts=0),
    ])
    # Unweighted this is 0.5 alerts per week; weighted it is 10/1000.
    assert card.false_alarms_per_quiet_series_week == 0.01


def test_only_observed_quiet_rows_are_in_the_denominator():
    card = IntervalCard(results=[
        result(weight=100.0, alerts=0),
        result(cc="KE", verdict="event_present", weight=100.0, alerts=3),
    ])
    assert card.false_alarms_per_quiet_series_week == 0.0
    assert card.interval_detection_rate == 1.0


def test_alarm_free_share_and_rate_can_disagree():
    """One noisy week and many clean ones: a bad rate with a good alarm-free
    share. Blending them into one number would hide which failure mode a
    configuration has."""
    rows = [result(cc="KE", week="2026-03-09", weight=1.0, alerts=8)]
    rows += [result(cc=f"C{i}", weight=1.0) for i in range(9)]
    card = IntervalCard(results=rows)
    assert card.false_alarms_per_quiet_series_week == 0.8
    assert card.quiet_weeks_alarm_free == 0.9


def test_bands_are_derived_from_the_count():
    assert volume_band(99) == "low"
    assert volume_band(100) == "medium"
    assert volume_band(1000) == "high"
    card = IntervalCard(results=[
        result(measurements=50, weight=1.0, alerts=1),
        result(cc="KE", measurements=5000, weight=1.0, alerts=0),
    ])
    assert card.by_band(card.quiet)["low"].startswith("1.000")
    assert card.by_band(card.quiet)["high"].startswith("0.000")


def test_no_interval_below_ten_country_weeks():
    """A percentile interval over four clusters is arbitrary, not wide."""
    from oonipipeline.analysis.interval_eval import _cluster_bootstrap

    few = [result(cc=f"C{i}") for i in range(4)]
    assert _cluster_bootstrap(few, lambda r: r.alerts, resamples=50, seed=0) is None

    many = [result(cc=f"C{i}", alerts=i % 2) for i in range(20)]
    ci = _cluster_bootstrap(many, lambda r: r.alerts, resamples=200, seed=0)
    assert ci is not None
    lo, hi = ci
    assert 0.0 <= lo <= 0.5 <= hi <= 1.0


def test_clusters_are_country_weeks():
    a = result(cc="TZ", week="2026-03-02")
    b = result(cc="TZ", asn=12345, week="2026-03-02")
    c = result(cc="TZ", week="2026-03-09")
    assert a.cluster == b.cluster  # two ASNs, one country-week
    assert a.cluster != c.cluster


def test_gate_uses_the_lower_bound_when_there_is_one():
    """So a change fails only when the corpus can tell the rate from the
    budget. A gate that fails at random gets switched off."""
    rows = [result(cc=f"C{i}", alerts=i % 2) for i in range(20)]
    card = IntervalCard(results=rows)
    card.ci = (0.30, 0.70)
    ok, why = gate(card, 0.5)
    assert ok and "lower bound" in why
    ok, _ = gate(card, 0.1)
    assert not ok


def test_gate_falls_back_to_the_point_estimate():
    card = IntervalCard(results=[result(alerts=1, weight=1.0)])
    ok, why = gate(card, 0.5)
    assert not ok and "point estimate" in why


def test_gate_passes_when_there_is_nothing_to_gate_on():
    ok, why = gate(IntervalCard(), 0.5)
    assert ok and "nothing to gate on" in why
