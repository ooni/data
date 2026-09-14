from collections import defaultdict
from datetime import datetime, timedelta, timezone

import pytest

from oonipipeline.analysis.detectorV2 import Cell, Detector, State, get_cells


def test_detectorV2_venezuela(db, db_analysis_ve):
    """
    Runs the detector against a known period with blocking in Venezuela
    """
    start = datetime(2026, 8, 3, tzinfo=timezone.utc)
    end = datetime(2026, 9, 3, tzinfo=timezone.utc)

    cells = list(get_cells(db.client, ["www.caraotadigital.net"], start, end, "VE"))

    cells_by_series = defaultdict(list)
    for cell in cells:
        cells_by_series[(cell.probe_asn, cell.resolver_asn)].append(cell)
    for series_cells in cells_by_series.values():
        series_cells.sort(key=lambda c: c.ts_hour)

    all_changepoints = []
    changepoints_by_series = {}
    for series_key, series_cells in cells_by_series.items():
        for layer in ("dns", "tcp", "tls"):
            cps = Detector().compute_changepoints(series_cells, layer)
            if cps:
                changepoints_by_series[(series_key, layer)] = cps
            all_changepoints.extend(cps)

    assert len(all_changepoints) == 6

    # All of them should be on the dns layer.
    assert all(layer == "dns" for (_series, layer) in changepoints_by_series)

    # And across exactly 5 distinct (probe_asn, resolver_asn) series.
    series_with_events = {series for (series, _layer) in changepoints_by_series}
    assert len(series_with_events) == 5


BASE_HOUR = datetime(2024, 1, 1, tzinfo=timezone.utc)

def make_cell(ts_hour: datetime, **layer_counts: int) -> Cell:
    """
    layer_counts: any of k_dns/n_dns/k_tcp/n_tcp/k_tls/n_tls, defaulting to 0
    """
    defaults = dict(k_dns=0, n_dns=0, k_tcp=0, n_tcp=0, k_tls=0, n_tls=0)
    defaults.update(layer_counts)
    return Cell(
        domain="example.com",
        probe_cc="ZZ",
        probe_asn="0",
        resolver_asn="0",
        ts_hour=ts_hour,
        n_measurements=max(defaults["n_dns"], defaults["n_tcp"], defaults["n_tls"]),
        n_probes=0,
        **defaults,
    )


def test_decay_noop_within_24_hours():
    """
    The gap must exceed 24h before any decay is applied at all,
    regardless of gap_halflife.
    """
    d = Detector()
    d.s_pos, d.s_neg = 10.0, 7.0
    d.last_hour = BASE_HOUR

    d.decay(gap_halflife=1, ts_hour=BASE_HOUR + timedelta(hours=24))

    assert d.s_pos == 10.0
    assert d.s_neg == 7.0


def test_decay_halves_at_exactly_one_halflife():
    """
    A gap equal to gap_halflife (and > 24h) should cut both accumulators
    exactly in half.
    """
    d = Detector()
    d.s_pos, d.s_neg = 10.0, 8.0
    d.last_hour = BASE_HOUR

    d.decay(gap_halflife=25, ts_hour=BASE_HOUR + timedelta(hours=25))

    assert d.s_pos == pytest.approx(5.0)
    assert d.s_neg == pytest.approx(4.0)


def test_decay_scales_exponentially_with_gap():
    """
    Two halflives should quarter the accumulators, not just halve them
    twice as much (i.e. it's 0.5**(gap/halflife), not linear)
    """
    d = Detector()
    d.s_pos, d.s_neg = 10.0, 8.0
    d.last_hour = BASE_HOUR

    d.decay(gap_halflife=24, ts_hour=BASE_HOUR + timedelta(hours=48))

    assert d.s_pos == pytest.approx(2.5)
    assert d.s_neg == pytest.approx(2.0)


def test_decay_approaches_zero_for_a_very_long_gap():
    d = Detector()
    d.s_pos, d.s_neg = 10.0, 8.0
    d.last_hour = BASE_HOUR

    d.decay(gap_halflife=24, ts_hour=BASE_HOUR + timedelta(hours=240))  # 10 halflives

    assert d.s_pos == pytest.approx(10.0 * 0.5**10)
    assert d.s_neg == pytest.approx(8.0 * 0.5**10)
    assert d.s_pos < 0.02
    assert d.s_neg < 0.02


def test_decay_applied_through_step_between_two_silent_cells():
    """
    step()/Cell rather than calling decay() directly
    """
    d = Detector()
    d.s_pos, d.s_neg = 10.0, 8.0

    first_cell = make_cell(BASE_HOUR)
    d.step(first_cell, w_block=1.0, w_clear=-1.0, layer="dns", h=1e9, gap_halflife=48)
    assert d.s_pos == pytest.approx(10.0)  # gap from None -> no decay
    assert d.s_neg == pytest.approx(8.0)
    assert d.last_hour == BASE_HOUR

    second_cell = make_cell(BASE_HOUR + timedelta(hours=48))
    d.step(second_cell, w_block=1.0, w_clear=-1.0, layer="dns", h=1e9, gap_halflife=48)

    assert d.s_pos == pytest.approx(5.0)
    assert d.s_neg == pytest.approx(4.0)
    assert d.last_hour == BASE_HOUR + timedelta(hours=48)
