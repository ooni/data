from collections import defaultdict
from datetime import datetime, timezone

from oonipipeline.analysis.detectorV2 import Detector, get_cells


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
