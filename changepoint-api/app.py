# /// script
# requires-python = ">=3.11"
# dependencies = ["fastapi", "uvicorn", "clickhouse-driver", "requests"]
# ///
"""
Minimal HTTP API around oonipipeline.analysis.detectorV2.

Needs oonipipeline's `src` dir on PYTHONPATH (see Readme.md).
"""
import os
from datetime import date, datetime, time, timedelta, timezone
from itertools import groupby
from typing import Literal

from clickhouse_driver import Client
from fastapi import FastAPI, HTTPException, Query

from oonipipeline.analysis.detectorV2 import LAYERS, Detector, iter_cells

CLICKHOUSE_URL = os.environ.get("CLICKHOUSE_URL", "clickhouse://localhost:9000/ooni")

app = FastAPI(title="OONI changepoint API")


@app.get("/changepoints")
def changepoints(
    probe_cc: str = Query(..., min_length=2, max_length=2),
    domain: str = Query(...),
    start_date: date = Query(...),
    end_date: date | None = Query(None),
    layers: list[Literal["dns", "tcp", "tls"]] = Query(LAYERS),
    warmup_days: int = Query(30, ge=0, le=365),
    p0: float = Query(0.05, gt=0, lt=1),
    p1: float = Query(0.50, gt=0, lt=1),
    h: float = Query(30, gt=0),
    gap_halflife: float = Query(24, gt=0),
    use_decay: bool = True,
):
    end_date = end_date or start_date
    if end_date < start_date:
        raise HTTPException(400, "end_date must be >= start_date")
    if p1 <= p0:
        raise HTTPException(400, "p1 must be > p0")

    start = datetime.combine(start_date, time(), timezone.utc)
    end = datetime.combine(end_date, time(23), timezone.utc)
    params = dict(p0=p0, p1=p1, h=h, gap_halflife=gap_halflife, use_decay=use_decay)

    cells = iter_cells(
        Client.from_url(CLICKHOUSE_URL),
        [domain],
        start - timedelta(days=warmup_days),
        end,
        probe_cc=probe_cc.upper(),
    )
    events, series = [], []
    try:
        for (asn, resolver_asn), group in groupby(
            cells, key=lambda c: (c.probe_asn, c.resolver_asn)
        ):
            group = list(group)
            warmup = [c for c in group if c.ts_hour < start]
            target = [c for c in group if c.ts_hour >= start]
            final_state = {}
            for layer in layers:
                d = Detector()
                d.compute_changepoints(warmup, layer, warmup=True, **params)
                for cp in d.compute_changepoints(target, layer, **params):
                    events.append({"layer": layer, **vars(cp), "state": str(cp.state)})
                final_state[layer] = str(d.state)
            series.append(
                {
                    "probe_asn": asn,
                    "resolver_asn": resolver_asn,
                    "n_measurements": sum(c.n_measurements for c in target),
                    "final_state": final_state,
                }
            )
    except RuntimeError as e:
        # iter_cells raises StopIteration (-> RuntimeError) on empty results
        if not isinstance(e.__cause__, StopIteration):
            raise

    return {
        "query": {
            "probe_cc": probe_cc.upper(),
            "domain": domain,
            "start_date": start_date,
            "end_date": end_date,
            "layers": layers,
            "warmup_days": warmup_days,
            **params,
        },
        "changepoints": sorted(events, key=lambda e: e["ts_hour"]),
        "series": series,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 8000)))
