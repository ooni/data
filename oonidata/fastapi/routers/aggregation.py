from typing import Optional
from fastapi import APIRouter

router = APIRouter()


@router.get("/aggregation", tags=["aggregation"])
async def get_aggregation(
    axis_x: str,
    axis_y: str,
    category_code: Optional[str],
    test_name: Optional[str],
    domain: Optional[str],
    input: Optional[str],
    probe_asn: Optional[str],
    probe_cc: Optional[str],
    ooni_run_link_id: Optional[str],
    since: Optional[str],
    until: Optional[str],
    time_grain: Optional[str],
    format: Optional[str],
    download: Optional[bool],
):
    return {
        "db_stats": {
            "bytes": 1861692094,
            "elapsed_seconds": 0.5809690952301025,
            "row_count": 53169473,
            "total_row_count": 53169473,
        },
        "dimension_count": 1,
        # TODO(arturo): it's annoying that this is result instead of results
        "result": [
            {
                "anomaly_count": 60655,
                "confirmed_count": 8739,
                "failure_count": 46221,
                "measurement_count": 1255146,
                "measurement_start_day": "2023-10-22",
                "ok_count": 1139531,
            }
        ],
    }
