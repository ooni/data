from typing import Optional
from fastapi import APIRouter

router = APIRouter()


@router.get("/measurements", tags=["measurements"])
async def list_measurements(
    report_id: Optional[str],
    probe_asn: Optional[str],
    probe_cc: Optional[str],
    test_name: Optional[str],
    since: Optional[str],
    until: Optional[str],
    order_by: Optional[str],
    order: Optional[str],
    offset: Optional[str],
    limit: Optional[int],
    anomaly: Optional[bool],
    confirmed: Optional[bool],
    category_code: Optional[str],
    software_version: Optional[str],
    test_version: Optional[str],
    engine_version: Optional[str],
    ooni_run_link_id: Optional[str],
):
    return {
        "metadata": {
            "count": -1,
            "current_page": 1,
            "limit": 100,
            "next_url": "https://api.ooni.io/api/v1/measurements?offset=100&limit=100",
            "offset": 0,
            "pages": -1,
            "query_time": 0.10463142395019531,
        },
        "results": [],
    }
