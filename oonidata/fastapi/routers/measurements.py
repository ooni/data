from typing import Optional
from fastapi import APIRouter, Depends
from typing_extensions import Annotated

from ..dependencies import ClickhouseClient, get_clickhouse_client

router = APIRouter()


@router.get("/measurements", tags=["measurements"])
async def list_measurements(
    db: Annotated[ClickhouseClient, Depends(get_clickhouse_client)],
    report_id: Optional[str] = None,
    probe_asn: Optional[str] = None,
    probe_cc: Optional[str] = None,
    test_name: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    order_by: Optional[str] = None,
    order: Optional[str] = None,
    offset: Optional[str] = None,
    limit: Optional[int] = None,
    anomaly: Optional[bool] = None,
    confirmed: Optional[bool] = None,
    category_code: Optional[str] = None,
    software_version: Optional[str] = None,
    test_version: Optional[str] = None,
    engine_version: Optional[str] = None,
    ooni_run_link_id: Optional[str] = None,
):
    cols = [
        "measurement_uid",
        "observation_id_list",
        "timeofday",
        "created_at",
        "location_network_type",
        "location_network_asn",
        "location_network_cc",
        "location_network_as_org_name",
        "location_network_as_cc",
        "location_resolver_asn",
        "location_resolver_as_org_name",
        "location_resolver_as_cc",
        "location_resolver_cc",
        "location_blocking_scope",
        "target_nettest_group",
        "target_category",
        "target_name",
        "target_domain_name",
        "target_detail",
        "loni_ok_value",
        "loni_down_keys",
        "loni_down_values",
        "loni_blocked_keys",
        "loni_blocked_values",
        "loni_ok_keys",
        "loni_ok_values",
        "loni_list",
        "analysis_transcript_list",
        "measurement_count",
        "observation_count",
        "vp_count",
        "anomaly",
        "confirmed",
    ]
    rows = db.execute(
        f"SELECT {','.join(cols)} FROM measurement_experiment_result LIMIT 100"
    )
    assert rows and isinstance(rows, list)

    results = []
    for row in rows:
        results.append(dict(zip(cols, row)))
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
        "results": results,
    }
