import dataclasses
from datetime import date
import math
from typing import List, Literal, Optional, Union
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from typing_extensions import Annotated

from oonidata.datautils import PerfTimer
from oonidata.models.observations import WebObservation

from ..config import settings
from ..dependencies import ClickhouseClient, get_clickhouse_client

router = APIRouter()


class ResponseMetadata(BaseModel):
    count: int
    current_page: int
    limit: int
    next_url: str
    offset: int
    pages: int
    query_time: float


class WebObservationEntry(BaseModel):
    pass


ObservationEntry = Union[WebObservationEntry, BaseModel]

# TODO: dynamically create the WebObservation entry class from this:
# for x in dataclasses.fields(WebObservation):
#    setattr(WebObservation, x.name, x.type)


class ListObservationsResponse(BaseModel):
    metadata: ResponseMetadata
    results: List[ObservationEntry]


@router.get("/observations", tags=["observations"])
async def list_observations(
    db: Annotated[ClickhouseClient, Depends(get_clickhouse_client)],
    report_id: Annotated[Optional[str], Query()] = None,
    probe_asn: Annotated[Union[int, str, None], Query()] = None,
    probe_cc: Annotated[Optional[str], Query(max_length=2, min_length=2)] = None,
    test_name: Annotated[Optional[str], Query()] = None,
    since: Annotated[Optional[date], Query()] = None,
    until: Annotated[Optional[date], Query()] = None,
    order_by: Annotated[
        Literal[
            "measurement_start_time",
            "input",
            "probe_cc",
            "probe_asn",
            "test_name",
        ],
        Query(),
    ] = "measurement_start_time",
    order: Annotated[Optional[Literal["asc", "desc", "ASC", "DESC"]], Query()] = "DESC",
    offset: Annotated[int, Query()] = 0,
    limit: Annotated[int, Query()] = 100,
    software_name: Annotated[Optional[str], Query()] = None,
    software_version: Annotated[Optional[str], Query()] = None,
    test_version: Annotated[Optional[str], Query()] = None,
    engine_version: Annotated[Optional[str], Query()] = None,
    ooni_run_link_id: Annotated[Optional[str], Query()] = None,
) -> ListObservationsResponse:
    q_args = {}
    and_clauses = []
    if report_id is not None:
        q_args["report_id"] = report_id
        and_clauses.append("report_id = %(report_id)s")
    if probe_asn is not None:
        if isinstance(probe_asn, str) and probe_asn.startswith("AS"):
            probe_asn = int(probe_asn[2:])
        q_args["probe_asn"] = probe_asn
        and_clauses.append("probe_asn = %(probe_asn)d")
    if probe_cc is not None:
        q_args["probe_cc"] = probe_cc
        and_clauses.append("probe_cc = %(probe_cc)s")

    if software_name is not None:
        q_args["software_name"] = software_version
        and_clauses.append("software_name = %(software_name)s")
    if software_version is not None:
        q_args["software_version"] = software_version
        and_clauses.append("software_version = %(software_version)s")

    if test_name is not None:
        q_args["test_name"] = test_name
        and_clauses.append("test_name = %(test_name)s")
    if test_version is not None:
        q_args["test_version"] = test_version
        and_clauses.append("test_version = %(test_version)s")
    if engine_version is not None:
        q_args["engine_version"] = engine_version
        and_clauses.append("engine_version = %(engine_version)s")

    if ooni_run_link_id is not None:
        q_args["ooni_run_link_id"] = ooni_run_link_id
        and_clauses.append("ooni_run_link_id = %(ooni_run_link_id)s")

    if since is not None:
        q_args["since"] = since
        and_clauses.append("measurement_start_time >= %(since)s")
    if until is not None:
        and_clauses.append("measurement_start_time <= %(until)s")
        q_args["until"] = until

    cols = [x.name for x in dataclasses.fields(WebObservation)]
    q = f"SELECT {','.join(cols)} FROM obs_web"
    if len(and_clauses) > 0:
        q += " WHERE "
        q += " AND ".join(and_clauses)
    q += f" ORDER BY {order_by} {order} LIMIT {limit} OFFSET {offset}"

    t = PerfTimer()
    rows = db.execute(q, q_args)

    results: List[ObservationEntry] = []
    if rows and isinstance(rows, list):
        for row in rows:
            d = dict(zip(cols, row))
            results.append(WebObservationEntry(**d))

    response = ListObservationsResponse(
        metadata=ResponseMetadata(
            count=-1,
            current_page=math.ceil(offset / limit) + 1,
            limit=limit,
            next_url=f"{settings.base_url}/api/v1/observations?offset={offset+limit}&limit={limit}",
            offset=offset,
            pages=-1,
            query_time=t.s,
        ),
        results=results,
    )

    return response
