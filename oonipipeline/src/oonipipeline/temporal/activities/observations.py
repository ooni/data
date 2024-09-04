import asyncio
from dataclasses import dataclass
import dataclasses
import functools
from typing import Any, Dict, List, Sequence, Tuple, TypedDict
from oonidata.dataclient import (
    ccs_set,
    list_file_entries_batches,
    load_measurement,
    stream_measurements,
)
from oonidata.datautils import PerfTimer
from oonidata.models.nettests import SupportedDataformats
from oonipipeline.db.connections import ClickhouseConnection
from oonipipeline.netinfo import NetinfoDB
from oonipipeline.temporal.common import (
    PrevRange,
    get_prev_range,
    make_db_rows,
    maybe_delete_prev_range,
)

from opentelemetry import trace

from temporalio import activity


import pathlib
from datetime import datetime, timedelta

from oonipipeline.transforms.observations import measurement_to_observations

log = activity.logger


@dataclass
class MakeObservationsParams:
    probe_cc: List[str]
    test_name: List[str]
    clickhouse: str
    data_dir: str
    fast_fail: bool
    bucket_date: str


def write_observations_to_db(
    msmt: SupportedDataformats,
    netinfodb: NetinfoDB,
    db: ClickhouseConnection,
    bucket_date: str,
):
    for observations in measurement_to_observations(
        msmt=msmt, netinfodb=netinfodb, bucket_date=bucket_date
    ):
        if len(observations) == 0:
            continue

        column_names = [f.name for f in dataclasses.fields(observations[0])]
        table_name, rows = make_db_rows(
            bucket_date=bucket_date,
            dc_list=observations,
            column_names=column_names,
        )
        db.write_rows(table_name=table_name, rows=rows, column_names=column_names)


FileEntryBatchType = Tuple[str, str, str, int]


@dataclass
class MakeObservationsFileEntryBatch:
    batch_idx: int
    clickhouse: str
    write_batch_size: int
    data_dir: str
    bucket_date: str
    probe_cc: List[str]
    test_name: List[str]
    bucket_date: str
    fast_fail: bool


def make_observations_for_file_entry_batch(
    file_entry_batch: List[FileEntryBatchType],
    bucket_date: str,
    probe_cc: List[str],
    data_dir: pathlib.Path,
    clickhouse: str,
    write_batch_size: int,
    fast_fail: bool = False,
) -> int:
    netinfodb = NetinfoDB(datadir=data_dir, download=False)

    tracer = trace.get_tracer(__name__)

    total_failure_count = 0
    with ClickhouseConnection(clickhouse, write_batch_size=write_batch_size) as db:
        ccs = ccs_set(probe_cc)
        idx = 0
        for bucket_name, s3path, ext, fe_size in file_entry_batch:
            failure_count = 0
            # Nest the traced span within the current span
            with tracer.start_span("MakeObservations:stream_file_entry") as span:
                log.debug(f"processing file s3://{bucket_name}/{s3path}")
                t = PerfTimer()
                try:
                    for msmt_dict in stream_measurements(
                        bucket_name=bucket_name, s3path=s3path, ext=ext
                    ):
                        # Legacy cans don't allow us to pre-filter on the probe_cc, so
                        # we need to check for probe_cc consistency in here.
                        if ccs and msmt_dict["probe_cc"] not in ccs:
                            continue
                        msmt = None
                        try:
                            msmt = load_measurement(msmt_dict)
                            if not msmt.test_keys:
                                log.error(
                                    f"measurement with empty test_keys: ({msmt.measurement_uid})",
                                    exc_info=True,
                                )
                                continue
                            obs_tuple = measurement_to_observations(
                                msmt=msmt,
                                netinfodb=netinfodb,
                                bucket_date=bucket_date,
                            )
                            for obs_list in obs_tuple:
                                db.write_table_model_rows(obs_list)
                            idx += 1
                        except Exception as exc:
                            msmt_str = msmt_dict.get("report_id", None)
                            if msmt:
                                msmt_str = msmt.measurement_uid
                            log.error(
                                f"failed at idx: {idx} ({msmt_str})", exc_info=True
                            )
                            failure_count += 1

                            if fast_fail:
                                db.close()
                                raise exc
                    log.debug(f"done processing file s3://{bucket_name}/{s3path}")
                except Exception as exc:
                    log.error(
                        f"failed to stream measurements from s3://{bucket_name}/{s3path}"
                    )
                    log.error(exc)
                # TODO(art): figure out if the rate of these metrics is too
                # much. For each processed file a telemetry event is generated.
                span.set_attribute("kb_per_sec", fe_size / 1024 / t.s)
                span.set_attribute("fe_size", fe_size)
                span.set_attribute("failure_count", failure_count)
                span.add_event(f"s3_path: s3://{bucket_name}/{s3path}")
                total_failure_count += failure_count

    return idx


ObservationBatches = TypedDict(
    "ObservationBatches",
    {"batches": List[List[FileEntryBatchType]], "total_size": int},
)


def make_observation_batches(
    bucket_date: str, probe_cc: List[str], test_name: List[str]
) -> ObservationBatches:
    day = datetime.strptime(bucket_date, "%Y-%m-%d").date()

    t = PerfTimer()
    file_entry_batches, total_size = list_file_entries_batches(
        probe_cc=probe_cc,
        test_name=test_name,
        start_day=day,
        end_day=day + timedelta(days=1),
    )
    log.info(f"listing {len(file_entry_batches)} batches took {t.pretty}")
    return {"batches": file_entry_batches, "total_size": total_size}


MakeObservationsResult = TypedDict(
    "MakeObservationsResult",
    {
        "measurement_count": int,
        "measurement_per_sec": float,
        "mb_per_sec": float,
        "total_size": int,
    },
)


@activity.defn
async def make_observations(params: MakeObservationsParams) -> MakeObservationsResult:
    loop = asyncio.get_running_loop()

    tbatch = PerfTimer()
    current_span = trace.get_current_span()
    batches = await loop.run_in_executor(
        None,
        functools.partial(
            make_observation_batches,
            probe_cc=params.probe_cc,
            test_name=params.test_name,
            bucket_date=params.bucket_date,
        ),
    )
    awaitables = []
    for file_entry_batch in batches["batches"]:
        awaitables.append(
            loop.run_in_executor(
                None,
                functools.partial(
                    make_observations_for_file_entry_batch,
                    file_entry_batch=file_entry_batch,
                    bucket_date=params.bucket_date,
                    probe_cc=params.probe_cc,
                    data_dir=pathlib.Path(params.data_dir),
                    clickhouse=params.clickhouse,
                    write_batch_size=1_000_000,
                    fast_fail=False,
                ),
            )
        )

    measurement_count = sum(await asyncio.gather(*awaitables))

    current_span.set_attribute("total_runtime_ms", tbatch.ms)
    # current_span.set_attribute("total_failure_count", total_failure_count)

    return {
        "measurement_count": measurement_count,
        "mb_per_sec": float(batches["total_size"]) / 1024 / 1024 / tbatch.s,
        "measurement_per_sec": measurement_count / tbatch.s,
        "total_size": batches["total_size"],
    }


@dataclass
class GetPreviousRangeParams:
    clickhouse: str
    bucket_date: str
    test_name: List[str]
    probe_cc: List[str]
    tables: List[str]


@activity.defn
def get_previous_range(params: GetPreviousRangeParams) -> List[PrevRange]:
    with ClickhouseConnection(params.clickhouse) as db:
        prev_ranges = []
        for table_name in params.tables:
            prev_ranges.append(
                get_prev_range(
                    db=db,
                    table_name=table_name,
                    bucket_date=params.bucket_date,
                    test_name=params.test_name,
                    probe_cc=params.probe_cc,
                ),
            )
    return prev_ranges


@dataclass
class DeletePreviousRangeParams:
    clickhouse: str
    previous_ranges: List[PrevRange]


@activity.defn
def delete_previous_range(params: DeletePreviousRangeParams) -> None:
    with ClickhouseConnection(params.clickhouse) as db:
        for pr in params.previous_ranges:
            log.info("deleting previous range of {pr}")
            maybe_delete_prev_range(db=db, prev_range=pr)
