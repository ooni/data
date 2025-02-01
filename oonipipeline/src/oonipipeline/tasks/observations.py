import asyncio
import pathlib
import logging
import concurrent.futures
from dataclasses import dataclass
import functools
from typing import Any, Dict, List, Optional, Sequence, Tuple, TypedDict
from datetime import datetime, timedelta

from opentelemetry import trace

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
from oonipipeline.tasks.common import update_assets
from oonipipeline.settings import config
from oonipipeline.transforms.observations import measurement_to_observations


log = logging.getLogger()

@dataclass
class MakeObservationsParams:
    probe_cc: List[str]
    test_name: List[str]
    clickhouse: str
    data_dir: str
    fast_fail: bool
    bucket_date: str


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


def write_observations_to_db(
    db: ClickhouseConnection,
    netinfodb: NetinfoDB,
    bucket_date: str,
    msmt: SupportedDataformats,
):
    obs_tuple = measurement_to_observations(
        msmt=msmt,
        netinfodb=netinfodb,
        bucket_date=bucket_date,
    )
    for obs_list in obs_tuple:
        db.write_table_model_rows(obs_list)


def make_observations_for_file_entry(
    db: ClickhouseConnection,
    netinfodb: NetinfoDB,
    bucket_date: str,
    bucket_name: str,
    s3path: str,
    ext: str,
    ccs: set,
    fast_fail: bool,
):
    failure_count = 0
    measurement_count = 0
    for msmt_dict in stream_measurements(
        bucket_name=bucket_name, s3path=s3path, ext=ext
    ):
        # Legacy cans don't allow us to pre-filter on the probe_cc, so
        # we need to check for probe_cc consistency in here.
        if ccs and msmt_dict["probe_cc"] not in ccs:
            continue

        measurement_uid = msmt_dict.get("measurement_uid", None)
        report_id = msmt_dict.get("report_id", None)
        msmt_str = f"muid={measurement_uid} (rid={report_id})"

        if not msmt_dict.get("test_keys", None):
            log.error(
                f"measurement with empty test_keys: ({msmt_str})",
                exc_info=True,
            )
            continue
        try:
            msmt = load_measurement(msmt_dict)
            write_observations_to_db(
                db=db, netinfodb=netinfodb, bucket_date=bucket_date, msmt=msmt
            )
            measurement_count += 1
        except Exception as exc:
            log.error(f"failed at idx: {measurement_count} ({msmt_str})", exc_info=True)
            failure_count += 1
            if fast_fail:
                db.close()
                raise exc
    log.debug(f"done processing file s3://{bucket_name}/{s3path}")
    return measurement_count, failure_count


def make_observations_for_file_entry_batch(
    file_entry_batch: List[FileEntryBatchType],
    bucket_date: str,
    probe_cc: List[str],
    data_dir: pathlib.Path,
    clickhouse: str,
    write_batch_size: int,
    fast_fail: bool = False,
) -> int:
    tbatch = PerfTimer()
    total_failure_count = 0
    ccs = ccs_set(probe_cc)
    total_measurement_count = 0
    netinfodb = NetinfoDB(datadir=data_dir, download=False)
    with ClickhouseConnection(clickhouse, write_batch_size=write_batch_size) as db:
        for bucket_name, s3path, ext, fe_size in file_entry_batch:
            failure_count = 0
            log.debug(f"processing file s3://{bucket_name}/{s3path}")
            try:
                measurement_count, failure_count = make_observations_for_file_entry(
                    db=db,
                    netinfodb=netinfodb,
                    bucket_date=bucket_date,
                    bucket_name=bucket_name,
                    s3path=s3path,
                    ext=ext,
                    fast_fail=fast_fail,
                    ccs=ccs,
                )
            except Exception as exc:
                log.error(
                    f"corrupt file entry s3://{bucket_name}/{s3path}", exc_info=True
                )
                if fast_fail:
                    raise exc
            total_measurement_count += measurement_count
        total_failure_count += failure_count

    log.info(
        f"finished batch for bucket_date={bucket_date}\n"
        f"    {len(file_entry_batch)} entries \n"
        f"    in {tbatch.s:.3f} seconds \n"
        f"    msmt/s: {total_measurement_count / tbatch.s}"
    )
    return total_measurement_count


ObservationBatches = TypedDict(
    "ObservationBatches",
    {"batches": List[List[FileEntryBatchType]], "total_size": int},
)


def make_observation_batches(
    bucket_date: str, probe_cc: List[str], test_name: List[str]
) -> ObservationBatches:
    """
    Lists all file_entries for the specified batch bucket_date and returns them
    in batches.

    bucket_date: is a string either formatted as YYYY-MM-DD or YYYY-MM-DDTHH
    depending on whether we are processing an hourly batch or a daily batch.
    """
    if "T" in bucket_date:
        start_hour = datetime.strptime(bucket_date, "%Y-%m-%dT%H")
        end_hour = start_hour + timedelta(hours=1)
    else:
        start_hour = datetime.strptime(bucket_date, "%Y-%m-%d")
        end_hour = start_hour + timedelta(days=1)

    t = PerfTimer()
    file_entry_batches, total_size = list_file_entries_batches(
        probe_cc=probe_cc,
        test_name=test_name,
        start_hour=start_hour,
        end_hour=end_hour,
    )
    log.info(
        f"listing bucket_date={bucket_date} {len(file_entry_batches)} batches took {t.pretty}"
    )
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


def make_observations(params: MakeObservationsParams) -> MakeObservationsResult:
    tbatch = PerfTimer()
    current_span = trace.get_current_span()
    log.debug(f"starting update_assets for {params.bucket_date}")

    update_assets(
        data_dir=params.data_dir,
        refresh_hours=10,
        force_update=False,
    )

    batches = make_observation_batches(
        probe_cc=params.probe_cc,
        test_name=params.test_name,
        bucket_date=params.bucket_date,
    )

    with concurrent.futures.ProcessPoolExecutor(max_workers=config.max_workers) as executor:
        futures = [
            executor.submit(
                make_observations_for_file_entry_batch,
                file_entry_batch=file_entry_batch,
                bucket_date=params.bucket_date,
                probe_cc=params.probe_cc,
                data_dir=pathlib.Path(params.data_dir),
                clickhouse=params.clickhouse,
                write_batch_size=config.clickhouse_write_batch_size,
                fast_fail=False,
            )
            for file_entry_batch in batches["batches"]
        ]
        measurement_count = sum(
            f.result() for f in concurrent.futures.as_completed(futures)
        )

    current_span.set_attribute("total_runtime_ms", tbatch.ms)
    # current_span.set_attribute("total_failure_count", total_failure_count)

    return {
        "measurement_count": measurement_count,
        "mb_per_sec": float(batches["total_size"]) / 1024 / 1024 / tbatch.s,
        "measurement_per_sec": measurement_count / tbatch.s,
        "total_size": batches["total_size"],
    }
