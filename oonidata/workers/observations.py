import pathlib
import logging
import dataclasses
from datetime import date, datetime, timedelta

from typing import (
    List,
    Optional,
    Sequence,
    Tuple,
)

import statsd

from dask.distributed import Client as DaskClient
from dask.distributed import progress as dask_progress
from dask.distributed import wait as dask_wait
from dask.distributed import as_completed

from oonidata.analysis.datasources import load_measurement
from oonidata.datautils import PerfTimer
from oonidata.models.nettests import SupportedDataformats

from oonidata.netinfo import NetinfoDB

from oonidata.dataclient import (
    date_interval,
    list_file_entries_batches,
    stream_measurements,
    ccs_set,
)
from oonidata.db.connections import (
    ClickhouseConnection,
)
from oonidata.transforms import measurement_to_observations
from oonidata.workers.common import (
    get_prev_range,
    make_db_rows,
    maybe_delete_prev_range,
    optimize_all_tables,
)

log = logging.getLogger("oonidata.processing")


def write_observations_to_db(
    msmt: SupportedDataformats,
    netinfodb: NetinfoDB,
    db: ClickhouseConnection,
    bucket_date: str,
):
    for observations in measurement_to_observations(msmt, netinfodb=netinfodb):
        if len(observations) == 0:
            continue

        column_names = [f.name for f in dataclasses.fields(observations[0])]
        table_name, rows = make_db_rows(
            bucket_date=bucket_date,
            dc_list=observations,
            column_names=column_names,
        )
        db.write_rows(table_name=table_name, rows=rows, column_names=column_names)


def make_observations_for_file_entry_batch(
    file_entry_batch: Sequence[Tuple[str, str, str, int]],
    clickhouse: str,
    row_buffer_size: int,
    data_dir: pathlib.Path,
    bucket_date: str,
    probe_cc: str,
    fast_fail: bool,
):
    netinfodb = NetinfoDB(datadir=data_dir, download=False)
    tbatch = PerfTimer()
    with ClickhouseConnection(clickhouse, row_buffer_size=row_buffer_size) as db:
        statsd_client = statsd.StatsClient("localhost", 8125)
        ccs = ccs_set(probe_cc)
        idx = 0
        for bucket_name, s3path, ext, fe_size in file_entry_batch:
            log.info(f"processing file s3://{bucket_name}/{s3path}")
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
                        t = PerfTimer()
                        msmt = load_measurement(msmt_dict)
                        if not msmt.test_keys:
                            log.error(
                                f"measurement with empty test_keys: ({msmt.measurement_uid})",
                                exc_info=True,
                            )
                            continue
                        write_observations_to_db(msmt, netinfodb, db, bucket_date)
                        # following types ignored due to https://github.com/jsocol/pystatsd/issues/146
                        statsd_client.timing("oonidata.make_observations.timed", t.ms, rate=0.1)  # type: ignore
                        statsd_client.incr("oonidata.make_observations.msmt_count", rate=0.1)  # type: ignore
                        idx += 1
                    except Exception as exc:
                        msmt_str = msmt_dict.get("report_id", None)
                        if msmt:
                            msmt_str = msmt.measurement_uid
                        log.error(f"failed at idx: {idx} ({msmt_str})", exc_info=True)

                        if fast_fail:
                            db.close()
                            raise exc
                log.info(f"done processing file s3://{bucket_name}/{s3path}")
            except Exception as exc:
                log.error(
                    f"failed to stream measurements from s3://{bucket_name}/{s3path}"
                )
                log.error(exc)
            statsd_client.timing("oonidata.dataclient.stream_file_entry.timed", t.ms, rate=0.1)  # type: ignore
            statsd_client.gauge("oonidata.dataclient.file_entry.kb_per_sec.gauge", fe_size / 1024 / t.s, rate=0.1)  # type: ignore
        statsd_client.timing("oonidata.dataclient.batch.timed", tbatch.ms)  # type: ignore
    return idx


def make_observation_in_day(
    dask_client: DaskClient,
    probe_cc: List[str],
    test_name: List[str],
    clickhouse: Optional[str],
    data_dir: pathlib.Path,
    fast_fail: bool,
    day: date,
):
    statsd_client = statsd.StatsClient("localhost", 8125)

    bucket_date = day.strftime("%Y-%m-%d")

    with ClickhouseConnection(clickhouse, row_buffer_size=10_000) as db:
        prev_ranges = []
        for table_name in ["obs_web"]:
            prev_ranges.append(
                (
                    table_name,
                    get_prev_range(
                        db=db,
                        table_name=table_name,
                        bucket_date=bucket_date,
                        test_name=test_name,
                        probe_cc=probe_cc,
                    ),
                )
            )

    t = PerfTimer()
    total_t = PerfTimer()
    file_entry_batches, total_size = list_file_entries_batches(
        probe_cc=probe_cc,
        test_name=test_name,
        start_day=day,
        end_day=day + timedelta(days=1),
    )
    log.info(f"running {len(file_entry_batches)} batches took {t.pretty}")

    future_list = []
    for batch in file_entry_batches:
        t = dask_client.submit(
            make_observations_for_file_entry_batch,
            batch,
            clickhouse,
            10_000,
            data_dir,
            bucket_date,
            probe_cc,
            fast_fail,
        )
        future_list.append(t)

    log.debug("starting progress monitoring")
    dask_progress(future_list)
    total_msmt_count = 0
    for _, result in as_completed(future_list, with_results=True):
        total_msmt_count += result  # type: ignore

    log.debug("waiting on task_list")
    dask_wait(future_list)
    mb_per_sec = round(total_size / total_t.s / 10**6, 1)
    msmt_per_sec = round(total_msmt_count / total_t.s)
    log.info(
        f"finished processing all batches in {total_t.pretty} speed: {mb_per_sec}MB/s ({msmt_per_sec}msmt/s)"
    )
    statsd_client.timing("oonidata.dataclient.daily.timed", total_t.ms)

    if len(prev_ranges) > 0:
        with ClickhouseConnection(clickhouse, row_buffer_size=10_000) as db:
            for table_name, pr in prev_ranges:
                maybe_delete_prev_range(db=db, prev_range=pr, table_name=table_name)

    return total_size, total_msmt_count


def start_observation_maker(
    probe_cc: List[str],
    test_name: List[str],
    start_day: date,
    end_day: date,
    clickhouse: Optional[str],
    data_dir: pathlib.Path,
    parallelism: int,
    fast_fail: bool,
    log_level: int = logging.INFO,
):
    log.info("Optimizing all tables")
    optimize_all_tables(clickhouse)

    dask_client = DaskClient(
        threads_per_worker=2,
        n_workers=parallelism,
    )

    t_total = PerfTimer()
    total_size, total_msmt_count = 0, 0
    day_list = list(date_interval(start_day, end_day))
    # See: https://stackoverflow.com/questions/51099685/best-practices-in-setting-number-of-dask-workers

    log.info(f"Starting observation making on {probe_cc} ({start_day} - {end_day})")
    for day in day_list:
        t = PerfTimer()
        size, msmt_count = make_observation_in_day(
            dask_client=dask_client,
            probe_cc=probe_cc,
            test_name=test_name,
            clickhouse=clickhouse,
            data_dir=data_dir,
            fast_fail=fast_fail,
            day=day,
        )
        total_size += size
        total_msmt_count += msmt_count
        mb_per_sec = round(size / t.s / 10**6, 1)
        msmt_per_sec = round(msmt_count / t.s)
        log.info(
            f"finished processing {day} speed: {mb_per_sec}MB/s ({msmt_per_sec}msmt/s)"
        )
        with ClickhouseConnection(clickhouse) as db:
            db.execute(
                "INSERT INTO oonidata_processing_logs (key, timestamp, runtime_ms, bytes, msmt_count, comment) VALUES",
                [
                    [
                        "oonidata.bucket_processed",
                        datetime.utcnow(),
                        int(t.ms),
                        size,
                        msmt_count,
                        day.strftime("%Y-%m-%d"),
                    ]
                ],
            )

    mb_per_sec = round(total_size / t_total.s / 10**6, 1)
    msmt_per_sec = round(total_msmt_count / t_total.s)
    log.info(
        f"finished processing {start_day} - {end_day} speed: {mb_per_sec}MB/s ({msmt_per_sec}msmt/s)"
    )
    log.info(
        f"{round(total_size/10**9, 2)}GB {total_msmt_count} msmts in {t_total.pretty}"
    )
