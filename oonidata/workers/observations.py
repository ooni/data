import pathlib
import logging
import dataclasses
from datetime import date, timedelta

from typing import (
    List,
    Optional,
)

import statsd

import dask
from dask.distributed import Client as DaskClient
from dask.distributed import progress as dask_progress
from dask.distributed import wait as dask_wait

from oonidata.analysis.datasources import load_measurement
from oonidata.datautils import PerfTimer

from oonidata.netinfo import NetinfoDB

from oonidata.dataclient import (
    date_interval,
    iter_measurements,
    list_file_entries_batches,
    stream_measurements,
    ccs_set,
)
from oonidata.db.connections import (
    ClickhouseConnection,
    CSVConnection,
)
from oonidata.transforms import measurement_to_observations
from oonidata.workers.common import (
    get_prev_range,
    make_db_rows,
    maybe_delete_prev_range,
)

log = logging.getLogger("oonidata.processing")


@dask.delayed  # type: ignore
def make_observations_for_file_entry_batch(
    file_entry_batch,
    clickhouse,
    row_buffer_size,
    netinfodb,
    bucket_date,
    probe_cc,
    fast_fail,
):
    tbatch = PerfTimer()
    db = ClickhouseConnection(clickhouse, row_buffer_size=row_buffer_size)
    statsd_client = statsd.StatsClient("localhost", 8125)
    ccs = ccs_set(probe_cc)
    idx = 0
    for bucket_name, s3path, ext, fe_size in file_entry_batch:
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
                    for observations in measurement_to_observations(
                        msmt, netinfodb=netinfodb
                    ):
                        if len(observations) == 0:
                            continue

                        column_names = [
                            f.name for f in dataclasses.fields(observations[0])
                        ]
                        table_name, rows = make_db_rows(
                            bucket_date=bucket_date,
                            dc_list=observations,
                            column_names=column_names,
                        )
                        db.write_rows(
                            table_name=table_name, rows=rows, column_names=column_names
                        )
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
        except Exception as exc:
            log.error(f"failed to stream measurements from s3://{bucket_name}/{s3path}")
            log.error(exc)
        statsd_client.timing("oonidata.dataclient.stream_file_entry.timed", t.ms, rate=0.1)  # type: ignore
        statsd_client.gauge("oonidata.dataclient.file_entry.kb_per_sec.gauge", fe_size / 1024 / t.s, rate=0.1)  # type: ignore
    statsd_client.timing("oonidata.dataclient.batch.timed", tbatch.ms)  # type: ignore


def make_observation_in_day(
    probe_cc: List[str],
    test_name: List[str],
    csv_dir: Optional[pathlib.Path],
    clickhouse: Optional[str],
    data_dir: pathlib.Path,
    fast_fail: bool,
    day: date,
    parallelism: int,
):
    from dask.graph_manipulation import bind

    dask_client = DaskClient(
        threads_per_worker=2,
        n_workers=parallelism,
    )
    statsd_client = statsd.StatsClient("localhost", 8125)
    netinfodb = NetinfoDB(datadir=data_dir, download=False)

    db = None
    if clickhouse:
        db = ClickhouseConnection(clickhouse, row_buffer_size=10_000)
    elif csv_dir:
        db = CSVConnection(csv_dir)
    assert db, "no DB chosen"

    bucket_date = day.strftime("%Y-%m-%d")

    prev_ranges = []
    if isinstance(db, ClickhouseConnection):
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
    file_entry_batches = list_file_entries_batches(
        probe_cc=probe_cc,
        test_name=test_name,
        start_day=day,
        end_day=day + timedelta(days=1),
        batch_count=60,
    )
    print(f"running {len(file_entry_batches)} batches took {t.pretty}")

    task_list = []
    for batch in file_entry_batches:
        task_list.append(
            make_observations_for_file_entry_batch(
                batch,
                clickhouse,
                10_000,
                netinfodb,
                bucket_date,
                probe_cc,
                fast_fail,
            )
        )

    futures = dask_client.compute(task_list)
    dask_progress(futures)
    print("waiting on task_list")
    dask_wait(futures)

    if len(prev_ranges) > 0 and isinstance(db, ClickhouseConnection):
        for table_name, pr in prev_ranges:
            maybe_delete_prev_range(db=db, prev_range=pr, table_name=table_name)

    db.close()


def start_observation_maker(
    probe_cc: List[str],
    test_name: List[str],
    start_day: date,
    end_day: date,
    csv_dir: Optional[pathlib.Path],
    clickhouse: Optional[str],
    data_dir: pathlib.Path,
    parallelism: int,
    fast_fail: bool,
    log_level: int = logging.INFO,
):
    assert clickhouse or csv_dir, "missing either clickhouse or csv_dir"

    day_list = list(date_interval(start_day, end_day))
    # See: https://stackoverflow.com/questions/51099685/best-practices-in-setting-number-of-dask-workers
    for day in day_list:
        make_observation_in_day(
            probe_cc=probe_cc,
            test_name=test_name,
            csv_dir=csv_dir,
            clickhouse=clickhouse,
            data_dir=data_dir,
            fast_fail=fast_fail,
            day=day,
            parallelism=parallelism,
        )
