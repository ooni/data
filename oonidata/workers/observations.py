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


def make_observation_in_day(
    probe_cc: List[str],
    test_name: List[str],
    csv_dir: Optional[pathlib.Path],
    clickhouse: Optional[str],
    data_dir: pathlib.Path,
    fast_fail: bool,
    day: date,
):
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

    for idx, msmt_dict in enumerate(
        iter_measurements(
            probe_cc=probe_cc,
            test_name=test_name,
            start_day=day,
            end_day=day + timedelta(days=1),
        )
    ):
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
            for observations in measurement_to_observations(msmt, netinfodb=netinfodb):
                if len(observations) == 0:
                    continue

                column_names = [f.name for f in dataclasses.fields(observations[0])]
                table_name, rows = make_db_rows(
                    bucket_date=bucket_date,
                    dc_list=observations,
                    column_names=column_names,
                )
                db.write_rows(
                    table_name=table_name, rows=rows, column_names=column_names
                )
            # following types ignored due to https://github.com/jsocol/pystatsd/issues/146
            statsd_client.timing("make_observations.timed", t.ms, rate=0.1)  # type: ignore
            statsd_client.incr("make_observations.msmt_count", rate=0.1)  # type: ignore
        except Exception as exc:
            msmt_str = msmt_dict.get("report_id", None)
            if msmt:
                msmt_str = msmt.measurement_uid
            log.error(f"failed at idx: {idx} ({msmt_str})", exc_info=True)

            if fast_fail:
                db.close()
                raise exc

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
    # When there is only 1 day or parallelism is set to 1, there is no need to
    # use dask.
    if len(day_list) == 1 or parallelism == 1:
        for day in day_list:
            make_observation_in_day(
                probe_cc=probe_cc,
                test_name=test_name,
                csv_dir=csv_dir,
                clickhouse=clickhouse,
                data_dir=data_dir,
                fast_fail=fast_fail,
                day=day,
            )
        return

    # See: https://stackoverflow.com/questions/51099685/best-practices-in-setting-number-of-dask-workers
    dask_client = DaskClient(
        threads_per_worker=2,
        n_workers=parallelism,
    )

    task_list = map(
        lambda day: dask.delayed(  # type: ignore # not working due to https://github.com/dask/dask/issues/9710
            make_observation_in_day(
                probe_cc=probe_cc,
                test_name=test_name,
                csv_dir=csv_dir,
                clickhouse=clickhouse,
                data_dir=data_dir,
                fast_fail=fast_fail,
                day=day,
            )
        ),
        day_list,
    )
    futures = dask_client.compute(task_list)
    dask_progress(futures)
    print("waiting on task_list")
    dask_wait(futures)
