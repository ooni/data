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
from dask.distributed import Client, progress

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


@dask.delayed
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
            statsd_client.timing("make_observations.timed", t.ms)
            statsd_client.incr("make_observations.msmt_count")
        except Exception as exc:
            msmt_str = ""
            if msmt:
                msmt_str = msmt.report_id
                if msmt.input:
                    msmt_str += f"?input={msmt.input}"
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
    dask_client = Client(threads_per_worker=4, n_workers=parallelism)

    assert clickhouse or csv_dir, "missing either clickhouse or csv_dir"

    task_list = []
    for day in date_interval(start_day, end_day):
        t = make_observation_in_day(
            probe_cc=probe_cc,
            test_name=test_name,
            csv_dir=csv_dir,
            clickhouse=clickhouse,
            data_dir=data_dir,
            fast_fail=fast_fail,
            day=day,
        )
        task_list.append(t)

    t = dask.persist(*task_list)
    progress(t)

    t.compute()
