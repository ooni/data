from dataclasses import dataclass
import dataclasses
from typing import List, Sequence, Tuple
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


def make_observations_for_file_entry_batch(
    file_entry_batch: Sequence[Tuple[str, str, str, int]],
    clickhouse: str,
    write_batch_size: int,
    data_dir: pathlib.Path,
    bucket_date: str,
    probe_cc: List[str],
    fast_fail: bool,
):
    netinfodb = NetinfoDB(datadir=data_dir, download=False)
    tbatch = PerfTimer()

    tracer = trace.get_tracer(__name__)

    total_failure_count = 0
    current_span = trace.get_current_span()
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
                            t = PerfTimer()
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

        current_span.set_attribute("total_runtime_ms", tbatch.ms)
        current_span.set_attribute("total_failure_count", total_failure_count)
    return idx


@activity.defn
def make_observation_in_day(params: MakeObservationsParams) -> dict:
    day = datetime.strptime(params.bucket_date, "%Y-%m-%d").date()

    # TODO(art): this previous range search and deletion makes the idempotence
    # of the activity not 100% accurate.
    # We should look into fixing it.
    with ClickhouseConnection(params.clickhouse) as db:
        prev_ranges = []
        for table_name in ["obs_web"]:
            prev_ranges.append(
                (
                    table_name,
                    get_prev_range(
                        db=db,
                        table_name=table_name,
                        bucket_date=params.bucket_date,
                        test_name=params.test_name,
                        probe_cc=params.probe_cc,
                    ),
                )
            )
    log.info(f"prev_ranges: {prev_ranges}")

    t = PerfTimer()
    total_t = PerfTimer()
    file_entry_batches, total_size = list_file_entries_batches(
        probe_cc=params.probe_cc,
        test_name=params.test_name,
        start_day=day,
        end_day=day + timedelta(days=1),
    )
    log.info(f"running {len(file_entry_batches)} batches took {t.pretty}")

    total_msmt_count = 0
    for batch in file_entry_batches:
        msmt_cnt = make_observations_for_file_entry_batch(
            batch,
            params.clickhouse,
            500_000,
            pathlib.Path(params.data_dir),
            params.bucket_date,
            params.probe_cc,
            params.fast_fail,
        )
        total_msmt_count += msmt_cnt

    mb_per_sec = round(total_size / total_t.s / 10**6, 1)
    msmt_per_sec = round(total_msmt_count / total_t.s)
    log.info(
        f"finished processing all batches in {total_t.pretty} speed: {mb_per_sec}MB/s ({msmt_per_sec}msmt/s)"
    )

    if len(prev_ranges) > 0:
        with ClickhouseConnection(params.clickhouse) as db:
            for table_name, pr in prev_ranges:
                log.info("deleting previous range of {pr}")
                maybe_delete_prev_range(db=db, prev_range=pr)

    return {"size": total_size, "measurement_count": total_msmt_count}
