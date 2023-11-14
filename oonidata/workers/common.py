import queue
import logging
import multiprocessing as mp
from multiprocessing.synchronize import Event as EventClass

from datetime import date, datetime, timedelta

from typing import (
    Dict,
    List,
    NamedTuple,
    Optional,
    Tuple,
)

from tqdm import tqdm
from oonidata.dataclient import (
    MeasurementListProgress,
    ProgressStatus,
)
from oonidata.db.connections import (
    ClickhouseConnection,
)

log = logging.getLogger("oonidata.processing")


class PrevRange(NamedTuple):
    bucket_date: Optional[str]
    start_timestamp: Optional[datetime]
    end_timestamp: Optional[datetime]
    max_created_at: Optional[datetime]
    min_created_at: Optional[datetime]
    where: str


def get_prev_range(
    db: ClickhouseConnection,
    table_name: str,
    test_name: List[str],
    probe_cc: List[str],
    bucket_date: Optional[str] = None,
    timestamp: Optional[datetime] = None,
    timestamp_column: str = "timestamp",
) -> PrevRange:
    """
    We lookup the range of previously generated rows so we can drop
    them from the database once we have finished processing.

    We can't rely just on deduplication happening at the clickhouse level,
    because we might in the future add or remove certain rows, so it's
    more robust to just drop them once we are done reprocessing.

    Moreover, you don't have any guarantee on when the deduplication is
    happening, which means that if you run queries while the reprocessing is
    happening you don't know when exactly it's going to be safe to run
    deduplcated queries on the DB.

    For observation tables we use the bucket_date field. For experiment results
    we use a range of timestamp in a day.
    In both cases we delimit the range via the created_at column and any
    additional filters that may have been applied to the reprocessing process.

    TODO: while the reprocessing is running we should probably flag this
    bucket as reprocessing in progress and guard against running queries for
    it.
    """
    q = f"SELECT MAX(created_at), MIN(created_at) FROM {table_name} "
    assert (
        timestamp or bucket_date
    ), "either timestamp or bucket_date should be provided"
    start_timestamp = None
    end_timestamp = None
    where = None
    where = "WHERE bucket_date = %(bucket_date)s"
    q_args = {"bucket_date": bucket_date}
    if timestamp:
        start_timestamp = timestamp
        end_timestamp = timestamp + timedelta(days=1)
        q_args = {"start_timestamp": start_timestamp, "end_timestamp": end_timestamp}
        where = f"WHERE {timestamp_column} >= %(start_timestamp)s AND {timestamp_column} < %(end_timestamp)s"

    if len(test_name) > 0:
        test_name_list = []
        for tn in test_name:
            # sanitize the test_names. It should not be a security issue since
            # it's not user provided, but better safe than sorry
            assert tn.replace("_", "").isalnum(), f"not alphabetic testname {tn}"
            test_name_list.append(f"'{tn}'")
        where += " AND test_name IN ({})".format(",".join(test_name_list))
    if len(probe_cc) > 0:
        probe_cc_list = []
        for cc in probe_cc:
            assert cc.replace("_", "").isalnum(), f"not alphabetic probe_cc"
            probe_cc_list.append(f"'{cc}'")
        where += " AND probe_cc IN ({})".format(",".join(probe_cc_list))

    prev_obs_range = db.execute(q + where, q_args)
    assert isinstance(prev_obs_range, list) and len(prev_obs_range) == 1
    max_created_at, min_created_at = prev_obs_range[0]

    # We pad it by 1 second to take into account the time resolution downgrade
    # happening when going from clickhouse to python data types
    if max_created_at and min_created_at:
        max_created_at += timedelta(seconds=1)
        min_created_at -= timedelta(seconds=1)

    return PrevRange(
        max_created_at=max_created_at,
        min_created_at=min_created_at,
        start_timestamp=start_timestamp,
        end_timestamp=end_timestamp,
        where=where,
        bucket_date=bucket_date,
    )


def get_obs_count_by_cc(
    db: ClickhouseConnection,
    test_name: List[str],
    start_day: date,
    end_day: date,
    table_name: str = "obs_web",
) -> Dict[str, int]:
    q = f"SELECT probe_cc, COUNT() FROM {table_name} WHERE measurement_start_time > %(start_day)s AND measurement_start_time < %(end_day)s GROUP BY probe_cc"
    cc_list: List[Tuple[str, int]] = db.execute(
        q, {"start_day": start_day, "end_day": end_day}
    )  # type: ignore
    assert isinstance(cc_list, list)
    return dict(cc_list)


def maybe_delete_prev_range(
    db: ClickhouseConnection, table_name: str, prev_range: PrevRange
):
    """
    We perform a lightweight delete of all the rows which have been
    regenerated, so we don't have any duplicates in the table
    """
    if not prev_range.max_created_at:
        return

    # Disabled due to: https://github.com/ClickHouse/ClickHouse/issues/40651
    # db.execute("SET allow_experimental_lightweight_delete = true;")
    q_args = {
        "max_created_at": prev_range.max_created_at,
        "min_created_at": prev_range.min_created_at,
    }
    if prev_range.bucket_date:
        q_args["bucket_date"] = prev_range.bucket_date
    elif prev_range.start_timestamp:
        q_args["start_timestamp"] = prev_range.start_timestamp
        q_args["end_timestamp"] = prev_range.end_timestamp
    else:
        raise Exception("either bucket_date or timestamps should be set")

    where = f"{prev_range.where} AND created_at <= %(max_created_at)s AND created_at >= %(min_created_at)s"
    return db.execute(f"ALTER TABLE {table_name} DELETE " + where, q_args)


def make_db_rows(
    dc_list: List, column_names: List[str], bucket_date: Optional[str] = None
) -> Tuple[str, List[str]]:
    assert len(dc_list) > 0

    table_name = dc_list[0].__table_name__
    rows = []
    for d in dc_list:
        if bucket_date:
            d.bucket_date = bucket_date
        assert table_name == d.__table_name__, "inconsistent group of observations"
        rows.append(tuple(getattr(d, k) for k in column_names))

    return table_name, rows


class StatusMessage(NamedTuple):
    src: str
    exception: Optional[Exception] = None
    traceback: Optional[str] = None
    progress: Optional[MeasurementListProgress] = None
    idx: Optional[int] = None
    day_str: Optional[str] = None
    archive_queue_size: Optional[int] = None


def run_status_thread(status_queue: mp.Queue, shutdown_event: EventClass):
    total_prefixes = 0
    current_prefix_idx = 0

    total_file_entries = 0
    current_file_entry_idx = 0
    download_desc = ""
    last_idx_desc = ""
    qsize_desc = ""

    pbar_listing = tqdm(position=0)
    pbar_download = tqdm(unit="B", unit_scale=True, position=1)

    log.info("starting error handling thread")
    while not shutdown_event.is_set():
        try:
            res = status_queue.get(block=True, timeout=0.1)
        except queue.Empty:
            continue

        if res.exception:
            log.error(f"got an error from {res.src}: {res.exception} {res.traceback}")

        if res.progress:
            p = res.progress
            if p.progress_status == ProgressStatus.LISTING_BEGIN:
                total_prefixes += p.total_prefixes
                pbar_listing.total = total_prefixes

                pbar_listing.set_description("starting listing")

            if p.progress_status == ProgressStatus.LISTING:
                current_prefix_idx += 1
                pbar_listing.update(1)
                pbar_listing.set_description(
                    f"listed {current_prefix_idx}/{total_prefixes} prefixes"
                )

            if p.progress_status == ProgressStatus.DOWNLOAD_BEGIN:
                if not pbar_download.total:
                    pbar_download.total = 0
                total_file_entries += p.total_file_entries
                pbar_download.total += p.total_file_entry_bytes

            if p.progress_status == ProgressStatus.DOWNLOADING:
                current_file_entry_idx += 1
                download_desc = (
                    f"downloading {current_file_entry_idx}/{total_file_entries} files"
                )
                pbar_download.update(p.current_file_entry_bytes)

        if res.idx:
            last_idx_desc = f" idx: {res.idx} ({res.day_str})"

        if res.archive_queue_size:
            qsize_desc = f" aqsize: {res.archive_queue_size}"

        pbar_download.set_description(download_desc + last_idx_desc + qsize_desc)

        status_queue.task_done()


def run_progress_thread(
    status_queue: mp.Queue, shutdown_event: EventClass, desc: str = "analyzing data"
):
    pbar = tqdm(position=0)

    log.info("starting error handling thread")
    while not shutdown_event.is_set():
        try:
            count = status_queue.get(block=True, timeout=0.1)
        except queue.Empty:
            continue

        try:
            pbar.update(count)
            pbar.set_description(desc)
        finally:
            status_queue.task_done()
