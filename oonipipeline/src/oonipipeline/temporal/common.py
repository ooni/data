from dataclasses import dataclass
import queue
import logging
import multiprocessing as mp
from multiprocessing.synchronize import Event as EventClass

from datetime import datetime, timedelta

from typing import (
    Any,
    Callable,
    Dict,
    List,
    NamedTuple,
    Optional,
    Tuple,
)

from tqdm import tqdm
from oonidata.dataclient import (
    MeasurementListProgress,
)
from ..db.connections import ClickhouseConnection

log = logging.getLogger("oonidata.processing")


@dataclass
class BatchParameters:
    test_name: List[str]
    probe_cc: List[str]
    bucket_date: Optional[str]
    timestamp: Optional[datetime]


@dataclass
class PrevRange:
    table_name: str
    batch_parameters: BatchParameters
    timestamp_column: Optional[str]
    probe_cc_column: Optional[str]
    max_created_at: Optional[datetime] = None
    min_created_at: Optional[datetime] = None

    def format_query(self):
        start_timestamp = None
        end_timestamp = None
        where = None
        where = "WHERE "
        q_args: Dict[str, Any] = {}

        if self.batch_parameters.bucket_date:
            where = "WHERE bucket_date = %(bucket_date)s"
            q_args["bucket_date"] = self.batch_parameters.bucket_date

        elif self.batch_parameters.timestamp:
            start_timestamp = self.batch_parameters.timestamp
            end_timestamp = start_timestamp + timedelta(days=1)
            q_args["start_timestamp"] = start_timestamp
            q_args["end_timestamp"] = end_timestamp
            where += f"{self.timestamp_column} >= %(start_timestamp)s AND {self.timestamp_column} < %(end_timestamp)s"
        else:
            raise Exception("Must specify either bucket_date or timestamp")

        if len(self.batch_parameters.test_name) > 0:
            where += " AND test_name IN %(test_names)s"
            q_args["test_names"] = self.batch_parameters.test_name
        if len(self.batch_parameters.probe_cc) > 0:
            where += f" AND {self.probe_cc_column} IN %(probe_ccs)s"
            q_args["probe_ccs"] = self.batch_parameters.probe_cc

        return where, q_args


def maybe_delete_prev_range(db: ClickhouseConnection, prev_range: PrevRange):
    """
    We perform a lightweight delete of all the rows which have been
    regenerated, so we don't have any duplicates in the table
    """
    if not prev_range.max_created_at or not prev_range.min_created_at:
        return

    # Disabled due to: https://github.com/ClickHouse/ClickHouse/issues/40651
    # db.execute("SET allow_experimental_lightweight_delete = true;")

    where, q_args = prev_range.format_query()

    q_args["max_created_at"] = prev_range.max_created_at
    q_args["min_created_at"] = prev_range.min_created_at
    where = f"{where} AND created_at <= %(max_created_at)s AND created_at >= %(min_created_at)s"
    log.debug(f"runing {where} with {q_args}")

    q = f"ALTER TABLE {prev_range.table_name} DELETE "
    final_query = q + where
    return db.execute(final_query, q_args)


def get_prev_range(
    db: ClickhouseConnection,
    table_name: str,
    test_name: List[str],
    probe_cc: List[str],
    bucket_date: Optional[str] = None,
    timestamp: Optional[datetime] = None,
    timestamp_column: str = "timestamp",
    probe_cc_column: str = "probe_cc",
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
    # A batch specified by test_name, probe_cc and one of either bucket_date or
    # timestamp depending on it being observations or experiment results.
    assert (
        timestamp or bucket_date
    ), "either timestamp or bucket_date should be provided"
    prev_range = PrevRange(
        table_name=table_name,
        batch_parameters=BatchParameters(
            test_name=test_name,
            probe_cc=probe_cc,
            timestamp=timestamp,
            bucket_date=bucket_date,
        ),
        timestamp_column=timestamp_column,
        probe_cc_column=probe_cc_column,
    )

    q = f"SELECT MAX(created_at), MIN(created_at) FROM {prev_range.table_name} "
    where, q_args = prev_range.format_query()
    final_query = q + where
    prev_obs_range = db.execute(final_query, q_args)
    assert isinstance(prev_obs_range, list) and len(prev_obs_range) == 1
    max_created_at, min_created_at = prev_obs_range[0]

    # We pad it by 1 second to take into account the time resolution downgrade
    # happening when going from clickhouse to python data types
    if max_created_at and min_created_at:
        prev_range.max_created_at = (max_created_at + timedelta(seconds=1)).replace(
            tzinfo=None
        )
        prev_range.min_created_at = (min_created_at - timedelta(seconds=1)).replace(
            tzinfo=None
        )

    return prev_range


def make_db_rows(
    dc_list: List,
    column_names: List[str],
    bucket_date: Optional[str] = None,
    custom_remap: Optional[Dict[str, Callable]] = None,
) -> Tuple[str, List[str]]:
    # TODO(art): this function is quite sketchy
    assert len(dc_list) > 0

    def maybe_remap(k, value):
        if custom_remap and k in custom_remap:
            return custom_remap[k](value)
        return value

    table_name = dc_list[0].__table_name__
    rows = []
    for d in dc_list:
        if bucket_date:
            d.bucket_date = bucket_date
        assert table_name == d.__table_name__, "inconsistent group of observations"
        rows.append(tuple(maybe_remap(k, getattr(d, k)) for k in column_names))

    return table_name, rows
