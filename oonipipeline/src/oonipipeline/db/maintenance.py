import itertools
from datetime import datetime, timedelta
from typing import List, Optional
from tqdm import tqdm
from collections import defaultdict

from clickhouse_driver import Client as Clickhouse


def click_execute(q, params: Optional[dict] = None, clickhouse_url: str = "localhost"):
    click = Clickhouse(
        "localhost",
        connect_timeout=10,
        send_receive_timeout=60 * 15,
        sync_request_timeout=5,
    )
    return click.execute(q, params=params)


def batch(iterable, n=1):
    l = len(iterable)
    for ndx in range(0, l, n):
        yield iterable[ndx : min(ndx + n, l)]


def list_duplicates_in_buckets(
    clickhouse_url: str,
    start_bucket: datetime,
    end_bucket: datetime,
    target_table: str = "obs_web",
) -> List:
    end_delta = (end_bucket - start_bucket).days
    bucket_range = [
        (start_bucket + timedelta(days=offset)).strftime("%Y-%m-%d")
        for offset in range(end_delta)
    ]
    result_list = []
    for bucket_dates in tqdm(list(batch(bucket_range, n=5))):
        res = click_execute(
            f"""
        SELECT 
        countIf(uid_cnt > 1) as duplicate_uids,
        bucket_date
        FROM (
            SELECT
            CONCAT(measurement_uid, '-', toString(observation_idx)) as uid,
            COUNT() as uid_cnt,
            bucket_date
            FROM {target_table}
            WHERE bucket_date IN %(bucket_date)s
            GROUP BY bucket_date, uid
        ) GROUP BY bucket_date
        """,
            params={"bucket_date": bucket_dates},
            clickhouse_url=clickhouse_url,
        )
        result_list += res
    return sorted(result_list, key=lambda x: x[1])


def list_partitions_to_delete(result_list):
    partitions_to_clear = []

    sum_by_partition = defaultdict(lambda: 0)
    for count, bucket_date in result_list:
        partition_id = bucket_date.replace("-", "")[:6]
        sum_by_partition[partition_id] += count
    for partition_id, count in sum_by_partition.items():
        if count > 0:
            partitions_to_clear.append(partition_id)
    return partitions_to_clear


def optimize_all_tables_by_partition(
    clickhouse_url: str,
    partition_list,
    tables=["obs_web", "obs_web_ctrl", "obs_http_middlebox"],
):
    for table_name, partition in tqdm(list(itertools.product(tables, partition_list))):
        print(f"optimizing {table_name} partition {partition}")
        click_execute(
            f"OPTIMIZE TABLE {table_name} PARTITION '{partition}'",
            clickhouse_url=clickhouse_url,
        )
