import ssl

import itertools
from datetime import datetime, timedelta
from typing import List, Optional
from tqdm import tqdm
from collections import defaultdict

from clickhouse_driver import Client as Clickhouse

from urllib.parse import urlparse, parse_qs, unquote


# from paste.deploy.converters
def asbool(obj):
    if isinstance(obj, str):
        obj = obj.strip().lower()
        if obj in ["true", "yes", "on", "y", "t", "1"]:
            return True
        elif obj in ["false", "no", "off", "n", "f", "0"]:
            return False
        else:
            raise ValueError("String is not true/false: %r" % obj)
    return bool(obj)


# from clickhouse_driver.util.helpers
def parse_clickhouse_url(url):
    """
    Parses url into host and kwargs suitable for further Client construction.
    Return host and kwargs.

    For example::

        clickhouse://[user:password]@localhost:9000/default
        clickhouses://[user:password]@localhost:9440/default

    Three URL schemes are supported:

        * clickhouse:// creates a normal TCP socket connection
        * clickhouses:// creates a SSL wrapped TCP socket connection

    Any additional querystring arguments will be passed along to
    the Connection class's initializer.
    """
    url = urlparse(url)

    settings = {}
    kwargs = {}

    host = url.hostname

    if url.port is not None:
        kwargs["port"] = url.port

    path = url.path.replace("/", "", 1)
    if path:
        kwargs["database"] = path

    if url.username is not None:
        kwargs["user"] = unquote(url.username)

    if url.password is not None:
        kwargs["password"] = unquote(url.password)

    if url.scheme == "clickhouses":
        kwargs["secure"] = True

    compression_algs = {"lz4", "lz4hc", "zstd"}
    timeouts = {"connect_timeout", "send_receive_timeout", "sync_request_timeout"}

    for name, value in parse_qs(url.query).items():
        if not value or not len(value):
            continue

        value = value[0]

        if name == "compression":
            value = value.lower()
            if value in compression_algs:
                kwargs[name] = value
            else:
                kwargs[name] = asbool(value)

        elif name == "secure":
            kwargs[name] = asbool(value)

        elif name == "use_numpy":
            settings[name] = asbool(value)

        elif name == "round_robin":
            kwargs[name] = asbool(value)

        elif name == "client_name":
            kwargs[name] = value

        elif name in timeouts:
            kwargs[name] = float(value)

        elif name == "compress_block_size":
            kwargs[name] = int(value)

        elif name == "settings_is_important":
            kwargs[name] = asbool(value)

        elif name == "tcp_keepalive":
            try:
                kwargs[name] = asbool(value)
            except ValueError:
                parts = value.split(",")
                kwargs[name] = (int(parts[0]), int(parts[1]), int(parts[2]))
        elif name == "client_revision":
            kwargs[name] = int(value)

        # ssl
        elif name == "verify":
            kwargs[name] = asbool(value)
        elif name == "ssl_version":
            kwargs[name] = getattr(ssl, value)
        elif name in ["ca_certs", "ciphers", "keyfile", "certfile", "server_hostname"]:
            kwargs[name] = value
        elif name == "alt_hosts":
            kwargs["alt_hosts"] = value
        else:
            settings[name] = value

    if settings:
        kwargs["settings"] = settings

    return host, kwargs


def click_execute(
    q,
    params: Optional[dict] = None,
    clickhouse_url: str = "clickhouse://localhost/default",
):
    host, kwargs = parse_clickhouse_url(clickhouse_url)
    kwargs["connect_timeout"] = 10
    kwargs["send_receive_timeout"] = 60 * 15
    kwargs["sync_request_timeout"] = 5
    click = Clickhouse(host, **kwargs)
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
        short_bucket_date
        FROM (
            WITH concat(substring(bucket_date, 1, 4), '-', substring(bucket_date, 6, 2), '-', substring(bucket_date, 9, 2)) as short_bucket_date
            SELECT
            CONCAT(measurement_uid, '-', toString(observation_idx)) as uid,
            COUNT() as uid_cnt,
            short_bucket_date
            FROM {target_table}
            WHERE short_bucket_date IN %(bucket_date)s
            GROUP BY short_bucket_date, uid
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
