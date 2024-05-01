import csv
from dataclasses import asdict
import pickle
import random
import time

from collections import defaultdict, namedtuple
from datetime import datetime, timezone
from pprint import pformat
import logging
from typing import Iterable, List, Optional, Union

from oonidata.models.base import TableModelProtocol

log = logging.getLogger("oonidata.processing")


class DatabaseConnection:
    def __init__(self):
        self.client = None

    def execute(self, *args, **kwargs):
        pass

    def write_rows(self, table_name, rows, columns_names):
        log.info(f"Writing to {table_name} {columns_names}")
        log.info(pformat(rows))

    def close(self):
        pass


class ClickhouseConnection(DatabaseConnection):
    def __init__(
        self,
        conn_url,
        row_buffer_size=0,
        max_block_size=1_000_000,
        max_retries=3,
        backoff_factor=1.0,
        max_backoff=32.0,
    ):
        from clickhouse_driver import Client

        self.clickhouse_url = conn_url
        self.client = Client.from_url(conn_url)

        self.row_buffer_size = row_buffer_size
        self.max_block_size = max_block_size

        self._column_names = {}
        self._row_buffer = defaultdict(list)

        self._max_retries = max_retries
        self._max_backoff = max_backoff
        self._backoff_factor = backoff_factor

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def delete_sync(self, table_name: str, where: str):
        self.execute("SET allow_experimental_lightweight_delete = true;")
        self.execute("SET mutations_sync = 1;")
        return self.execute(f"DELETE FROM {table_name} WHERE {where};")

    def _execute(self, *args, **kwargs):
        return self.client.execute(*args, **kwargs)

    def execute(self, query_str, *args, **kwargs):
        exception_list = []
        # Exponentially backoff the retries
        for attempt in range(self._max_retries):
            try:
                return self._execute(query_str, *args, **kwargs)
            except Exception as e:
                exception_list.append(e)
                sleep_time = min(self._max_backoff, self._backoff_factor * (2**attempt))
                log.error(
                    f"failed to execute {query_str} args[{len(args)}] kwargs[{len(kwargs)}] (attempt {attempt})"
                )
                log.error(e)
                log.error("### Exception history")
                for exc in exception_list[:-1]:
                    log.error(exc)
                sleep_time += random.uniform(0, sleep_time * 0.1)
                time.sleep(sleep_time)
        # Raise the last exception
        raise exception_list[-1]

    def execute_iter(self, *args, **kwargs):
        return self.client.execute_iter(
            *args, **kwargs, settings={"max_block_size": self.max_block_size}
        )

    def write_rows(self, table_name, rows, column_names, use_buffer_table=False):
        if use_buffer_table:
            table_name = f"buffer_{table_name}"
        fields_str = ", ".join(column_names)
        query_str = f"INSERT INTO {table_name} ({fields_str}) VALUES"
        self.execute(query_str, rows)

    def write_table_model_rows(
        self,
        row_iterator: Union[Iterable, List],
        use_buffer_table=True,
    ):
        row_list = []
        column_names = None
        table_name = None
        for row in row_iterator:
            d = asdict(row)
            if "probe_meta" in d:
                d.update(d.pop("probe_meta"))
            if "measurement_meta" in d:
                d.update(d.pop("measurement_meta"))

            if column_names is None:
                assert table_name is None
                table_name = row.__table_name__
                column_names = list(d.keys())
            else:
                assert column_names == list(d.keys())
            row_list.append(d)

        if len(row_list) == 0:
            return

        assert table_name is not None
        assert column_names is not None
        if use_buffer_table:
            table_name = f"buffer_{table_name}"
        fields_str = ", ".join(column_names)
        query_str = f"INSERT INTO {table_name} ({fields_str}) VALUES"
        self.execute(query_str, row_list)

    def close(self):
        self.client.disconnect()


CSVConnectionHandle = namedtuple("CSVConnectionHandle", ["fh", "writer"])


class CSVConnection(DatabaseConnection):
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.open_writers = {}

    def write_rows(self, table_name, rows, column_names):
        if table_name not in self.open_writers:
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
            fh = (self.output_dir / f"{table_name}-{ts}.csv").open("w")
            csv_writer = csv.writer(fh)
            csv_writer.writerow(column_names)
            self.open_writers[table_name] = CSVConnectionHandle(
                writer=csv_writer, fh=fh
            )
        self.open_writers[table_name].writer.writerows(rows)

    def close(self):
        for handle in self.open_writers.values():
            handle.fh.close()
