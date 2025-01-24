import csv
from dataclasses import asdict
import pickle
import random
import time

from collections import defaultdict, namedtuple
from datetime import datetime, timezone
from pprint import pformat
import logging
from typing import Dict, Iterable, List, Optional, Tuple, Union

from oonidata.models.base import TableModelProtocol
import orjson

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
        write_batch_size=1_000_000,
        max_block_size=1_000_000,
        max_retries=3,
        backoff_factor=1.0,
        max_backoff=32.0,
    ):
        from clickhouse_driver import Client

        self.clickhouse_url = conn_url
        self.client = Client.from_url(conn_url)

        self.max_block_size = max_block_size

        self.write_batch_size = write_batch_size
        self.row_buffer = defaultdict(list)

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

    def execute(self, query_str, rows=None, *args, **kwargs):
        exception_list = []
        # Exponentially backoff the retries
        for attempt in range(self._max_retries):
            try:
                if attempt > 0:
                    kwargs["types_check"] = True
                return self._execute(query_str, rows, *args, **kwargs)
            except Exception as e:
                exception_list.append(e)
                sleep_time = min(self._max_backoff, self._backoff_factor * (2**attempt))
                row_len = 0
                if rows and len(rows) > 0:
                    row_len = len(rows)
                    log.info(f"{query_str} {rows[0]}")
                log.error(
                    f"failed to execute {query_str} row_len={row_len} args=[{args}] kwargs[{kwargs}] (attempt {attempt})"
                )
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

    def write_rows(self, table_name, rows, column_names):
        fields_str = ", ".join(column_names)
        query_str = f"INSERT INTO {table_name} ({fields_str}) VALUES"
        self.execute(query_str, rows)

    def _consume_rows(
        self, row_iterator: Union[Iterable, List]
    ) -> Tuple[List[Dict], Optional[str]]:
        row_list = []
        table_name = None
        # TODO(art): I'm not a fan of this living in here. It should be much closer to the actual models.
        for row in row_iterator:
            d = asdict(row)
            if "probe_meta" in d:
                d.update(d.pop("probe_meta"))
            if "measurement_meta" in d:
                d.update(d.pop("measurement_meta"))

            if table_name is None:
                table_name = row.__table_name__
            else:
                assert table_name == row.__table_name__, "mixed tables in row iterator"
            row_list.append(d)

        return row_list, table_name

    def write_table_model_rows(
        self,
        row_iterator: Union[Iterable, List],
    ):
        """
        Write rows from a TableModelProtocol to the database.

        We use buffering for performance reasons via a Python in memory buffer
        to batch writes to the underlying database connection via the
        max_block_size argument
        """
        row_list, table_name = self._consume_rows(row_iterator)
        if len(row_list) == 0:
            return
        assert table_name is not None, f"no table for {row_list}"

        if table_name not in self.row_buffer:
            self.row_buffer[table_name] = []
        self.row_buffer[table_name] += row_list

        if len(self.row_buffer[table_name]) >= self.write_batch_size:
            log.debug(f"flushing table {table_name}")
            self.flush(table_name)

    def flush(self, table_name=None):
        if table_name:
            self._flush_table(table_name)
        else:
            for t_name in list(self.row_buffer.keys()):
                self._flush_table(t_name)

    def _flush_table(self, table_name):
        if table_name in self.row_buffer and self.row_buffer[table_name]:
            rows_to_flush = self.row_buffer[table_name]
            if rows_to_flush:
                column_names = list(rows_to_flush[0].keys())
                fields_str = ", ".join(column_names)
                query_str = f"INSERT INTO {table_name} ({fields_str}) VALUES "
                self.execute(query_str, rows_to_flush)
                self.row_buffer[table_name] = []

    def close(self):
        self.flush()
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
