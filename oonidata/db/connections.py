import csv
import pickle
import time

from collections import defaultdict, namedtuple
from datetime import datetime
from pprint import pformat
import logging

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
    def __init__(self, conn_url, row_buffer_size=0, max_block_size=1_000_000):
        from clickhouse_driver import Client

        self.client = Client.from_url(conn_url)

        self.row_buffer_size = row_buffer_size
        self.max_block_size = max_block_size

        self._column_names = {}
        self._row_buffer = defaultdict(list)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def delete_sync(self, table_name: str, where: str):
        self.execute("SET allow_experimental_lightweight_delete = true;")
        self.execute("SET mutations_sync = 1;")
        return self.execute(f"DELETE FROM {table_name} WHERE {where};")

    def execute(self, *args, **kwargs):
        return self.client.execute(*args, **kwargs)

    def execute_iter(self, *args, **kwargs):
        return self.client.execute_iter(
            *args, **kwargs, settings={"max_block_size": self.max_block_size}
        )

    def write_rows(self, table_name, rows, column_names):
        if table_name in self._column_names:
            assert self._column_names[table_name] == column_names
        else:
            self._column_names[table_name] = column_names

        if self.row_buffer_size:
            self._row_buffer[table_name] += rows
            if len(self._row_buffer[table_name]) >= self.row_buffer_size:
                self.flush_rows(table_name, self._row_buffer[table_name])
                self._row_buffer[table_name] = []
        else:
            self.flush_rows(table_name=table_name, rows=rows)

    def flush_rows(self, table_name, rows):
        fields_str = ", ".join(self._column_names[table_name])
        query_str = f"INSERT INTO {table_name} ({fields_str}) VALUES"
        try:
            self.execute(query_str, rows)
        except:
            log.error(
                f"Failed to write {len(rows)} rows. Trying to savage what is savageable"
            )
            for row in rows:
                try:
                    self.execute(query_str, [row])
                except:
                    log.error(f"Failed to write {row}")
                    with open(f"failing-rows.pickle", "ab") as out_file:
                        pickle.dump({"query_str": query_str, "rows": rows}, out_file)

    def close(self):
        for table_name, rows in self._row_buffer.items():
            self.flush_rows(table_name=table_name, rows=rows)
            self._row_buffer[table_name] = []
        self.client.disconnect()


CSVConnectionHandle = namedtuple("CSVConnectionHandle", ["fh", "writer"])


class CSVConnection(DatabaseConnection):
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.open_writers = {}

    def write_rows(self, table_name, rows, column_names):
        if table_name not in self.open_writers:
            ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
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
