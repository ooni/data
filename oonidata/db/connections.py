import csv

from collections import namedtuple
from datetime import datetime
from pprint import pformat
import logging

log = logging.getLogger("oonidata.processing")


class DatabaseConnection:
    def __init__(self):
        self.client = None

    def execute(self, *args, **kwargs):
        pass

    def write_rows(self, table_name, rows, fields=None):
        log.info(f"Writing to {table_name}")
        log.info(pformat(rows))

    def close(self):
        pass


class ClickhouseConnection(DatabaseConnection):
    def __init__(self, conn_url):
        from clickhouse_driver import Client

        self.client = Client.from_url(conn_url)
        self._row_buffer = []

    def execute(self, *args, **kwargs):
        # log.debug(f"execute {args} {kwargs}")
        return self.client.execute(*args, **kwargs)

    def write_rows(self, table_name, rows, fields=None):
        if not fields:
            fields = rows[0].keys()

        fields_str = ", ".join(fields)
        query_str = f"INSERT INTO {table_name} ({fields_str}) VALUES"
        try:
            self.client.execute(query_str, rows)
        except Exception as exc:
            log.error(f"Failed to write rows")
            log.error(pformat(rows))
            raise exc


CSVConnectionHandle = namedtuple("CSVConnectionHandle", ["fh", "writer"])


class CSVConnection(DatabaseConnection):
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.open_writers = {}

    def write_rows(self, table_name, rows, fields=None):
        if not fields:
            fields = rows[0].keys()

        if table_name not in self.open_writers:
            ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
            fh = (self.output_dir / f"{table_name}-{ts}.csv").open("w")
            csv_writer = csv.DictWriter(fh, fieldnames=fields)
            csv_writer.writeheader()
            self.open_writers[table_name] = CSVConnectionHandle(
                writer=csv_writer, fh=fh
            )
        self.open_writers[table_name].writer.writerows(rows)

    def close(self):
        for handle in self.open_writers.values():
            handle.fh.close()
