import csv

from collections import namedtuple
from datetime import datetime
from pprint import pformat
import logging

log = logging.getLogger("oonidata.processing")


class DatabaseConnection:
    def __init__(self):
        self.client = None

    def write_row(self, table_name, row):
        log.info(f"Writing to {table_name}")
        log.info(pformat(row))

    def write_rows(self, table_name, rows):
        log.info(f"Writing to {table_name}")
        log.info(pformat(rows))

    def close(self):
        pass


class ClickhouseConnection(DatabaseConnection):
    def __init__(self, conn_url):
        from clickhouse_driver import Client

        self.client = Client.from_url(conn_url)

    def execute(self, *args, **kwargs):
        # log.debug(f"execute {args} {kwargs}")
        return self.client.execute(*args, **kwargs)

    def write_rows(self, table_name, rows):
        # TODO remove this function
        fields = ", ".join(rows[0].keys())
        query_str = f"INSERT INTO {table_name} ({fields}) VALUES"
        try:
            self.client.execute(query_str, rows)
        except Exception as exc:
            log.error(f"Failed to write rows")
            log.error(pformat(rows))
            raise exc

    def write_row(self, table_name, row):
        fields = ", ".join(row.keys())
        query_str = f"INSERT INTO {table_name} ({fields}) VALUES"
        try:
            self.client.execute(query_str, [row])
        except Exception as exc:
            log.error(f"Failed to write row")
            log.error(pformat(row))
            raise exc


CSVConnectionHandle = namedtuple("CSVConnectionHandle", ["fh", "writer"])


class CSVConnection(DatabaseConnection):
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.open_writers = {}

    def write_row(self, table_name, row):
        if table_name not in self.open_writers:
            ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
            fh = (self.output_dir / f"{table_name}-{ts}.csv").open("w")
            csv_writer = csv.DictWriter(fh, fieldnames=list(row.keys()))
            csv_writer.writeheader()
            self.open_writers[table_name] = CSVConnectionHandle(
                writer=csv_writer, fh=fh
            )

        self.open_writers[table_name].writer.writerow(row)

    def close(self):
        for handle in self.open_writers.values():
            handle.fh.close()
