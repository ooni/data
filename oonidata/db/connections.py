import csv
from pprint import pformat
import logging

log = logging.getLogger("oonidata.processing")


class DatabaseConnection:
    def __init__(self):
        self.client = None

    def write_row(self, table_name, row):
        log.info(f"Writing to {table_name}")
        log.info(pformat(row))


class ClickhouseConnection(DatabaseConnection):
    def __init__(self, conn_url):
        from clickhouse_driver import Client

        self.client = Client.from_url(conn_url)

    def execute(self, *args, **kwargs):
        # log.debug(f"execute {args} {kwargs}")
        return self.client.execute(*args, **kwargs)

    def write_row(self, table_name, row):
        fields = ", ".join(row.keys())
        query_str = f"INSERT INTO {table_name} ({fields}) VALUES"
        try:
            self.client.execute(query_str, [row])
        except Exception as exc:
            log.error(f"Failed to write row")
            log.error(pformat(row))
            raise exc


class CSVConnection(DatabaseConnection):
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.open_writers = {}

    def write_row(self, table_name, row):
        if table_name not in self.open_writers:
            out_path = (self.output_dir / f"{table_name}.csv").open("w")
            csv_writer = csv.DictWriter(out_path, fieldnames=list(row.keys()))
            csv_writer.writeheader()
            self.open_writers[table_name] = csv_writer

        self.open_writers[table_name].writerow(row)
