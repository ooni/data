import csv
from pprint import pprint
from typing import Optional, Union, Tuple, List, Any


class DatabaseConnection:
    def __init__(self):
        self.client = None

    def execute(
        self, query: str, params: Optional[dict]
    ) -> Union[List[Tuple], int, None]:
        print(query)
        print(params)
        return

    def write_row(self, table_name, row):
        print(f"Writing to {table_name}")
        pprint(row)


class ClickhouseConnection(DatabaseConnection):
    def __init__(self, conn_url):
        from clickhouse_driver import Client

        self.client = Client.from_url(conn_url)

    def write_row(self, table_name, row):
        fields = ", ".join(row.keys())
        query_str = f"INSERT INTO {table_name} ({fields}) VALUES"
        try:
            self.client.execute(query_str, [row])
        except Exception as exc:
            print(f"Failed to write row {row}")
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
