from dataclasses import dataclass
from oonipipeline.db.connections import ClickhouseConnection
from oonipipeline.db.create_tables import create_queries

from temporalio import activity


@dataclass
class ClickhouseParams:
    clickhouse_url: str


@activity.defn
def optimize_all_tables(params: ClickhouseParams):
    with ClickhouseConnection(params.clickhouse_url) as db:
        for _, table_name in create_queries:
            db.execute(f"OPTIMIZE TABLE {table_name}")
