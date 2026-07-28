from dataclasses import dataclass
from datetime import datetime, timedelta

from ..analysis.ctrl_rollup import write_ctrl_rollup
from ..db.connections import ClickhouseConnection


@dataclass
class MakeCtrlRollupParams:
    clickhouse_url: str
    timestamp: str


def make_ctrl_rollup(params: MakeCtrlRollupParams):
    if "T" in params.timestamp:
        start_hour = datetime.strptime(params.timestamp, "%Y-%m-%dT%H")
        end_hour = start_hour + timedelta(hours=1)
    else:
        start_hour = datetime.strptime(params.timestamp, "%Y-%m-%d")
        end_hour = start_hour + timedelta(days=1)

    db = ClickhouseConnection(params.clickhouse_url)
    write_ctrl_rollup(db=db, start_time=start_hour, end_time=end_hour)
