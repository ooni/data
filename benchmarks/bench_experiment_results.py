from datetime import date
from oonidata.db.connections import ClickhouseConnection
from oonidata.experiments.control import BodyDB
from oonidata.processing import run_experiment_results


def test_experiment_results(fingerprintdb, netinfodb):
    db_writer = ClickhouseConnection("clickhouse://localhost", row_buffer_size=10_000)

    body_db = BodyDB(db=ClickhouseConnection("clickhouse://localhost"))
    for day in [
        date(2022, 11, 10),
        date(2022, 11, 11),
        date(2022, 11, 12),
        date(2022, 11, 13),
    ]:
        for er in run_experiment_results(
            day=day,
            db_writer=db_writer,
            body_db=body_db,
            clickhouse="clickhouse://localhost",
            fingerprintdb=fingerprintdb,
            netinfodb=netinfodb,
        ):
            pass
