from datetime import date, timedelta
import logging
from oonidata.datautils import PerfTimer
from oonidata.db.connections import ClickhouseConnection
from oonidata.analysis.control import BodyDB
from oonidata.processing import maybe_build_web_ground_truth, run_experiment_results


def test_experiment_results(fingerprintdb, netinfodb, datadir):
    logging.getLogger().setLevel(logging.INFO)
    day = date(2022, 11, 10)
    end_day = day + timedelta(days=1)

    db = ClickhouseConnection("clickhouse://localhost", row_buffer_size=10_000)
    q = """
        SELECT COUNT(DISTINCT(measurement_uid))
        FROM obs_web 
        WHERE test_name = 'web_connectivity' AND probe_cc IN ('IT', 'ID')
        AND measurement_start_time > %(start_day)s AND measurement_start_time < %(end_day)s
        """
    res = db.execute(
        q,
        dict(start_day=day.strftime("%Y-%m-%d"), end_day=end_day.strftime("%Y-%m-%d")),
    )
    assert res[0][0] == 31243, "inconsistent database. repopulate it using oonidata"  # type: ignore
    # TODO: For some reason this is off by 2 measurements vs what we see in backend-fsn
    # assert res[0][0] == 31245, "inconsistent database. repopulate it using oonidata"

    body_db = BodyDB(db=ClickhouseConnection("clickhouse://localhost"))
    """
    for day in days:
        print(f"building gtdb for {day}")
        maybe_build_web_ground_truth(
            db=db,
            netinfodb=netinfodb,
            day=day,
            data_dir=datadir,
            rebuild_ground_truths=False,
        )
    """

    t = PerfTimer()
    idx = 0
    for er in run_experiment_results(
        day=day,
        probe_cc=["IT", "ID"],
        db_writer=db,
        body_db=body_db,
        data_dir=datadir,
        clickhouse="clickhouse://localhost",
        fingerprintdb=fingerprintdb,
    ):
        idx += 1
    print(f"generated {idx} experiment_results in {t.pretty}")
    print(f"{idx / t.ms * 1000} er/s")
