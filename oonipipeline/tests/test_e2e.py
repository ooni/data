from datetime import datetime, timezone
from oonipipeline.tasks.observations import (
    MakeObservationsParams,
    make_observations,
)
from oonipipeline.tasks.analysis import (
    MakeAnalysisParams,
    make_analysis,
)
from oonipipeline.tasks.detector import (
    MakeDetectorParams,
    make_detector,
)
from oonipipeline.tasks.volume import (
    MakeVolumeParams,
    make_volume_analysis,
)
from oonipipeline.tasks.time_inconsistencies import (
    MakeTimeInconsistenciesParams,
    make_time_inconsistencies_analysis,
)
from oonipipeline.cli.utils import build_timestamps
from oonipipeline.tasks.updaters.citizenlab_test_lists_updater import (
    update_citizenlab_test_lists,
)

from .utils import wait_for_mutations


def test_observation_workflow(datadir, db):
    bucket_date = "2022-10-21"
    obs_params = MakeObservationsParams(
        probe_cc=["BA"],
        test_name=["web_connectivity"],
        fast_fail=False,
        bucket_date=bucket_date,
        clickhouse=db.clickhouse_url,
        data_dir=datadir,
    )
    wf_res = make_observations(obs_params)

    assert wf_res["measurement_count"] == 613
    assert wf_res["total_size"] == 11381440

    res = db.execute(
        """
        SELECT bucket_date,
        COUNT(DISTINCT(measurement_uid))
        FROM obs_web WHERE probe_cc = 'BA'
        GROUP BY bucket_date
        """
    )
    bucket_dict = dict(res)
    assert bucket_dict[bucket_date] == wf_res["measurement_count"]
    res = db.execute(
        """
        SELECT bucket_date,
        COUNT()
        FROM obs_web WHERE probe_cc = 'BA'
        GROUP BY bucket_date
        """
    )
    bucket_dict = dict(res)
    obs_count = bucket_dict[bucket_date]
    assert obs_count == 2548

    wf_res = make_observations(obs_params)
    db.execute("OPTIMIZE TABLE obs_web")
    wait_for_mutations(db, "obs_web")
    res = db.execute(
        """
        SELECT bucket_date,
        COUNT()
        FROM obs_web WHERE probe_cc = 'BA'
        GROUP BY bucket_date
        """
    )
    bucket_dict = dict(res)
    obs_count_2 = bucket_dict[bucket_date]

    assert obs_count == obs_count_2


def test_observation_workflow_hourly(datadir, db):
    bucket_date = "2022-10-21T01"
    obs_params = MakeObservationsParams(
        probe_cc=["IT"],
        test_name=["web_connectivity"],
        fast_fail=False,
        bucket_date=bucket_date,
        clickhouse=db.clickhouse_url,
        data_dir=datadir,
    )
    wf_res = make_observations(obs_params)

    assert wf_res["measurement_count"] == 1814
    assert wf_res["total_size"] == 33597397


def test_event_detector(datadir, db):
    update_citizenlab_test_lists(db.clickhouse_url)
    for timestamp, _ in build_timestamps(
        datetime(2025, 6, 23, 0, 0, 0, tzinfo=timezone.utc),
        datetime(2025, 6, 30, 0, 0, 0, tzinfo=timezone.utc),
    ):
        bucket_date = timestamp
        obs_params = MakeObservationsParams(
            probe_cc=["TG"],
            test_name=["web_connectivity"],
            fast_fail=False,
            bucket_date=bucket_date,
            clickhouse=db.clickhouse_url,
            data_dir=datadir,
        )
        wf_res = make_observations(obs_params)
        make_analysis(
            MakeAnalysisParams(
                probe_cc=["TG"],
                test_name=["web_connectivity"],
                timestamp=timestamp,
                clickhouse_url=db.clickhouse_url,
            )
        )
        make_detector(
            MakeDetectorParams(
                clickhouse_url=db.clickhouse_url, probe_cc=["TG"], timestamp=timestamp
            )
        )
    res = db.execute("SELECT COUNT() FROM event_detector_changepoints")
    print(res)


def test_volume_analysis(db, fastpath_data_fake, clean_faulty_measurements):
    """
    Make sure you can run the volume analysis with the right parameters
    """
    make_volume_analysis(
        MakeVolumeParams(
            clickhouse_url=db.clickhouse_url,
            timestamp=datetime(2024, 1, 1, 0, 0, 0).strftime("%Y-%m-%dT%H"),
            threshold=5
        )
    )
    res = db.execute("SELECT COUNT() FROM faulty_measurements WHERE type = 'volume'")
    assert res == [(1,)], "There should be exactly one event"


def test_time_inconsistencies_analysis(db, fastpath_data_time_inconsistencies, clean_faulty_measurements):
    """
    Make sure you can run the time inconsistencies analysis with the right parameters
    """
    make_time_inconsistencies_analysis(
        MakeTimeInconsistenciesParams(
            clickhouse_url=db.clickhouse_url,
            timestamp=datetime(2023, 12, 31, 23, 0, 0).strftime("%Y-%m-%dT%H"),
            future_threshold=3600,
            past_threshold=3600
        )
    )
    res = db.execute("SELECT COUNT() FROM faulty_measurements WHERE type IN ('time_inconsistency_future', 'time_inconsistency_past')")
    assert res[0][0] > 0, "There should be at least one time inconsistency event"
