from oonipipeline.tasks.observations import (
    MakeObservationsParams,
    make_observations,
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
