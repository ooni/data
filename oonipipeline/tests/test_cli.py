import asyncio
from multiprocessing import Process
from pathlib import Path
import time

from oonipipeline.cli.commands import cli


def wait_for_mutations(db, table_name):
    while True:
        res = db.execute(
            f"SELECT * FROM system.mutations WHERE is_done=0 AND table='{table_name}';"
        )
        if len(res) == 0:  # type: ignore
            break
        time.sleep(1)


def test_full_workflow(
    db,
    cli_runner,
    fingerprintdb,
    netinfodb,
    datadir,
    tmp_path: Path,
    temporal_dev_server,
):
    result = cli_runner.invoke(
        cli,
        [
            "mkobs",
            "--probe-cc",
            "BA",
            "--start-day",
            "2022-10-20",
            "--end-day",
            "2022-10-21",
            "--test-name",
            "web_connectivity",
            "--create-tables",
            "--data-dir",
            datadir,
            "--clickhouse",
            db.clickhouse_url,
            "--clickhouse-buffer-min-time",
            1,
            "--clickhouse-buffer-max-time",
            2,
            # "--archives-dir",
            # tmp_path.absolute(),
        ],
    )
    assert result.exit_code == 0
    # We wait on the table buffers to be flushed
    time.sleep(3)
    # assert len(list(tmp_path.glob("*.warc.gz"))) == 1
    res = db.execute(
        "SELECT bucket_date, COUNT(DISTINCT(measurement_uid)) FROM obs_web WHERE probe_cc = 'BA' GROUP BY bucket_date"
    )
    bucket_dict = dict(res)
    assert "2022-10-20" in bucket_dict, bucket_dict
    assert bucket_dict["2022-10-20"] == 200, bucket_dict
    obs_count = bucket_dict["2022-10-20"]

    result = cli_runner.invoke(
        cli,
        [
            "mkobs",
            "--probe-cc",
            "BA",
            "--start-day",
            "2022-10-20",
            "--end-day",
            "2022-10-21",
            "--test-name",
            "web_connectivity",
            "--create-tables",
            "--data-dir",
            datadir,
            "--clickhouse",
            db.clickhouse_url,
            "--clickhouse-buffer-min-time",
            1,
            "--clickhouse-buffer-max-time",
            2,
        ],
    )
    assert result.exit_code == 0
    # We wait on the table buffers to be flushed
    time.sleep(3)

    # Wait for the mutation to finish running
    wait_for_mutations(db, "obs_web")
    res = db.execute(
        "SELECT bucket_date, COUNT(DISTINCT(measurement_uid)) FROM obs_web WHERE probe_cc = 'BA' GROUP BY bucket_date"
    )
    bucket_dict = dict(res)
    assert "2022-10-20" in bucket_dict, bucket_dict
    # By re-running it against the same date, we should still get the same observation count
    assert bucket_dict["2022-10-20"] == obs_count, bucket_dict

    result = cli_runner.invoke(
        cli,
        [
            "mkgt",
            "--start-day",
            "2022-10-20",
            "--end-day",
            "2022-10-21",
            "--data-dir",
            datadir,
            "--clickhouse",
            db.clickhouse_url,
            "--clickhouse-buffer-min-time",
            1,
            "--clickhouse-buffer-max-time",
            2,
        ],
    )
    assert result.exit_code == 0
    # We wait on the table buffers to be flushed
    time.sleep(3)

    # result = cli_runner.invoke(
    #    cli,
    #    [
    #        "fphunt",
    #        "--data-dir",
    #        datadir,
    #        "--archives-dir",
    #        tmp_path.absolute(),
    #    ],
    # )
    # assert result.exit_code == 0

    result = cli_runner.invoke(
        cli,
        [
            "mkanalysis",
            "--probe-cc",
            "BA",
            "--start-day",
            "2022-10-20",
            "--end-day",
            "2022-10-21",
            "--test-name",
            "web_connectivity",
            "--data-dir",
            datadir,
            "--clickhouse",
            db.clickhouse_url,
            "--clickhouse-buffer-min-time",
            1,
            "--clickhouse-buffer-max-time",
            2,
        ],
    )
    assert result.exit_code == 0
    res = db.execute(
        "SELECT COUNT(DISTINCT(measurement_uid)) FROM measurement_experiment_result WHERE measurement_uid LIKE '20221020%' AND location_network_cc = 'BA'"
    )
    assert res[0][0] == 200  # type: ignore
    # We wait on the table buffers to be flushed
    time.sleep(3)
