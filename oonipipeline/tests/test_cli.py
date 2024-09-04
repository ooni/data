import asyncio
from multiprocessing import Process
from pathlib import Path
import time
import textwrap

from oonipipeline.cli.commands import cli
from oonipipeline.cli.commands import parse_config_file
from oonipipeline.temporal.client_operations import TemporalConfig, get_status
import pytest


def wait_for_mutations(db, table_name):
    while True:
        res = db.execute(
            f"SELECT * FROM system.mutations WHERE is_done=0 AND table='{table_name}';"
        )
        if len(res) == 0:  # type: ignore
            break
        time.sleep(1)


def wait_for_backfill():
    temporal_config = TemporalConfig(temporal_address="localhost:7233")
    loop = asyncio.new_event_loop()
    time.sleep(1)

    while True:
        res = loop.run_until_complete(get_status(temporal_config))
        if len(res[0]) == 0 and len(res[1]) == 0:
            break
        time.sleep(3)
    loop.close()


class MockContext:
    def __init__(self):
        self.default_map = {}


def test_parse_config(tmp_path):
    ctx = MockContext()

    config_content = """[options]
    something = other
    [options.subcommand]
    otherthing = bar
    [options.subcommand2]
    spam = ham
    """
    config_path = tmp_path / "config.ini"
    with config_path.open("w") as out_file:
        out_file.write(textwrap.dedent(config_content))
    defaults = parse_config_file(ctx, str(config_path))
    assert defaults["something"] == "other"
    assert defaults["subcommand"]["otherthing"] == "bar"
    assert defaults["subcommand2"]["spam"] == "ham"
    assert defaults["schedule"]["something"] == "other"
    assert defaults["backfill"]["something"] == "other"


@pytest.mark.skip("TODO(art): moved into temporal_e2e")
def test_full_workflow(
    db,
    cli_runner,
    fingerprintdb,
    netinfodb,
    datadir,
    tmp_path: Path,
    temporal_dev_server,
    temporal_workers,
):
    print(f"running schedule observations")
    result = cli_runner.invoke(
        cli,
        [
            "schedule",
            "--probe-cc",
            "BA",
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
    result = cli_runner.invoke(
        cli,
        [
            "backfill",
            "--start-at",
            "2022-10-21",
            "--end-at",
            "2022-10-22",
            "--clickhouse",
            db.clickhouse_url,
            "--clickhouse-buffer-min-time",
            1,
            "--clickhouse-buffer-max-time",
            2,
            "--schedule-id",
            "oonipipeline-observations-schedule-ba-web_connectivity",
            # "--archives-dir",
            # tmp_path.absolute(),
        ],
    )
    assert result.exit_code == 0

    wait_for_backfill()
    # We wait on the table buffers to be flushed
    db.execute("OPTIMIZE TABLE buffer_obs_web")
    # assert len(list(tmp_path.glob("*.warc.gz"))) == 1
    res = db.execute(
        "SELECT bucket_date, COUNT(DISTINCT(measurement_uid)) FROM obs_web WHERE probe_cc = 'BA' GROUP BY bucket_date"
    )
    bucket_dict = dict(res)
    assert "2022-10-20" in bucket_dict, bucket_dict
    assert bucket_dict["2022-10-20"] == 200, bucket_dict
    obs_count = bucket_dict["2022-10-20"]

    print("running backfill")
    result = cli_runner.invoke(
        cli,
        [
            "backfill",
            "--start-at",
            "2022-10-21",
            "--end-at",
            "2022-10-22",
            "--clickhouse",
            db.clickhouse_url,
            "--clickhouse-buffer-min-time",
            1,
            "--clickhouse-buffer-max-time",
            2,
            "--schedule-id",
            "oonipipeline-observations-schedule-ba-web_connectivity",
            # "--archives-dir",
            # tmp_path.absolute(),
        ],
    )
    assert result.exit_code == 0

    wait_for_backfill()
    # We wait on the table buffers to be flushed
    db.execute("OPTIMIZE TABLE buffer_obs_web")

    # Wait for the mutation to finish running
    wait_for_mutations(db, "obs_web")
    res = db.execute(
        "SELECT bucket_date, COUNT(DISTINCT(measurement_uid)) FROM obs_web WHERE probe_cc = 'BA' GROUP BY bucket_date"
    )
    bucket_dict = dict(res)
    assert "2022-10-20" in bucket_dict, bucket_dict
    # By re-running it against the same date, we should still get the same observation count
    assert bucket_dict["2022-10-20"] == obs_count, bucket_dict

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

    # print("running mkanalysis")
    # result = cli_runner.invoke(
    #     cli,
    #     [
    #         "mkanalysis",
    #         "--probe-cc",
    #         "BA",
    #         "--start-day",
    #         "2022-10-20",
    #         "--end-day",
    #         "2022-10-21",
    #         "--test-name",
    #         "web_connectivity",
    #         "--data-dir",
    #         datadir,
    #         "--clickhouse",
    #         db.clickhouse_url,
    #         "--clickhouse-buffer-min-time",
    #         1,
    #         "--clickhouse-buffer-max-time",
    #         2,
    #         "--parallelism",
    #         1,
    #     ],
    # )
    # assert result.exit_code == 0
    # time.sleep(3)
    # res = db.execute(
    #     "SELECT COUNT(DISTINCT(measurement_uid)) FROM measurement_experiment_result WHERE measurement_uid LIKE '20221020%' AND location_network_cc = 'BA'"
    # )
    # assert res[0][0] == 200  # type: ignore
    # print("finished ALL")
    # # We wait on the table buffers to be flushed

    print("running schedule analysis")
    result = cli_runner.invoke(
        cli,
        [
            "schedule",
            "--probe-cc",
            "BA",
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
            "--no-observations",
            "--analysis",
            # "--archives-dir",
            # tmp_path.absolute(),
        ],
    )
    assert result.exit_code == 0
    result = cli_runner.invoke(
        cli,
        [
            "backfill",
            "--start-at",
            "2022-10-21",
            "--end-at",
            "2022-10-22",
            "--clickhouse",
            db.clickhouse_url,
            "--clickhouse-buffer-min-time",
            1,
            "--clickhouse-buffer-max-time",
            2,
            "--schedule-id",
            "oonipipeline-analysis-schedule-ba-web_connectivity",
            # "--archives-dir",
            # tmp_path.absolute(),
        ],
    )
    assert result.exit_code == 0

    # We wait on the table buffers to be flushed
    wait_for_backfill()
    # assert len(list(tmp_path.glob("*.warc.gz"))) == 1
    db.execute("OPTIMIZE TABLE measurement_experiment_result")
    db.execute("OPTIMIZE TABLE buffer_measurement_experiment_result")
    wait_for_mutations(db, "measurement_experiment_result")

    # TODO(art): find a better way than sleeping to get the tables to be flushed
    time.sleep(10)
    res = db.execute(
        "SELECT COUNT(DISTINCT(measurement_uid)) FROM measurement_experiment_result WHERE measurement_uid LIKE '20221020%' AND location_network_cc = 'BA'"
    )
    assert res[0][0] == 200  # type: ignore
    print("finished ALL")
