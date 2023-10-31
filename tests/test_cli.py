from pathlib import Path

import pytest
from oonidata.cli import cli
from oonidata.db.connections import ClickhouseConnection


def test_sync(cli_runner, tmp_path: Path):
    result = cli_runner.invoke(
        cli,
        [
            "sync",
            "--probe-cc",
            "IT",
            "--start-day",
            "2022-01-01",
            "--end-day",
            "2022-01-02",
            "--test-name",
            "whatsapp,telegram",
            "--output-dir",
            tmp_path.absolute(),
        ],
    )
    assert result.exit_code == 0
    assert len(list(tmp_path.iterdir())) == 2
    assert len(list((tmp_path / "telegram").iterdir())) == 1
    assert len(list((tmp_path / "telegram" / "2022-01-01").iterdir())) == 24


def test_full_workflow(cli_runner, fingerprintdb, netinfodb, datadir, tmp_path: Path):
    db = ClickhouseConnection(conn_url="clickhouse://localhost")
    try:
        db.execute("SELECT 1")
    except:
        pytest.skip("no database connection")

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
            "clickhouse://localhost/",
            # "--archives-dir",
            # tmp_path.absolute(),
        ],
    )
    assert result.exit_code == 0
    # assert len(list(tmp_path.glob("*.warc.gz"))) == 1
    res = db.execute(
        "SELECT COUNT(DISTINCT(measurement_uid)) FROM obs_web WHERE bucket_date = '2022-10-20' AND probe_cc = 'BA'"
    )
    assert res[0][0] == 200  # type: ignore
    res = db.execute(
        "SELECT COUNT() FROM obs_web WHERE bucket_date = '2022-10-20' AND probe_cc = 'BA'"
    )
    obs_count = res[0][0]  # type: ignore

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
            "clickhouse://localhost/",
        ],
    )
    assert result.exit_code == 0
    res = db.execute(
        "SELECT COUNT() FROM obs_web WHERE bucket_date = '2022-10-20' AND probe_cc = 'BA'"
    )
    # By re-running it against the same date, we should still get the same observation count
    assert res[0][0] == obs_count  # type: ignore

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
            "clickhouse://localhost/",
        ],
    )
    assert result.exit_code == 0

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
            "mker",
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
            "clickhouse://localhost/",
        ],
    )
    assert result.exit_code == 0
    res = db.execute(
        "SELECT COUNT(DISTINCT(measurement_uid)) FROM experiment_result WHERE measurement_uid LIKE '20221020%' AND probe_cc = 'BA'"
    )
    assert res[0][0] == 200  # type: ignore
