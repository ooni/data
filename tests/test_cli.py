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


def test_mkobs(cli_runner, datadir, fingerprintdb, netinfodb, tmp_path: Path):
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
            "--data-dir",
            datadir,
            "--csv-dir",
            tmp_path.absolute(),
            "--archives-dir",
            tmp_path.absolute(),
        ],
    )
    assert result.exit_code == 0
    assert len(list(tmp_path.glob("*.csv"))) == 2
    assert len(list(tmp_path.glob("*.warc.gz"))) == 1


def test_full_worfklow(cli_runner, datadir, tmp_path: Path):
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
            "--archives-dir",
            tmp_path.absolute(),
        ],
    )
    assert result.exit_code == 0
    assert len(list(tmp_path.glob("*.warc.gz"))) == 1

    result = cli_runner.invoke(
        cli,
        [
            "mkgt",
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
            "--archives-dir",
            tmp_path.absolute(),
        ],
    )
    assert result.exit_code == 0

    result = cli_runner.invoke(
        cli,
        [
            "mkgt",
            "--probe-cc",
            "BA",
            "--start-day",
            "2022-10-20",
            "--end-day",
            "2022-10-21",
            "--data-dir",
            datadir,
        ],
    )
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
