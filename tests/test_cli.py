from pathlib import Path
from oonidata.cli import cli


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
            "dnscheck",
            "--data-dir",
            datadir,
            "--csv-dir",
            tmp_path.absolute(),
        ],
    )
    assert result.exit_code == 0
    assert len(list(tmp_path.iterdir())) == 1
