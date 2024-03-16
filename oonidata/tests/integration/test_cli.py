from pathlib import Path
import time

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


def wait_for_mutations(db, table_name):
    while True:
        res = db.execute(
            f"SELECT * FROM system.mutations WHERE is_done=0 AND table='{table_name}';"
        )
        if len(res) == 0:  # type: ignore
            break
        time.sleep(1)
