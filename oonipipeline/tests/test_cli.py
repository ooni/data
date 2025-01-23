import asyncio
from datetime import datetime
from unittest import mock
from pathlib import Path
import time

from oonipipeline.cli.commands import cli
from oonipipeline.cli.utils import build_timestamps

def wait_for_mutations(db, table_name):
    while True:
        res = db.execute(
            f"SELECT * FROM system.mutations WHERE is_done=0 AND table='{table_name}';"
        )
        if len(res) == 0:  # type: ignore
            break
        time.sleep(1)


class MockContext:
    def __init__(self):
        self.default_map = {}


@mock.patch("oonipipeline.cli.commands.make_create_queries")
@mock.patch("oonipipeline.cli.commands.list_all_table_diffs")
@mock.patch("oonipipeline.cli.commands.maybe_create_delete_tables")
def test_full_workflow(
    maybe_create_delete_tables_mock,
    list_all_table_diffs,
    make_create_queries_mock,
    cli_runner,
):
    result = cli_runner.invoke(
        cli,
        [
            "run",
            "--start-at",
            "2022-10-21",
            "--end-at",
            "2022-10-22",
            "--probe-cc",
            "BA",
            "--test-name",
            "web_connectivity",
        ],
    )
    assert result.exit_code == 0

    result = cli_runner.invoke(
        cli,
        ["checkdb", "--print-create", "--create-tables", "--print-diff"],
    )
    assert result.exit_code == 0
    assert maybe_create_delete_tables_mock.called
    assert list_all_table_diffs.called
    assert make_create_queries_mock.called

    maybe_create_delete_tables_mock.reset_mock()
    list_all_table_diffs.reset_mock()
    make_create_queries_mock.reset_mock()
    result = cli_runner.invoke(
        cli,
        ["checkdb", "--print-create"],
    )
    assert result.exit_code == 0
    assert not maybe_create_delete_tables_mock.called
    assert not list_all_table_diffs.called
    assert make_create_queries_mock.called

    result = cli_runner.invoke(
        cli,
        [
            "run",
            "--start-at",
            "2022-10-21T01:00:00",
            "--end-at",
            "2022-10-22T02:00:00",
            "--probe-cc",
            "BA",
            "--test-name",
            "web_connectivity",
        ],
    )
    assert result.exit_code == 0

def test_build_timestamps():
    start = datetime.strptime("2024-01-01 01", "%Y-%m-%d %H")
    end = datetime.strptime("2024-01-05 01", "%Y-%m-%d %H")
    result = build_timestamps(start, end)

    assert result[0][0] == "2024-01-01T01"  # First hour
    assert result[-1][0] == "2024-01-05T00"  # Last hour
    assert "2024-01-02" in list(
        map(lambda x: x[0], result)
    )  # Complete day in the middle

    # Single day
    start = datetime.strptime("2024-01-01 01", "%Y-%m-%d %H")
    end = datetime.strptime("2024-01-01 23", "%Y-%m-%d %H")
    result = build_timestamps(start, end)

    assert all("T" in ts[0] for ts in result)  # All hourly format
    assert len(result) == 22  # Correct number of hours

    # Exactly midnight
    start = datetime.strptime("2024-01-01 00", "%Y-%m-%d %H")
    end = datetime.strptime("2024-01-03 00", "%Y-%m-%d %H")
    result = build_timestamps(start, end)

    assert result[0][0] == "2024-01-01T00"
    assert "2024-01-02" in list(map(lambda x: x[0], result))
    assert result[-1][0] == "2024-01-02"

    start = datetime.strptime("2024-01-01 05", "%Y-%m-%d %H")
    end = datetime.strptime("2024-01-01 06", "%Y-%m-%d %H")
    result = build_timestamps(start, end)

    assert len(result) == 1
    assert result[0][0] == "2024-01-01T05"
