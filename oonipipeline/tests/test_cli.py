import asyncio
from unittest import mock
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
            "--workflow-name",
            "observations",
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
