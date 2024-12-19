import asyncio
from unittest import mock
from pathlib import Path
import time

from oonipipeline.cli.commands import cli
from oonipipeline.tasks.client_operations import TemporalConfig, get_status


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


@mock.patch("oonipipeline.cli.commands.make_create_queries")
@mock.patch("oonipipeline.cli.commands.list_all_table_diffs")
@mock.patch("oonipipeline.cli.commands.maybe_create_delete_tables")
@mock.patch("oonipipeline.cli.commands.clear_all_schedules")
@mock.patch("oonipipeline.cli.commands.schedule_backfill")
@mock.patch("oonipipeline.cli.commands.schedule_all")
@mock.patch("oonipipeline.cli.commands.temporal_connect")
def test_full_workflow(
    temporal_connect_mock,
    schedule_all_mock,
    schedule_backfill_mock,
    clear_all_schedules_mock,
    maybe_create_delete_tables_mock,
    list_all_table_diffs,
    make_create_queries_mock,
    cli_runner,
):
    result = cli_runner.invoke(
        cli,
        [
            "schedule",
            "--probe-cc",
            "BA",
            "--test-name",
            "web_connectivity",
        ],
    )
    assert result.exit_code == 0
    assert temporal_connect_mock.called
    assert schedule_all_mock.called
    temporal_connect_mock.reset_mock()
    result = cli_runner.invoke(
        cli,
        [
            "backfill",
            "--start-at",
            "2022-10-21",
            "--end-at",
            "2022-10-22",
            "--workflow-name",
            "observations",
        ],
    )
    assert result.exit_code == 0
    assert temporal_connect_mock.called
    assert schedule_backfill_mock.called

    temporal_connect_mock.reset_mock()
    result = cli_runner.invoke(
        cli,
        [
            "clear-schedules",
        ],
    )
    assert result.exit_code == 0
    assert temporal_connect_mock.called
    assert clear_all_schedules_mock.called

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
