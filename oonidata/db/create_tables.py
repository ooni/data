from datetime import datetime
from enum import Enum

from typing import NamedTuple, Optional, Tuple, List, Any, Type, Mapping, Dict
from dataclasses import fields
from oonidata.db.connections import ClickhouseConnection
from oonidata.models.experiment_result import (
    ExperimentResult,
)
from oonidata.models.analysis import WebsiteAnalysis
from oonidata.models.observations import (
    ObservationBase,
    WebControlObservation,
    WebObservation,
    HTTPMiddleboxObservation,
)


def typing_to_clickhouse(t: Any) -> str:
    if t == str:
        return "String"

    if t in (Optional[str], Optional[bytes]):
        return "Nullable(String)"

    if t == int:
        return "Int32"

    if t == Optional[int]:
        return "Nullable(Int32)"

    if t == bool:
        return "Int8"

    if t == Optional[bool]:
        return "Nullable(Int8)"

    if t == datetime:
        return "Datetime64(3, 'UTC')"

    if t == Optional[datetime]:
        return "Nullable(Datetime64(3, 'UTC'))"

    if t == float:
        return "Float64"

    if t == dict:
        return "String"

    if t == Optional[float]:
        return "Nullable(Float64)"

    if t in (List[str], List[bytes]):
        return "Array(String)"

    if t == Optional[List[str]]:
        return "Nullable(Array(String))"

    if t == Optional[Tuple[str, str]]:
        return "Nullable(Tuple(String, String))"

    if t == Optional[List[Tuple[str, bytes]]]:
        return "Nullable(Array(Array(String)))"

    if t in (Mapping[str, str], Dict[str, str]):
        return "Map(String, String)"

    raise Exception(f"Unhandled type {t}")


def create_query_for_observation(obs_class: Type[ObservationBase]) -> Tuple[str, str]:
    columns = []
    for f in fields(obs_class):
        type_str = typing_to_clickhouse(f.type)
        columns.append(f"     {f.name} {type_str}")

    columns_str = ",\n".join(columns)
    index_str = ",\n".join(obs_class.__table_index__)

    return (
        f"""
    CREATE TABLE IF NOT EXISTS {obs_class.__table_name__} (
{columns_str}
    )
    ENGINE = ReplacingMergeTree
    ORDER BY ({index_str})
    SETTINGS index_granularity = 8192;
    """,
        obs_class.__table_name__,
    )


def create_query_for_experiment_result() -> Tuple[str, str]:
    columns = []
    for f in ExperimentResult._fields:
        t = ExperimentResult.__annotations__.get(f)
        type_str = typing_to_clickhouse(t)
        columns.append(f"     {f} {type_str}")

    columns_str = ",\n".join(columns)
    table_name = ExperimentResult.__table_name__

    return (
        f"""
    CREATE TABLE IF NOT EXISTS {table_name} (
{columns_str}
    )
    ENGINE = ReplacingMergeTree
    ORDER BY (measurement_uid, experiment_result_id)
    SETTINGS index_granularity = 8192;
    """,
        "experiment_result",
    )


def create_query_for_analysis(base_class) -> Tuple[str, str]:
    columns = []
    for f in fields(base_class):
        type_str = typing_to_clickhouse(f.type)
        columns.append(f"     {f.name} {type_str}")

    columns_str = ",\n".join(columns)
    index_str = ",\n".join(base_class.__table_index__)

    return (
        f"""
    CREATE TABLE IF NOT EXISTS {base_class.__table_name__} (
{columns_str}
    )
    ENGINE = ReplacingMergeTree
    ORDER BY ({index_str})
    SETTINGS index_granularity = 8192;
    """,
        base_class.__table_name__,
    )


create_queries = [
    create_query_for_observation(WebObservation),
    create_query_for_observation(WebControlObservation),
    create_query_for_observation(HTTPMiddleboxObservation),
    create_query_for_experiment_result(),
    create_query_for_analysis(WebsiteAnalysis),
]


class TableDoesNotExistError(Exception):
    pass


def get_column_map_from_create_query(s):
    column_begin = False
    columns = {}
    for line in s.split("\n"):
        line = line.strip()
        if line == ")":
            break

        if line == "(":
            column_begin = True
            continue

        if column_begin is False:
            continue

        first_space_idx = line.index(" ")
        column_name = line[:first_space_idx]
        type_name = line[first_space_idx + 1 :]

        column_name = column_name.replace("`", "")
        type_name = type_name.rstrip(",")
        columns[column_name] = type_name
    return columns


class ColumnDiff(NamedTuple):
    table_name: str
    column_name: str
    expected_type: Optional[str]
    actual_type: Optional[str]

    def get_sql_migration(self):
        if self.expected_type == None:
            s = f"-- {self.actual_type} PRESENT\n"
            s += f"ALTER TABLE {self.table_name} DROP COLUMN {self.column_name};"
            return s
        if self.actual_type == None:
            s = f"-- MISSING {self.expected_type}\n"
            s += f"ALTER TABLE {self.table_name} ADD COLUMN {self.column_name} {self.expected_type};"
            return s
        if self.actual_type != self.expected_type:
            s = f"-- {self.actual_type} != {self.expected_type}\n"
            s += f"ALTER TABLE {self.table_name} MODIFY COLUMN {self.column_name} {self.expected_type};"
            return s


def get_table_column_diff(db: ClickhouseConnection, base_class) -> List[ColumnDiff]:
    """
    returns the difference between the current database tables and what we would
    expect to see.
    If the list is empty, it means there is no difference, otherwise you will
    get a list of ColumnDiff which includes the differences in the columns.
    """
    table_name = base_class.__table_name__
    try:
        res = db.execute(f"SHOW CREATE TABLE {table_name}")
    except:
        raise TableDoesNotExistError
    assert isinstance(res, list)
    column_map = get_column_map_from_create_query(res[0][0])
    column_diff = []
    for f in fields(base_class):
        expected_type = typing_to_clickhouse(f.type)
        try:
            actual_type = column_map.pop(f.name)
            if expected_type != actual_type:
                column_diff.append(
                    ColumnDiff(
                        table_name=table_name,
                        column_name=f.name,
                        expected_type=expected_type,
                        actual_type=actual_type,
                    )
                )
        except KeyError:
            column_diff.append(
                ColumnDiff(
                    table_name=table_name,
                    column_name=f.name,
                    expected_type=expected_type,
                    actual_type=None,
                )
            )

    for column_name, actual_type in column_map.items():
        column_diff.append(
            ColumnDiff(
                table_name=table_name,
                column_name=column_name,
                expected_type=None,
                actual_type=actual_type,
            )
        )
    return column_diff


def list_all_table_diffs(db: ClickhouseConnection):
    for base_class in [WebObservation, WebControlObservation, HTTPMiddleboxObservation]:
        table_name = base_class.__table_name__
        try:
            diff = get_table_column_diff(db=db, base_class=base_class)
        except TableDoesNotExistError:
            print(f"# {table_name} does not exist")
            print("rerun with --create-tables")
            continue
        if len(diff) > 0:
            print(f"# {table_name} diff")
            for cd in diff:
                print(cd.get_sql_migration())


def main():
    for query, table_name in create_queries:
        print(f"clickhouse-client -q 'DROP TABLE {table_name}';")
        print("cat <<EOF | clickhouse-client -nm")
        print(query)
        print("EOF")


if __name__ == "__main__":
    main()
