from datetime import datetime

from types import NoneType
from typing import (
    Generator,
    NamedTuple,
    Optional,
    Tuple,
    List,
    Any,
    Type,
    Mapping,
    Dict,
    Union,
)
from dataclasses import Field, fields
import typing

from oonidata.models.base import TableModelProtocol, ProcessingMeta
from oonidata.models.experiment_result import (
    ExperimentResult,
    MeasurementExperimentResult,
)
from oonidata.models.analysis import WebAnalysis
from oonidata.models.observations import (
    MeasurementMeta,
    ProbeMeta,
    WebControlObservation,
    WebObservation,
    HTTPMiddleboxObservation,
)

from .connections import ClickhouseConnection


MAPPED_BASIC_TYPES = {
    str: "String",
    int: "Int32",
    bool: "Bool",
    float: "Float32",
    dict: "String",
    List[str]: "Array(String)",
    List[float]: "Array(Float32)",
    # Cast JSON to dict
    List[Dict]: "String",
    List[List[str]]: "Array(Array(String))",
    datetime: "Datetime('UTC')",
}


def annotated_clickhouse_type(t):
    """
    these are typed annotated with Annotated[python_type, "CLICKHOUSE_TYPE_STR"]
    """
    return typing.get_args(t)[1]


def typing_to_clickhouse(t: Any) -> str:
    t_origin = typing.get_origin(t)
    if t_origin == typing.Annotated:
        return annotated_clickhouse_type(t)
    elif t_origin == typing.Union:
        args = typing.get_args(t)
        if len(args) == 2 and args[1] == NoneType:
            assert args[0] in MAPPED_BASIC_TYPES, f"{args[0]} not in basic types"
            mapped_basic_type = MAPPED_BASIC_TYPES[args[0]]
            return f"Nullable({mapped_basic_type})"

    if t in MAPPED_BASIC_TYPES:
        return MAPPED_BASIC_TYPES[t]

    raise Exception(f"could not map {t} to anything {t_origin}")


def iter_table_fields(
    field_tuple: Tuple[Field[Any], ...]
) -> Generator[Tuple[Field, str], None, None]:
    for f in field_tuple:
        if f.name in ("__table_index__", "__table_name__"):
            continue
        if f.name == "probe_meta":
            for f in fields(ProbeMeta):
                type_str = typing_to_clickhouse(f.type)
                yield f, type_str
            continue
        if f.name == "measurement_meta":
            for f in fields(MeasurementMeta):
                type_str = typing_to_clickhouse(f.type)
                yield f, type_str
            continue
        if f.type == ProcessingMeta:
            for f in fields(ProcessingMeta):
                type_str = typing_to_clickhouse(f.type)
                yield f, type_str
            continue

        try:
            type_str = typing_to_clickhouse(f.type)
        except:
            print(f"failed to generate create table for {f} of {field_tuple}")
            raise
        yield f, type_str


def format_create_query(
    table_name: str,
    model: Type[TableModelProtocol],
    engine: str = "ReplacingMergeTree",
    extra: bool = True,
) -> Tuple[str, str]:
    columns = []
    for f, type_str in iter_table_fields(fields(model)):
        columns.append(f"     {f.name} {type_str}")

    columns_str = ",\n".join(columns)
    index_str = ",\n".join(model.__table_index__)
    extra_str = ""
    if extra:
        extra_str = f"ORDER BY ({index_str}) SETTINGS index_granularity = 8192;"
    return (
        f"""
    CREATE TABLE IF NOT EXISTS {table_name} (
{columns_str}
    )
    ENGINE = {engine}
    {extra_str}
    """,
        table_name,
    )


table_models = [
    WebObservation,
    WebControlObservation,
    HTTPMiddleboxObservation,
    WebAnalysis,
    MeasurementExperimentResult,
]


def make_create_queries(
    num_layers=1,
    min_time=10,
    max_time=500,
    min_rows=10_0000,
    max_rows=100_000,
    min_bytes=10_000_000,
    max_bytes=1_000_000_000,
    with_buffer_table=True,
):
    create_queries = []
    for model in table_models:
        table_name = model.__table_name__
        create_queries.append(
            format_create_query(table_name, model),
        )

        if with_buffer_table:
            engine_str = f"""
            Buffer(
                currentDatabase(), {table_name}, 
                {num_layers},
                {min_time}, {max_time}, 
                {min_rows}, {max_rows},
                {min_bytes}, {max_bytes}
            )
            """
            create_queries.append(
                format_create_query(
                    f"buffer_{table_name}",
                    model,
                    engine=engine_str,
                    extra=False,
                )
            )
    return create_queries


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
            s += f"ALTER TABLE {self.table_name} DROP COLUMN IF EXISTS {self.column_name};\n"
            return s
        if self.actual_type == None:
            s = f"-- MISSING {self.expected_type}\n"
            s += f"ALTER TABLE {self.table_name} ADD COLUMN IF NOT EXISTS {self.column_name} {self.expected_type};\n"
            return s
        if self.actual_type != self.expected_type:
            s = f"-- {self.actual_type} != {self.expected_type}\n"
            s += f"ALTER TABLE {self.table_name} MODIFY COLUMN {self.column_name} {self.expected_type};\n"
            return s


def get_table_column_diff(
    db: ClickhouseConnection, base_class, table_name: str
) -> List[ColumnDiff]:
    """
    returns the difference between the current database tables and what we would
    expect to see.
    If the list is empty, it means there is no difference, otherwise you will
    get a list of ColumnDiff which includes the differences in the columns.
    """
    try:
        res = db.execute(f"SHOW CREATE TABLE {table_name}")
    except:
        raise TableDoesNotExistError
    assert isinstance(res, list)
    column_map = get_column_map_from_create_query(res[0][0])
    column_diff = []

    for f, _ in iter_table_fields(fields(base_class)):
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
    for base_class in table_models:
        table_name = base_class.__table_name__
        try:
            diff_orig = get_table_column_diff(
                db=db, base_class=base_class, table_name=table_name
            )
            diff_buffer = get_table_column_diff(
                db=db, base_class=base_class, table_name=f"buffer_{table_name}"
            )
        except TableDoesNotExistError:
            print(f"# {table_name} does not exist")
            print("rerun with --create-tables")
            continue
        if len(diff_orig) > 0:
            print(f"# {table_name} diff")
            for cd in diff_orig:
                print(cd.get_sql_migration())
        if len(diff_buffer) > 0:
            print(f"# buffer_{table_name} diff")
            for cd in diff_buffer:
                print(cd.get_sql_migration())


def main():
    for query, table_name in make_create_queries():
        print(f"clickhouse-client -q 'DROP TABLE {table_name}';")
        print("cat <<EOF | clickhouse-client -nm")
        print(query)
        print("EOF")


if __name__ == "__main__":
    main()
