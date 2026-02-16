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

from oonidata.models.base import TableModelProtocol
from oonidata.models.observations import (
    MeasurementMeta,
    ProbeMeta,
    WebControlObservation,
    WebObservation,
    HTTPMiddleboxObservation,
)

from .connections import ClickhouseConnection


MAPPED_BASIC_TYPES = [str, int, bool, datetime, float, dict]
BasicType = Union[str, int, bool, datetime, float, dict]


def python_basic_type_to_clickhouse(t: BasicType) -> str:
    if t == str:
        return "String"
    if t == int:
        return "Int32"
    if t == bool:
        return "Int8"
    if t == datetime:
        return "Datetime64(3, 'UTC')"
    if t == float:
        return "Float64"
    if t == dict:
        return "String"
    raise Exception(f"Unsupported type {t}")


def typing_to_clickhouse(t: Any) -> str:
    if t in MAPPED_BASIC_TYPES:
        return python_basic_type_to_clickhouse(t)

    if t in (Optional[str], Optional[bytes]):
        return "Nullable(String)"

    if t == Optional[int]:
        return "Nullable(Int32)"

    if t == Optional[bool]:
        return "Nullable(Int8)"

    if t == Optional[datetime]:
        return "Nullable(Datetime64(3, 'UTC'))"

    # Casting it to JSON
    if t == List[Dict]:
        return "String"

    if t == Optional[float]:
        return "Nullable(Float64)"

    if t == List[float]:
        return "Array(Float64)"

    if t == List[List[str]]:
        return "Array(Array(String))"

    if t in (List[str], List[bytes]):
        return "Array(String)"

    if t == Optional[List[str]]:
        return "Nullable(Array(String))"

    if t == Optional[List[Tuple[str, bytes]]]:
        return "Nullable(Array(Array(String)))"

    if t in (Mapping[str, str], Dict[str, str]):
        return "Map(String, String)"

    # TODO(art): eventually all the above types should be mapped using a similar pattern
    child_type, parent_type = typing.get_args(t)
    is_nullable = False
    if parent_type == NoneType:
        is_nullable = True
        target_type = child_type
    else:
        target_type = parent_type
    target_origin = typing.get_origin(target_type)
    target_args = typing.get_args(target_type)
    assert (
        target_origin == tuple
    ), f"{target_origin} is not tuple (target_args={target_args}, {target_type} {parent_type})"
    tuple_args = ", ".join([python_basic_type_to_clickhouse(a) for a in target_args])
    if is_nullable:
        return f"Nullable(Tuple({tuple_args}))"
    return f"Tuple({tuple_args})"


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
        if model.__partition_key__:
            extra_str = f"PARTITION BY ({model.__partition_key__})\n"
        extra_str += f"ORDER BY ({index_str}) SETTINGS index_granularity = 8192;"
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
]


def make_create_queries():
    create_queries = [
        (
            """
        CREATE TABLE IF NOT EXISTS fingerprints_dns (
            `name` String, `scope` String, `other_names` String, `location_found` String, `pattern_type` String,
            `pattern` String, `confidence_no_fp` String, `expected_countries` String, `source` String, `exp_url` String, `notes` String
        ) ENGINE = URL('https://raw.githubusercontent.com/ooni/blocking-fingerprints/main/fingerprints_dns.csv', 'CSV')
        """,
            "fingerprints_dns",
        ),
        (
            """
        CREATE TABLE IF NOT EXISTS analysis_web_measurement
        (
            `domain` String,
            `input` String,
            `test_name` String,
            `probe_asn` UInt32,
            `probe_as_org_name` String,
            `probe_cc` String,
            `resolver_asn` UInt32, `resolver_as_cc` String, `network_type` String,
            `measurement_start_time` DateTime64(3, 'UTC'),
            `measurement_uid` String,
            `ooni_run_link_id` String,
            `top_probe_analysis` Nullable(String),
            `top_dns_failure` Nullable(String),
            `top_tcp_failure` Nullable(String), `top_tls_failure` Nullable(String),
            `dns_blocked` Float32, `dns_down` Float32, `dns_ok` Float32,
            `tcp_blocked` Float32, `tcp_down` Float32, `tcp_ok` Float32,
            `tls_blocked` Float32, `tls_down` Float32, `tls_ok` Float32
        )
        ENGINE = ReplacingMergeTree
        PRIMARY KEY measurement_uid
        ORDER BY (measurement_uid, measurement_start_time, probe_cc, probe_asn)
        PARTITION BY substring(measurement_uid, 1, 6)
        SETTINGS index_granularity = 8192
    """,
            "analysis_web_measurement",
        ),
        (
            """
        CREATE TABLE IF NOT EXISTS event_detector_changepoints (
            `probe_asn` UInt32,
            `probe_cc` String,
            `domain` String,
            `ts` DateTime64(3, 'UTC'),
            `count_isp_resolver` Nullable(UInt32),
            `count_other_resolver` Nullable(UInt32),
            `count` Nullable(UInt32),
            `dns_isp_blocked` Nullable(float),
            `dns_other_blocked` Nullable(float),
            `tcp_blocked` Nullable(float),
            `tls_blocked` Nullable(float),
            `last_ts` DateTime64(3, 'UTC'),
            `dns_isp_blocked_obs_w_sum` Nullable(float),
            `dns_isp_blocked_w_sum` Nullable(float),
            `dns_isp_blocked_s_pos` Nullable(float),
            `dns_isp_blocked_s_neg` Nullable(float),
            `dns_other_blocked_obs_w_sum` Nullable(float),
            `dns_other_blocked_w_sum` Nullable(float),
            `dns_other_blocked_s_pos` Nullable(float),
            `dns_other_blocked_s_neg` Nullable(float),
            `tcp_blocked_obs_w_sum` Nullable(float),
            `tcp_blocked_w_sum` Nullable(float),
            `tcp_blocked_s_pos` Nullable(float),
            `tcp_blocked_s_neg` Nullable(float),
            `tls_blocked_obs_w_sum` Nullable(float),
            `tls_blocked_w_sum` Nullable(float),
            `tls_blocked_s_pos` Nullable(float),
            `tls_blocked_s_neg` Nullable(float),
            `change_dir` Nullable(Int8),
            `s_pos` Nullable(float),
            `s_neg` Nullable(float),
            `current_mean` Nullable(float),
            `h` Nullable(float),
            `block_type` String
        )
        ENGINE = ReplacingMergeTree
        ORDER BY (probe_asn, probe_cc, ts, domain);

            """,
            "event_detector_changepoints",
        ),
        (
            """
        CREATE TABLE IF NOT EXISTS event_detector_cusums
        (
            `probe_asn` UInt32,
            `probe_cc` String,
            `domain` String,
            `ts` DateTime64(3, 'UTC'),
            `dns_isp_blocked_obs_w_sum` Nullable(Float64),
            `dns_isp_blocked_w_sum` Nullable(Float64),
            `dns_isp_blocked_s_pos` Nullable(Float64),
            `dns_isp_blocked_s_neg` Nullable(Float64),

            `dns_other_blocked_obs_w_sum` Nullable(Float64),
            `dns_other_blocked_w_sum` Nullable(Float64),
            `dns_other_blocked_s_pos` Nullable(Float64),
            `dns_other_blocked_s_neg` Nullable(Float64),

            `tcp_blocked_obs_w_sum` Nullable(Float64),
            `tcp_blocked_w_sum` Nullable(Float64),
            `tcp_blocked_s_pos` Nullable(Float64),
            `tcp_blocked_s_neg` Nullable(Float64),

            `tls_blocked_obs_w_sum` Nullable(Float64),
            `tls_blocked_w_sum` Nullable(Float64),
            `tls_blocked_s_pos` Nullable(Float64),
            `tls_blocked_s_neg` Nullable(Float64)
        )
        ENGINE = ReplacingMergeTree
        ORDER BY (probe_asn, probe_cc, domain);
            """,
            "event_detector_cusums",
        ),
        (
            """
        CREATE TABLE IF NOT EXISTS faulty_measurements
        (
            `ts` DateTime64(3, 'UTC'),
            `type` String,
            -- geoip lookup result for the probe IP
            `probe_cc` String,
            `probe_asn` UInt32,
            -- JSON-encoded details about the anomaly
            `details` String
        )
        ENGINE = ReplacingMergeTree
        ORDER BY (type, probe_cc, probe_asn);
            """,
            "event_detector_cusums",
        ),
    ]
    for model in table_models:
        table_name = model.__table_name__
        create_queries.append(
            format_create_query(table_name, model),
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
        except TableDoesNotExistError:
            print(f"# {table_name} does not exist")
            print("rerun with --create-tables")
            continue
        if len(diff_orig) > 0:
            print(f"# {table_name} diff")
            for cd in diff_orig:
                print(cd.get_sql_migration())

def main():
    for query, table_name in make_create_queries():
        print(f"clickhouse-client -q 'DROP TABLE {table_name}';")
        print("cat <<EOF | clickhouse-client -nm")
        print(query)
        print("EOF")


if __name__ == "__main__":
    main()
