from datetime import datetime

from typing import Optional, Tuple, List, Any, Type, Mapping, Dict
from dataclasses import fields
from oonidata.observations import (
    MeasurementMeta,
    ObservationBase,
    WebControlObservation,
    WebObservation,
)
from oonidata.experiments.experiment_result import (
    BlockingType,
    ExperimentResult,
    BlockingEvent,
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
        return "Datetime64(6)"

    if t == Optional[datetime]:
        return "Nullable(Datetime64(6))"

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

    if t == Optional[List[Tuple[str, bytes]]]:
        return "Nullable(Array(Array(String)))"

    if t == BlockingType:
        return "String"

    if t == List[BlockingEvent]:
        return "String"

        # FIXME: Temporarily disabled until I figure out how this works properly
        # columns = []
        # for name, type in BlockingEvent.__annotations__.items():
        #     type_str = typing_to_clickhouse(type)
        #     columns.append(f"         {name} {type_str}")
        # columns_str = ",\n".join(columns)

        # s = "Nested (\n"
        # s += columns_str
        # s += "\n     )"
        # return s

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
    for f in fields(ExperimentResult):
        if f.name == "blocking_events":
            continue
        type_str = typing_to_clickhouse(f.type)
        columns.append(f"     {f.name} {type_str}")

    # TODO: this is a little bit sketch, should change the base data struct
    for f in fields(BlockingEvent):
        type_str = typing_to_clickhouse(f.type)
        columns.append(f"     {f.name} {type_str}")

    columns_str = ",\n".join(columns)

    return (
        f"""
    CREATE TABLE IF NOT EXISTS experiment_result (
{columns_str}
    )
    ENGINE = ReplacingMergeTree
    ORDER BY (measurement_uid)
    SETTINGS index_granularity = 8192;
    """,
        "experiment_result",
    )


create_queries = [
    create_query_for_observation(WebObservation),
    create_query_for_observation(WebControlObservation),
    create_query_for_experiment_result(),
]


def main():
    for query, table_name in create_queries:
        print(f"clickhouse-client -q 'DROP TABLE {table_name}';")
        print("cat <<EOF | clickhouse-client -nm")
        print(query)
        print("EOF")


if __name__ == "__main__":
    main()
