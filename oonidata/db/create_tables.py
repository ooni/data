from datetime import datetime

from typing import Optional, Tuple, List, Any, Type
from dataclasses import fields
from oonidata.observations import (
    Observation,
    DNSObservation,
    TCPObservation,
    TLSObservation,
    HTTPObservation,
)
from oonidata.verdicts import Outcome, Verdict

def typing_to_clickhouse(t: Any) -> str:
    if t == str:
        return "String"

    if t == Optional[str]:
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

    if t == Optional[float]:
        return "Nullable(Float64)"

    if t == List[str]:
        return "Array(String)"
    if t == Optional[List[str]]:
        return "Nullable(Array(String))"

    if t == Optional[List[Tuple[str, bytes]]]:
        return "Nullable(Array(Array(String)))"

    if t == Outcome:
        return "String"

    raise Exception(f"Unhandled type {t}")


def create_query_for_observation(obs_class: Type[Observation]) -> str:
    columns = []
    for f in fields(obs_class):
        type_str = typing_to_clickhouse(f.type)
        columns.append(f"     `{f.name}` {type_str}")

    columns_str = ",\n".join(columns)

    return f"""
    CREATE TABLE {obs_class.__table_name__} (
{columns_str}
    )
    ENGINE = ReplacingMergeTree
    ORDER BY (timestamp, observation_id, measurement_uid)
    SETTINGS index_granularity = 8192;
    """

def create_query_for_verdict() -> str:
    columns = []
    for f in fields(Verdict):
        type_str = typing_to_clickhouse(f.type)
        columns.append(f"     `{f.name}` {type_str}")

    columns_str = ",\n".join(columns)

    return f"""
    CREATE TABLE verdict (
{columns_str}
    )
    ENGINE = ReplacingMergeTree
    ORDER BY (timestamp, verdict_id, measurement_uid)
    SETTINGS index_granularity = 8192;
    """

def main():
    print(create_query_for_observation(DNSObservation))
    print(create_query_for_observation(TCPObservation))
    print(create_query_for_observation(TLSObservation))
    print(create_query_for_observation(HTTPObservation))

    print(create_query_for_verdict())

if __name__ == "__main__":
    main()
