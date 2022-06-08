import inspect

from datetime import datetime

from typing import Optional, Union, Tuple, List, Any
from oonidata.observations import (
    Observation,
    DNSObservation,
    TCPObservation,
    TLSObservation,
    HTTPObservation,
)


def _annotation_to_db_type(t: Any) -> str:
    if t == Optional[str] or t == str:
        return "String"

    if t == int or t == Optional[int]:
        return "Int32"

    if t == bool or t == Optional[bool]:
        return "Int8"

    if t == datetime or t == Optional[datetime]:
        return "Datetime64(6)"

    if t == float or t == Optional[float]:
        return "Float64"

    if t == List[str] or t == Optional[List[str]]:
        return "Array(String)"

    if t == Optional[List[Tuple[str, bytes]]]:
        return "Array(Array(String))"

    raise Exception(f"Unhandled type {t}")


def create_query_for_observation(obs_class: Observation) -> str:
    create_query = f"CREATE TABLE IF NOT EXISTS {obs_class.db_table} (\n"
    for cls in reversed(inspect.getmro(obs_class)):
        for name, ants in inspect.get_annotations(cls).items():
            if name == "db_table":
                continue
            type_str = _annotation_to_db_type(ants)
            create_query += f"`{name}` {type_str},\n"

    create_query += ")\n"
    create_query += """
    ENGINE = ReplacingMergeTree
    ORDER BY ()
    SETTINGS index_granularity = 8192;
    """
    return create_query


def main():
    print(create_query_for_observation(DNSObservation))
    print(create_query_for_observation(TCPObservation))
    print(create_query_for_observation(TLSObservation))
    print(create_query_for_observation(HTTPObservation))


main()
