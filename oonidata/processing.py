import inspect
from collections.abc import Iterable
from datetime import datetime
from typing import Optional, Union, Tuple, List, Any

from oonidata.observations import (
    Observation,
    make_http_observations,
    make_dns_observations,
    make_tcp_observations,
    make_tls_observations,
)
from oonidata.dataformat import BaseMeasurement
from oonidata.fingerprints.matcher import FingerprintDB
from oonidata.netinfo import NetinfoDB


class DatabaseConnection:
    def __init__(self):
        self.client = None

    def execute(
        self, query: str, params: Optional[dict]
    ) -> Union[List[Tuple], int, None]:
        print(query)
        print(params)
        return


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
    create_query = f"CREATE TABLE IF NOT EXISTS {obs_class.db_table} ("
    for cls in inspect.getmro(obs_class):
        for name, ants in inspect.get_annotations(cls).items():
            if name == "db_table":
                continue
            type_str = _annotation_to_db_type(ants)
            create_query += f"`{name}` {type_str}\n"

    create_query += ")\n"
    create_query += """
    ENGINE = ReplacingMergeTree
    ORDER BY ()
    SETTINGS index_granularity = 8192;
    """
    return create_query


def insert_query_for_observation(observation: Observation) -> Tuple[str, dict]:
    params = {}
    for attr in observation.__dict__:
        params[attr] = getattr(observation, attr)
    fields = ", ".join(params.keys())
    query_str = f"INSERT INTO {observation.db_table} ({fields}) VALUES"

    return (query_str, params)


def write_observations_to_db(
    db: DatabaseConnection, observations: Iterable[Observation]
) -> None:
    for obs in observations:
        query, params = insert_query_for_observation(obs)
        db.execute(query, params)


def web_connectivity_processor(
    msmt: BaseMeasurement,
    db: DatabaseConnection,
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
) -> None:
    http_observations = make_http_observations(
        msmt, msmt.test_keys.requests, fingerprintdb, netinfodb
    )
    write_observations_to_db(
        db,
        http_observations,
    )

    dns_observations = make_dns_observations(
        msmt, msmt.test_keys.queries, fingerprintdb, netinfodb
    )
    write_observations_to_db(
        db,
        dns_observations,
    )

    ip_to_domain = {obs.answer: obs.domain_name for obs in dns_observations}

    tcp_observations = make_tcp_observations(
        msmt, msmt.test_keys.tcp_connect, netinfodb, ip_to_domain
    )
    write_observations_to_db(
        db,
        tcp_observations,
    )

    tls_observations = make_tls_observations(
        msmt, msmt.test_keys.tls_handshakes, netinfodb, ip_to_domain
    )
    write_observations_to_db(
        db,
        tls_observations,
    )


nettest_processors = {"web_connectivity": web_connectivity_processor}
