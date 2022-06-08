from collections.abc import Iterable
from typing import Optional, Union, Tuple, List

from oonidata.observations import (
    Observation,
    make_http_observations,
    make_dns_observations,
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


def insert_query_for_observation(observation: Observation) -> Tuple[str, dict]:
    params = {}
    for attr in observation.__dict__:
        params[attr] = getattr(observation, attr)
    fields = ", ".join(params.keys())
    query_str = f"INSERT INTO {observation.db_table} ({fields}) VALUES"

    return (query_str, params)


def write_observations_to_db(
    db: DatabaseConnection, observations: Iterable[Observation]
):
    for obs in observations:
        query, params = insert_query_for_observation(obs)
        db.execute(query, params)


def web_connectivity_processor(
    msmt: BaseMeasurement,
    db: DatabaseConnection,
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
) -> bool:
    write_observations_to_db(
        db,
        make_http_observations(msmt, msmt.test_keys.requests, fingerprintdb, netinfodb),
    )
    write_observations_to_db(
        db,
        make_dns_observations(msmt, msmt.test_keys.queries, fingerprintdb, netinfodb),
    )


nettest_processors = {"web_connectivity": web_connectivity_processor}
