import json
import csv
import inspect
import argparse
from tqdm import tqdm
from pprint import pprint
from datetime import datetime, date, timedelta
from pathlib import Path
from functools import cache

from collections.abc import Iterable
from re import S
from typing import Optional, Union, Tuple, List, Any

from oonidata.datautils import trim_measurement
from oonidata.dataformat import load_measurement
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

from oonidata.dataclient import iter_raw_measurements


class DatabaseConnection:
    def __init__(self):
        self.client = None

    def execute(
        self, query: str, params: Optional[dict]
    ) -> Union[List[Tuple], int, None]:
        print(query)
        print(params)
        return

    def write_row(self, table_name, row):
        print(f"Writing to {table_name}")
        pprint(row)


class ClickhouseConnection(DatabaseConnection):
    def __init__(self, conn_url):
        from clickhouse_driver import Client

        self.client = Client.from_url(conn_url)

    def write_row(self, table_name, row):
        fields = ", ".join(row.keys())
        query_str = f"INSERT INTO {table_name} ({fields}) VALUES"
        try:
            self.client.execute(query_str, [row])
        except Exception as exc:
            print(f"Failed to write row {row}")
            raise exc


class CSVConnection(DatabaseConnection):
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.open_writers = {}

    def write_row(self, table_name, row):
        if table_name not in self.open_writers:
            out_path = (self.output_dir / f"{table_name}.csv").open("w")
            csv_writer = csv.DictWriter(out_path, fieldnames=list(row.keys()))
            csv_writer.writeheader()
            self.open_writers[table_name] = csv_writer

        self.open_writers[table_name].writerow(row)


@cache
def observation_attrs(obs_class: Observation) -> List[Tuple[str, Any]]:
    obs_attrs = []
    for cls in reversed(inspect.getmro(obs_class)):
        ann = cls.__dict__.get("__annotations__")
        if not ann:
            continue
        for name, t in ann.items():
            if name == "db_table":
                continue
            obs_attrs.append((name, t))
    return obs_attrs


def make_observation_row(observation: Observation) -> dict:
    row = {}
    for name, t in observation_attrs(observation.__class__):
        row[name] = getattr(observation, name, None)
        if t in (Optional[str], str) and row[name] is None:
            row[name] = ""
    return row


def write_observations_to_db(
    db: DatabaseConnection, observations: Iterable[Observation]
) -> None:
    for obs in observations:
        row = make_observation_row(obs)
        db.write_row(obs.db_table, row)


def default_processor(
    msmt: BaseMeasurement,
    db: DatabaseConnection,
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
) -> None:
    print(f"Ignoring {msmt}")


def web_connectivity_processor(
    msmt: BaseMeasurement,
    db: DatabaseConnection,
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
) -> None:
    write_observations_to_db(
        db,
        make_http_observations(msmt, msmt.test_keys.requests, fingerprintdb, netinfodb),
    )

    dns_observations = list(
        make_dns_observations(msmt, msmt.test_keys.queries, fingerprintdb, netinfodb)
    )
    ip_to_domain = {
        obs.answer: obs.domain_name
        # XXX this is a bit sketchy, it should be tidied up in the datamodel
        for obs in filter(lambda o: hasattr(o, "answer"), dns_observations)
    }

    write_observations_to_db(
        db,
        make_tcp_observations(
            msmt, msmt.test_keys.tcp_connect, netinfodb, ip_to_domain
        ),
    )

    tls_observations = list(
        make_tls_observations(
            msmt,
            msmt.test_keys.tls_handshakes,
            msmt.test_keys.network_events,
            netinfodb,
            ip_to_domain,
        )
    )
    write_observations_to_db(
        db,
        tls_observations,
    )

    tls_valid_domain_to_ip = {
        obs.domain: obs.is_certificate_valid
        for obs in filter(
            lambda o: hasattr(o, "domain") and hasattr(o, "is_certificate_valid"),
            tls_observations,
        )
    }
    enriched_dns_observations = []
    for dns_obs in dns_observations:
        if hasattr(dns_obs, "answer"):
            dns_obs.is_tls_consistent = tls_valid_domain_to_ip.get(dns_obs.answer, None)
        enriched_dns_observations.append(dns_obs)

    write_observations_to_db(
        db,
        enriched_dns_observations,
    )


nettest_processors = {"web_connectivity": web_connectivity_processor}


def process_day(db: DatabaseConnection, day: date, start_at_idx=0):
    fingerprintdb = FingerprintDB()
    netinfodb = NetinfoDB()

    with tqdm(unit="B", unit_scale=True) as pbar:
        for idx, raw_msmt in enumerate(
            iter_raw_measurements(
                ccs=[], testnames=[], start_day=day, end_day=day + timedelta(days=1)
            )
        ):
            pbar.set_description(f"idx {idx}")
            pbar.update(len(raw_msmt))
            if idx < start_at_idx:
                continue
            try:
                msmt = load_measurement(raw_msmt)
                processor = nettest_processors.get(msmt.test_name, default_processor)
                processor(
                    msmt,
                    db,
                    fingerprintdb,
                    netinfodb,
                )
            except Exception as exc:
                pprint(trim_measurement(json.loads(raw_msmt), 30))
                raise exc


if __name__ == "__main__":
    # XXX this is just for temporary testing
    def _parse_date_flag(date_str: str) -> date:
        return datetime.strptime(date_str, "%Y-%m-%d").date()

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--csv-dir",
        type=str,
    )
    parser.add_argument(
        "--clickhouse",
        type=str,
    )
    parser.add_argument(
        "--day",
        type=_parse_date_flag,
        default=date(2022, 1, 1),
    )
    parser.add_argument(
        "--start-at-idx",
        type=int,
        default=0,
    )
    args = parser.parse_args()

    if args.clickhouse:
        db = ClickhouseConnection(args.clickhouse)
    elif args.csv_dir:
        db = CSVConnection(Path(args.csv_dir))
    else:
        raise Exception("Missing --csv-dir or --clickhouse")

    # 31469
    process_day(db, args.day, args.start_at_idx)
