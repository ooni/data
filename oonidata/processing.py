import json
import sys
import argparse
import logging
import tempfile
from tqdm import tqdm
from pprint import pprint
from datetime import datetime, date, timedelta
from pathlib import Path
from functools import cache
from dataclasses import asdict, fields

from collections.abc import Iterable
from typing import Tuple, List, Generator

from oonidata.datautils import trim_measurement, one_day_dict
from oonidata.dataformat import load_measurement
from oonidata.observations import (
    DNSObservation,
    HTTPObservation,
    Observation,
    TCPObservation,
    TLSObservation,
    make_http_observations,
    make_dns_observations,
    make_tcp_observations,
    make_tls_observations,
)
from oonidata.dataformat import BaseMeasurement
from oonidata.fingerprints.matcher import FingerprintDB
from oonidata.netinfo import NetinfoDB
from oonidata.verdicts import (
    Outcome,
    Verdict,
    make_dns_baseline,
    make_http_baseline_map,
    make_tcp_baseline_map,
    make_website_verdicts,
)

from oonidata.dataclient import iter_raw_measurements
from oonidata.db.connections import (
    DatabaseConnection,
    ClickhouseConnection,
    CSVConnection,
)

log = logging.getLogger("oonidata.processing")
log.addHandler(logging.StreamHandler())
log.setLevel(logging.DEBUG)


def observation_field_names(obs_class: Observation) -> List[str]:
    return list(lambda dc: dc.name, fields(obs_class))

def make_observation_row(observation: Observation) -> dict:
    return asdict(observation)

def make_verdict_row(v: Verdict) -> dict:
    return asdict(v)

def write_observations_to_db(
    db: DatabaseConnection, observations: Iterable[Observation]
) -> None:
    for obs in observations:
        row = make_observation_row(obs)
        db.write_row(obs.__table_name__, row)


def write_verdicts_to_db(db: DatabaseConnection, verdicts: Iterable[Verdict]) -> None:
    for v in verdicts:
        log.debug(v)
        row = make_verdict_row(v)
        db.write_row("verdict", row)


def default_processor(
    msmt: BaseMeasurement,
    db: DatabaseConnection,
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
) -> None:
    print(f"Ignoring {msmt}")


def tor_processor(
    msmt: BaseMeasurement,
    db: DatabaseConnection,
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
) -> None:

    ip_to_domain = {}
    for target_id, target_msmt in msmt.test_keys.targets.items():
        write_observations_to_db(
            db,
            make_http_observations(
                msmt, target_msmt.requests, fingerprintdb, netinfodb, target=target_id
            ),
        )

        write_observations_to_db(
            db,
            make_dns_observations(
                msmt, target_msmt.queries, fingerprintdb, netinfodb, target=target_id
            ),
        )

        write_observations_to_db(
            db,
            make_tcp_observations(
                msmt, target_msmt.tcp_connect, netinfodb, ip_to_domain, target=target_id
            ),
        )

        write_observations_to_db(
            db,
            make_tls_observations(
                msmt,
                target_msmt.tls_handshakes,
                target_msmt.network_events,
                netinfodb,
                ip_to_domain,
                target=target_id,
            ),
        )


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
        for obs in filter(lambda o: o.answer, dns_observations)
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

    # Here we take dns measurements and compare them to what we see in the tls
    # data and check for TLS consistency.
    tls_valid_ip_to_domain = {}
    for obs in filter(
        lambda o: o.ip and o.domain_name,
        tls_observations,
    ):
        tls_valid_ip_to_domain[obs.ip] = tls_valid_ip_to_domain.get(obs.ip, {})
        tls_valid_ip_to_domain[obs.ip][obs.domain_name] = obs.is_certificate_valid
    enriched_dns_observations = []
    for dns_obs in dns_observations:
        if dns_obs.answer:
            valid_domains = tls_valid_ip_to_domain.get(dns_obs.answer, {})
            dns_obs.is_tls_consistent = valid_domains.get(dns_obs.domain_name, None)
        enriched_dns_observations.append(dns_obs)

    write_observations_to_db(
        db,
        enriched_dns_observations,
    )


def domains_in_a_day(day: date, db: ClickhouseConnection) -> Generator[str, None, None]:
    q = """SELECT DISTINCT(domain_name) FROM obs_dns
    WHERE timestamp >= %(start_day)s
    AND timestamp <= %(end_day)s;
    """
    for res in db.execute(q, one_day_dict(day)):
        yield res[0]


def dns_observations_by_session(
    day: date, domain_name: str, db: ClickhouseConnection
) -> Generator[List[DNSObservation], None, None]:
    # I wish I had an ORM...
    field_names = observation_field_names(DNSObservation)
    q = "SELECT "
    q += ",\n".join(field_names)
    q += """
    FROM obs_dns
    WHERE domain_name = %(domain_name)s
    AND timestamp >= %(start_day)s
    AND timestamp <= %(end_day)s
    ORDER BY session_id, measurement_uid;
    """
    q_params = one_day_dict(day)
    q_params["domain_name"] = domain_name

    dns_obs_session = []
    last_obs_session_id = None
    for res in db.execute(q, q_params):
        obs_dict = {field_names[idx]: val for idx, val in enumerate(res)}
        dns_obs = DNSObservation(**obs_dict)

        if last_obs_session_id and last_obs_session_id != dns_obs.session_id:
            yield dns_obs_session
            dns_obs_session = [dns_obs]
            last_obs_session_id = dns_obs.session_id
        else:
            dns_obs_session.append(dns_obs)
    if len(dns_obs_session) > 0:
        yield dns_obs_session


def observations_in_session(
    day: date,
    domain_name: str,
    obs_class: Observation,
    session_id: str,
    db: ClickhouseConnection,
) -> List[Observation]:
    observation_list = []
    field_names = observation_field_names(obs_class)
    q = "SELECT "
    q += ",\n".join(field_names)
    q += " FROM " + obs_class.__table_name__
    q += """
    WHERE domain_name = %(domain_name)s
    AND timestamp >= %(start_day)s
    AND timestamp <= %(end_day)s
    AND (session_id = %(session_id)s OR measurement_uid = %(session_id)s);
    """
    q_params = one_day_dict(day)
    q_params["domain_name"] = domain_name
    q_params["session_id"] = session_id

    for res in db.execute(q, q_params):
        obs_dict = {field_names[idx]: val for idx, val in enumerate(res)}
        observation_list.append(obs_class(**obs_dict))
    return observation_list


def websites_observation_group(
    day: date, domain_name: str, db: ClickhouseConnection
) -> Generator[
    Tuple[
        List[DNSObservation],
        List[TCPObservation],
        List[TLSObservation],
        List[HTTPObservation],
    ],
    None,
    None,
]:
    for dns_obs_list in dns_observations_by_session(day, domain_name, db):
        session_id = dns_obs_list[0].session_id
        tcp_o_list = observations_in_session(
            day,
            domain_name,
            TCPObservation,
            session_id,
            db,
        )
        tls_o_list = observations_in_session(
            day,
            domain_name,
            TLSObservation,
            session_id,
            db,
        )
        http_o_list = observations_in_session(
            day,
            domain_name,
            HTTPObservation,
            session_id,
            db,
        )
        yield dns_obs_list, tcp_o_list, tls_o_list, http_o_list


def generate_website_verdicts(
    day: date,
    db: ClickhouseConnection,
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
):
    for domain_name in domains_in_a_day(day, db):
        log.debug(f"Generating verdicts for {domain_name}")
        dns_baseline = make_dns_baseline(day, domain_name, db)
        http_baseline_map = make_http_baseline_map(day, domain_name, db)
        tcp_baseline_map = make_tcp_baseline_map(day, domain_name, db)

        for (
            dns_o_list,
            tcp_o_list,
            tls_o_list,
            http_o_list,
        ) in websites_observation_group(day, domain_name, db):
            yield from make_website_verdicts(
                dns_o_list,
                dns_baseline,
                fingerprintdb,
                netinfodb,
                tcp_o_list,
                tcp_baseline_map,
                tls_o_list,
                http_o_list,
                http_baseline_map,
            )


verdict_generators = [generate_website_verdicts]

nettest_processors = {
    "web_connectivity": web_connectivity_processor,
    "tor": tor_processor,
}


def process_day(db: DatabaseConnection, day: date, testnames=[], start_at_idx=0):
    fingerprintdb = FingerprintDB()
    netinfodb = NetinfoDB()

    with tqdm(unit="B", unit_scale=True) as pbar:
        for idx, raw_msmt in enumerate(
            iter_raw_measurements(
                ccs=[],
                testnames=testnames,
                start_day=day,
                end_day=day + timedelta(days=1),
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
                with open("bad_msmts.jsonl", "a+") as out_file:
                    out_file.write(raw_msmt.encode("utf-8"))
                    out_file.write("\n")
                log.error(f"Wrote bad msmt to: ./bad_msmts.jsonl")
                raise exc

    write_verdicts_to_db(
        db,
        generate_website_verdicts(
            day,
            db,
            fingerprintdb,
            netinfodb,
        ),
    )


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
        "--testname",
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
    parser.add_argument("--only-verdicts", action="store_true")
    args = parser.parse_args()

    if args.clickhouse:
        db = ClickhouseConnection(args.clickhouse)
    elif args.csv_dir:
        db = CSVConnection(Path(args.csv_dir))
    else:
        raise Exception("Missing --csv-dir or --clickhouse")

    if args.only_verdicts:
        fingerprintdb = FingerprintDB()
        netinfodb = NetinfoDB()
        write_verdicts_to_db(
            db,
            generate_website_verdicts(
                args.day,
                db,
                fingerprintdb,
                netinfodb,
            ),
        )
        sys.exit(0)

    testnames = []
    if args.testname:
        testnames = [args.testname]
    process_day(db, args.day, testnames=testnames, start_at_idx=args.start_at_idx)
