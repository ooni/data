import sys
import time
import argparse
import logging
import traceback
import multiprocessing

from tqdm import tqdm
from tqdm.contrib.logging import logging_redirect_tqdm

from datetime import datetime, date, timedelta
from pathlib import Path
from dataclasses import asdict, fields

from collections.abc import Iterable
from typing import Tuple, List, Generator, Type, TypeVar, Any, Optional

from oonidata.datautils import one_day_dict, is_ip_bogon
from oonidata.observations import (
    NettestObservation,
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
from oonidata.dataformat import DNSCheck, load_measurement
from oonidata.dataformat import BaseMeasurement, WebConnectivity, Tor
from oonidata.fingerprints.matcher import FingerprintDB
from oonidata.netinfo import NetinfoDB
from oonidata.verdicts import (
    DNSBaseline,
    Verdict,
    make_dns_baseline,
    make_http_baseline_map,
    make_tcp_baseline_map,
    make_website_verdicts,
)

from oonidata.dataclient import iter_raw_measurements, date_interval
from oonidata.db.connections import (
    DatabaseConnection,
    ClickhouseConnection,
    CSVConnection,
)

log = logging.getLogger("oonidata.processing")


def observation_field_names(obs_class: Type[Observation]) -> List[str]:
    return list(map(lambda dc: dc.name, fields(obs_class)))


def make_observation_row(observation: Observation) -> dict:
    return asdict(observation)


def make_verdict_row(v: Verdict) -> dict:
    row = asdict(v)
    # XXX come up with a cleaner solution to this
    row["outcome"] = row["outcome"].value
    return row


def write_observations_to_db(
    db: DatabaseConnection, observations: Iterable[Observation]
) -> None:
    for obs in observations:
        row = make_observation_row(obs)
        db.write_row(obs.__table_name__, row)


def write_verdicts_to_db(db: DatabaseConnection, verdicts: Iterable[Verdict]) -> None:
    for v in verdicts:
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
    msmt: Tor,
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
    msmt: WebConnectivity,
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
        str(obs.answer): obs.domain_name
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


def dnscheck_processor(
    msmt: DNSCheck,
    db: DatabaseConnection,
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
) -> None:
    ip_to_domain = {}
    if msmt.test_keys.bootstrap:
        dns_observations = list(
            make_dns_observations(
                msmt, msmt.test_keys.bootstrap.queries, fingerprintdb, netinfodb
            )
        )
        ip_to_domain = {
            str(obs.answer): obs.domain_name
            for obs in filter(lambda o: o.answer, dns_observations)
        }
        write_observations_to_db(
            db,
            dns_observations,
        )

    for lookup in msmt.test_keys.lookups.values():
        write_observations_to_db(
            db, make_dns_observations(msmt, lookup.queries, fingerprintdb, netinfodb)
        )

        write_observations_to_db(
            db,
            make_http_observations(msmt, lookup.requests, fingerprintdb, netinfodb),
        )

        write_observations_to_db(
            db,
            make_tcp_observations(msmt, lookup.tcp_connect, netinfodb, ip_to_domain),
        )

        write_observations_to_db(
            db,
            make_tls_observations(
                msmt,
                lookup.tls_handshakes,
                lookup.network_events,
                netinfodb,
                ip_to_domain,
            ),
        )


def base_processor(
    msmt: BaseMeasurement,
    db: DatabaseConnection,
    netinfodb: NetinfoDB,
) -> None:
    write_observations_to_db(db, [NettestObservation.from_measurement(msmt, netinfodb)])


def domains_in_a_day(
    day: date, db: ClickhouseConnection, probe_cc: Optional[str]
) -> List[str]:
    q = """SELECT DISTINCT(domain_name) FROM obs_dns
    WHERE timestamp >= %(start_day)s
    AND timestamp <= %(end_day)s
    """
    params = one_day_dict(day)
    if probe_cc:
        q += "AND probe_cc = %(probe_cc)s"
        params["probe_cc"] = probe_cc
    return [res[0] for res in db.execute(q, params)]


def dns_observations_by_session(
    day: date,
    domain_name: str,
    db: ClickhouseConnection,
    probe_cc: Optional[str] = None,
) -> Generator[List[DNSObservation], None, None]:
    # I wish I had an ORM...
    field_names = observation_field_names(DNSObservation)

    q_params = one_day_dict(day)
    q_params["domain_name"] = domain_name

    q = "SELECT "
    q += ",\n".join(field_names)
    q += """
    FROM obs_dns
    WHERE domain_name = %(domain_name)s
    AND timestamp >= %(start_day)s
    AND timestamp <= %(end_day)s
    """
    if probe_cc:
        q += "AND probe_cc = %(probe_cc)s\n"
        q_params["probe_cc"] = probe_cc

    q += "ORDER BY session_id, measurement_uid;"

    # Put all the DNS observations from the same testing session into a list and yield it
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


T = TypeVar("T", bound="Observation")


def observations_in_session(
    day: date,
    domain_name: str,
    obs_class: Type[T],
    session_id: str,
    db: ClickhouseConnection,
) -> List[T]:
    observation_list = []
    field_names = observation_field_names(obs_class)
    q = "SELECT "
    q += ",\n".join(field_names)
    q += " FROM " + obs_class.__table_name__
    q += """
    WHERE domain_name = %(domain_name)s
    AND timestamp >= %(start_day)s
    AND timestamp <= %(end_day)s
    AND session_id = %(session_id)s;
    """
    q_params = one_day_dict(day)
    q_params["domain_name"] = domain_name
    q_params["session_id"] = session_id

    for res in db.execute(q, q_params):
        obs_dict = {field_names[idx]: val for idx, val in enumerate(res)}
        observation_list.append(obs_class(**obs_dict))
    return observation_list


def websites_observation_group(
    day: date,
    domain_name: str,
    db: ClickhouseConnection,
    probe_cc: Optional[str] = None,
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
    for dns_obs_list in dns_observations_by_session(day, domain_name, db, probe_cc):
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

        # Drop all verdicts related to this session from the database.
        # XXX this should probably be refactored to be closer to the place where
        # we do the insert, but will require quite a bit of reorganizing of the
        # logic in here.
        db.execute(
            "ALTER TABLE verdict DELETE WHERE session_id = %(session_id)s",
            {"session_id": session_id},
        )
        yield dns_obs_list, tcp_o_list, tls_o_list, http_o_list


import certifi
import ssl
import socket


def is_tls_valid(ip, hostname):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(certifi.where())

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.settimeout(1)
        with context.wrap_socket(sock, server_hostname=hostname) as conn:
            try:
                conn.connect((ip, 443))
            # TODO: do we care to distinguish these values?
            except ssl.SSLCertVerificationError:
                return False
            except ssl.SSLError:
                return False
            except socket.timeout:
                return False
            except socket.error:
                return False
            except:
                return False
    return True


def get_extra_dns_consistency_tls_baseline(
    dns_baseline: DNSBaseline,
    dns_o_list: List[DNSObservation],
    db: ClickhouseConnection,
) -> List[str]:
    domain_name = dns_o_list[0].domain_name
    missing_answers = set(map(lambda a: a.answer, dns_o_list))
    for a in list(missing_answers):
        if a is None:
            missing_answers.discard(a)
            continue

        try:
            if is_ip_bogon(a):
                missing_answers.discard(a)
        except ValueError:
            missing_answers.discard(a)

    for a in dns_baseline.tls_consistent_answers:
        missing_answers.discard(a)

    new_tls_consistent_ips = []
    res = db.execute(
        "SELECT DISTINCT ip FROM dns_consistency_tls_baseline WHERE ip IN %(ip_list)s AND domain_name = %(domain_name)s",
        {"ip_list": list(missing_answers), "domain_name": domain_name},
    )
    for row in res:
        missing_answers.discard(row[0])
        new_tls_consistent_ips.append(row[0])

    rows_to_write = []
    for ip in missing_answers:
        timestamp = datetime.now()
        if is_tls_valid(ip, domain_name):
            rows_to_write.append((ip, domain_name, timestamp))
            new_tls_consistent_ips.append(ip)

    if len(rows_to_write) > 0:
        db.execute(
            "INSERT INTO dns_consistency_tls_baseline (ip, domain_name, timestamp) VALUES",
            rows_to_write,
        )
    return new_tls_consistent_ips


def generate_website_verdicts(
    day: date,
    db: ClickhouseConnection,
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
    probe_cc: Optional[str] = None,
):
    with logging_redirect_tqdm():
        for domain_name in tqdm(domains_in_a_day(day, db, probe_cc)):
            log.debug(f"Generating verdicts for {domain_name}")
            dns_baseline = make_dns_baseline(day, domain_name, db)
            http_baseline_map = make_http_baseline_map(day, domain_name, db)
            tcp_baseline_map = make_tcp_baseline_map(day, domain_name, db)

            for (
                dns_o_list,
                tcp_o_list,
                tls_o_list,
                http_o_list,
            ) in websites_observation_group(day, domain_name, db, probe_cc=probe_cc):
                extra_tls_consistent_answers = get_extra_dns_consistency_tls_baseline(
                    dns_baseline, dns_o_list, db
                )
                dns_baseline.tls_consistent_answers = list(
                    set(
                        list(dns_baseline.tls_consistent_answers)
                        + extra_tls_consistent_answers
                    )
                )
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
    "dnscheck": dnscheck_processor,
    "tor": tor_processor,
}


def process_day(
    db: DatabaseConnection,
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
    day: date,
    testnames=[],
    country_codes=[],
    start_at_idx=0,
    skip_verdicts=False,
    fast_fail=False,
) -> Tuple[float, date]:
    t0 = time.monotonic()
    with tqdm(unit="B", unit_scale=True) as pbar:
        for idx, raw_msmt in enumerate(
            iter_raw_measurements(
                ccs=set(country_codes),
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
                base_processor(msmt, db, netinfodb)
                processor = nettest_processors.get(msmt.test_name, default_processor)
                processor(
                    msmt,
                    db,
                    fingerprintdb,
                    netinfodb,
                )
            except Exception as exc:
                with open("bad_msmts.jsonl", "a+") as out_file:
                    out_file.write(raw_msmt.decode("utf-8"))
                    out_file.write("\n")
                with open("bad_msmts_fail_log.txt", "a+") as out_file:
                    out_file.write(traceback.format_exc())
                    out_file.write("ENDTB----\n")
                if fast_fail:
                    raise exc

    if not skip_verdicts:
        write_verdicts_to_db(
            db,
            generate_website_verdicts(
                day,
                db,
                fingerprintdb,
                netinfodb,
            ),
        )

    return time.monotonic() - t0, day


if __name__ == "__main__":
    # XXX this is just for temporary testing
    log.addHandler(logging.StreamHandler())
    log.setLevel(logging.DEBUG)

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
        "--geoip-dir",
        type=str,
    )
    parser.add_argument(
        "--asn-map",
        type=str,
    )
    parser.add_argument(
        "--country-code",
        type=str,
    )
    parser.add_argument(
        "--start-day",
        type=_parse_date_flag,
        default=date(2022, 1, 1),
    )
    parser.add_argument(
        "--end-day",
        type=_parse_date_flag,
        default=date(2022, 1, 2),
    )
    parser.add_argument(
        "--parallelism",
        type=int,
        default=multiprocessing.cpu_count(),
    )
    parser.add_argument(
        "--start-at-idx",
        type=int,
        default=0,
    )
    parser.add_argument("--only-verdicts", action="store_true")
    parser.add_argument("--skip-verdicts", action="store_true")
    parser.add_argument("--fast-fail", action="store_true")
    args = parser.parse_args()

    fingerprintdb = FingerprintDB()

    netinfodb = NetinfoDB(
        datadir=Path(args.geoip_dir), as_org_map_path=Path(args.asn_map)
    )

    if args.clickhouse:
        db = ClickhouseConnection(args.clickhouse)
    elif args.csv_dir:
        db = CSVConnection(Path(args.csv_dir))
    else:
        raise Exception("Missing --csv-dir or --clickhouse")

    if args.only_verdicts:
        if not isinstance(db, ClickhouseConnection):
            raise Exception("verdict generation requires clickhouse")

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

    skip_verdicts = args.skip_verdicts
    if not isinstance(db, ClickhouseConnection):
        skip_verdicts = True

    testnames = []
    if args.testname:
        testnames = [args.testname]

    country_codes = []
    if args.country_code:
        country_codes = [args.country_code]

    def task_for_a_day(day):
        return process_day(
            db,
            fingerprintdb,
            netinfodb,
            day,
            testnames=testnames,
            country_codes=country_codes,
            start_at_idx=args.start_at_idx,
            skip_verdicts=skip_verdicts,
            fast_fail=args.fast_fail,
        )

    with multiprocessing.Pool(processes=args.parallelism) as pool:
        for runtime, day in pool.imap_unordered(
            task_for_a_day, date_interval(args.start_day, args.end_day)
        ):
            with open("runtime-log.txt", "a+") as out_file:
                out_file.write(f"{day},{runtime}\n")
