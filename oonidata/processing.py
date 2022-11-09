import time
import logging
import traceback
import orjson

from tqdm import tqdm
from tqdm.contrib.logging import logging_redirect_tqdm

from datetime import datetime, date, timedelta
from pathlib import Path
from dataclasses import asdict, fields

from typing import (
    Tuple,
    List,
    Generator,
    Type,
    TypeVar,
    Optional,
    Union,
    Iterable,
    Dict,
)

from oonidata.datautils import one_day_dict, is_ip_bogon
from oonidata.observations import (
    NettestObservation,
    DNSObservation,
    Observation,
    make_http_observations,
    make_dns_observations,
    make_tcp_observations,
    make_tls_observations,
    make_web_connectivity_observations,
    make_ip_to_domain,
)
from oonidata.dataformat import DNSCheck, load_measurement
from oonidata.dataformat import BaseMeasurement, WebConnectivity, Tor
from oonidata.fingerprintdb import FingerprintDB
from oonidata.netinfo import NetinfoDB

from oonidata.dataclient import (
    MeasurementListProgress,
    iter_measurements,
    ProgressStatus,
)
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


def write_observations_to_db(
    db: DatabaseConnection, observations: Iterable[Observation]
) -> None:
    for obs in observations:
        row = make_observation_row(obs)
        db.write_row(obs.__table_name__, row)


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
        make_web_connectivity_observations(
            msmt, fingerprintdb=fingerprintdb, netinfodb=netinfodb
        ),
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
        ip_to_domain = make_ip_to_domain(dns_observations)
        write_observations_to_db(
            db,
            dns_observations,
        )

    lookup_map = msmt.test_keys.lookups or {}
    for lookup in lookup_map.values():
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
    res = db.execute(q, params)
    assert isinstance(res, list)
    return [row[0] for row in res]


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

    q += "ORDER BY report_id, measurement_uid;"

    # Put all the DNS observations from the same testing session into a list and yield it
    dns_obs_session = []
    last_obs_session_id = None
    res = db.execute(q, q_params)
    assert isinstance(res, list)
    for rows in res:
        obs_dict = {field_names[idx]: val for idx, val in enumerate(rows)}
        dns_obs = DNSObservation(**obs_dict)

        if last_obs_session_id and last_obs_session_id != dns_obs.report_id:
            yield dns_obs_session
            dns_obs_session = [dns_obs]
            last_obs_session_id = dns_obs.report_id
        else:
            dns_obs_session.append(dns_obs)
    if len(dns_obs_session) > 0:
        yield dns_obs_session


T = TypeVar("T", bound="Observation")


def observations_in_session(
    day: date,
    domain_name: str,
    obs_class: Type[T],
    report_id: str,
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
    AND report_id = %(report_id)s;
    """
    q_params = one_day_dict(day)
    q_params["domain_name"] = domain_name
    q_params["report_id"] = report_id

    res = db.execute(q, q_params)
    assert isinstance(res, list)
    for rows in res:
        obs_dict = {field_names[idx]: val for idx, val in enumerate(rows)}
        observation_list.append(obs_class(**obs_dict))
    return observation_list


nettest_processors = {
    "web_connectivity": web_connectivity_processor,
    "dnscheck": dnscheck_processor,
    "tor": tor_processor,
}


def process_msmt_dict(
    msmt_dict: Dict,
    db: Union[ClickhouseConnection, CSVConnection],
    netinfodb: NetinfoDB,
    fingerprintdb: FingerprintDB,
):
    msmt = load_measurement(msmt_dict)
    base_processor(msmt, db, netinfodb)
    processor = nettest_processors.get(msmt.test_name, default_processor)
    processor(
        msmt,
        db,
        fingerprintdb,
        netinfodb,
    )


def process_day(
    db: Union[ClickhouseConnection, CSVConnection],
    fingerprintdb: FingerprintDB,
    netinfodb: NetinfoDB,
    day: date,
    test_name=[],
    probe_cc=[],
    start_at_idx=0,
    fast_fail=False,
) -> Tuple[float, date]:
    t0 = time.monotonic()
    with tqdm(unit="B", unit_scale=True) as pbar:

        def progress_callback(p: MeasurementListProgress):
            if p.progress_status == ProgressStatus.LISTING:
                if not pbar.total:
                    pbar.total = p.total_prefixes
                pbar.update(1)
                pbar.set_description(
                    f"listed {p.total_file_entries} files in {p.current_prefix_idx}/{p.total_prefixes} prefixes"
                )
                return

            if p.progress_status == ProgressStatus.DOWNLOAD_BEGIN:
                pbar.unit = "B"
                pbar.reset(total=p.total_file_entry_bytes)

            pbar.set_description(
                f"downloading {p.current_file_entry_idx}/{p.total_file_entries} files"
            )
            pbar.update(p.current_file_entry_bytes)

        for idx, msmt_dict in enumerate(
            iter_measurements(
                probe_cc=probe_cc,
                test_name=test_name,
                start_day=day,
                end_day=day + timedelta(days=1),
                progress_callback=progress_callback,
            )
        ):
            pbar.set_description(f"idx {idx}")
            if idx < start_at_idx:
                continue
            try:
                process_msmt_dict(
                    msmt_dict=msmt_dict,
                    db=db,
                    netinfodb=netinfodb,
                    fingerprintdb=fingerprintdb
                )
            except Exception as exc:
                log.error(f"failed at idx:{idx} {exc}")
                with open("bad_msmts.jsonl", "ab+") as out_file:
                    out_file.write(orjson.dumps(msmt_dict))
                    out_file.write(b"\n")
                with open("bad_msmts_fail_log.txt", "a+") as out_file:
                    out_file.write(traceback.format_exc())
                    out_file.write("ENDTB----\n")
                if fast_fail:
                    raise exc

    return time.monotonic() - t0, day
