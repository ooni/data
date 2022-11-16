from collections import defaultdict
import time
import logging
import traceback
import orjson

from tqdm import tqdm

from datetime import date, timedelta
from dataclasses import asdict, fields

from typing import (
    Tuple,
    List,
    Type,
    Union,
    Dict,
)

from oonidata.observations import (
    ChainedObservation,
    Observation,
    make_tor_observations,
    make_signal_observations,
    make_web_connectivity_observations,
    make_dnscheck_observations,
    consume_chained_observations,
)
from oonidata.dataformat import load_measurement
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
    db: DatabaseConnection, observations: List[ChainedObservation]
) -> None:
    if len(observations) == 0:
        return

    table_name = observations[0].__table_name__
    rows = []
    for obs in observations:
        assert table_name == obs.__table_name__, "inconsistent table name in group"
        rows.append(make_observation_row(obs))
    db.write_rows(table_name, rows)


nettest_make_obs_map = {
    "web_connectivity": make_web_connectivity_observations,
    "dnscheck": make_dnscheck_observations,
    "tor": make_tor_observations,
    "signal": make_signal_observations,
}


def make_observations(
    msmt_dict: Dict,
    netinfodb: NetinfoDB,
    fingerprintdb: FingerprintDB,
):
    msmt = load_measurement(msmt_dict)

    if msmt.test_name in nettest_make_obs_map:
        return consume_chained_observations(
            *nettest_make_obs_map[msmt.test_name](msmt, fingerprintdb, netinfodb)
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

        buf_flush_rate = 1_000
        obs_buffer = []
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
                obs = make_observations(
                    msmt_dict=msmt_dict,
                    netinfodb=netinfodb,
                    fingerprintdb=fingerprintdb,
                )
                if obs:
                    obs_buffer += obs
                if len(obs_buffer) == buf_flush_rate:
                    write_observations_to_db(db, obs_buffer)
                    obs_buffer = []
            except Exception as exc:
                # This is a bit sketchy, we ought to eventually move it to some
                # better logging function
                log.error(f"failed at idx:{idx} {exc}")
                with open(
                    f"bad_msmts-{day.strftime('%Y%m%d')}.jsonl", "ab+"
                ) as out_file:
                    out_file.write(orjson.dumps(msmt_dict))
                    out_file.write(b"\n")
                with open(
                    f"bad_msmts_fail_log-{day.strftime('%Y%m%d')}.txt", "a+"
                ) as out_file:
                    out_file.write(traceback.format_exc())
                    out_file.write("ENDTB----\n")
                if fast_fail:
                    write_observations_to_db(db, obs_buffer)
                    raise exc
        write_observations_to_db(db, obs_buffer)

    return time.monotonic() - t0, day
