import os
from pathlib import Path
from datetime import date
from click.testing import CliRunner

import pytest

import orjson
from oonidata.db.connections import ClickhouseConnection

from oonidata.fingerprintdb import FingerprintDB
from oonidata.netinfo import NetinfoDB
from oonidata.dataclient import sync_measurements
from oonidata.apiclient import get_measurement_dict_by_uid

from ._sample_measurements import SAMPLE_MEASUREMENTS

FIXTURE_PATH = Path(os.path.dirname(os.path.realpath(__file__))) / "data"
DATA_DIR = FIXTURE_PATH / "datadir"


@pytest.fixture
def datadir():
    return DATA_DIR


@pytest.fixture
def fingerprintdb(datadir):
    return FingerprintDB(
        datadir=datadir,
        download=True,
    )


@pytest.fixture
def netinfodb():
    return NetinfoDB(
        datadir=DATA_DIR,
        download=True,
    )


@pytest.fixture
def raw_measurements():
    output_dir = FIXTURE_PATH / "raw_measurements"
    if (output_dir / "signal" / "2022-10-01").exists():
        return output_dir
    sync_measurements(
        output_dir=output_dir,
        probe_cc=["IT"],
        test_name=["web_connectivity", "signal"],
        start_day=date(2022, 10, 1),
        end_day=date(2022, 10, 2),
    )
    return output_dir


@pytest.fixture
def measurements():
    measurement_dir = FIXTURE_PATH / "measurements"
    measurement_dir.mkdir(parents=True, exist_ok=True)

    sampled_measurements = {}
    for msmt_uid in SAMPLE_MEASUREMENTS:
        sampled_measurements[msmt_uid] = measurement_dir / f"{msmt_uid}.json"
        if sampled_measurements[msmt_uid].exists():
            continue
        msmt = get_measurement_dict_by_uid(msmt_uid)
        with sampled_measurements[msmt_uid].open("wb") as out_file:
            out_file.write(orjson.dumps(msmt))
    return sampled_measurements


@pytest.fixture
def cli_runner():
    return CliRunner()


from oonidata.db.create_tables import create_queries


def create_db_for_fixture():
    try:
        with ClickhouseConnection(conn_url="clickhouse://localhost/") as db:
            db.execute("CREATE DATABASE IF NOT EXISTS testing_oonidata")
    except:
        pytest.skip("no database connection")

    db = ClickhouseConnection(conn_url="clickhouse://localhost/testing_oonidata")
    try:
        db.execute("SELECT 1")
    except:
        pytest.skip("no database connection")
    for query, _ in create_queries:
        db.execute(query)
    return db


@pytest.fixture
def db_notruncate():
    return create_db_for_fixture()


@pytest.fixture
def db():
    db = create_db_for_fixture()
    for _, table_name in create_queries:
        db.execute(f"TRUNCATE TABLE {table_name};")
    return db
