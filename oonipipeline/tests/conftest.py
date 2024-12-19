from multiprocessing import Process
import os
from pathlib import Path
from datetime import date

import pytest

import orjson

from click.testing import CliRunner
from clickhouse_driver import Client as ClickhouseClient

from oonidata.dataclient import sync_measurements
from oonidata.apiclient import get_measurement_dict_by_uid

from oonipipeline.db.connections import ClickhouseConnection
from oonipipeline.db.create_tables import make_create_queries
from oonipipeline.fingerprintdb import FingerprintDB
from oonipipeline.netinfo import NetinfoDB
from oonipipeline.settings import config

from ._fixtures import SAMPLE_MEASUREMENTS

FIXTURE_PATH = Path(os.path.dirname(os.path.realpath(__file__))) / "data"
DATA_DIR = FIXTURE_PATH / "datadir"


def is_clickhouse_running(url):
    try:
        with ClickhouseClient.from_url(url) as client:
            client.execute("SELECT 1")
        return True
    except Exception:
        return False


@pytest.fixture(scope="session")
def clickhouse_server(docker_ip, docker_services):
    """Ensure that HTTP service is up and responsive."""
    port = docker_services.port_for("clickhouse", 9000)
    url = "clickhouse://{}:{}/default".format(docker_ip, port)
    docker_services.wait_until_responsive(
        timeout=30.0, pause=0.1, check=lambda: is_clickhouse_running(url)
    )
    yield url


@pytest.fixture
def datadir():
    config.data_dir = str(DATA_DIR)
    return DATA_DIR


@pytest.fixture
def fingerprintdb(datadir):
    return FingerprintDB(
        datadir=datadir,
        download=True,
    )


@pytest.fixture
def netinfodb():
    return NetinfoDB(datadir=DATA_DIR, download=True, max_age_seconds=60 * 60 * 24)


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


def create_db_for_fixture(conn_url):
    try:
        with ClickhouseConnection(conn_url=conn_url) as db:
            db.execute("CREATE DATABASE IF NOT EXISTS testing_oonidata")
    except:
        pytest.skip("no database connection")

    db = ClickhouseConnection(
        conn_url=conn_url.replace("default", "testing_oonidata"), max_backoff=0.2
    )
    try:
        db.execute("SELECT 1")
    except:
        pytest.skip("no database connection")
    for query, _ in make_create_queries():
        db.execute(query)
    return db


@pytest.fixture
def db_notruncate(clickhouse_server):
    yield create_db_for_fixture(clickhouse_server)


@pytest.fixture
def db(clickhouse_server):
    db = create_db_for_fixture(clickhouse_server)
    for _, table_name in make_create_queries():
        # Ignore the fingerprints_dns table, since it's a remote table
        if table_name == "fingerprints_dns":
            continue
        db.execute(f"TRUNCATE TABLE {table_name};")

    config.clickhouse_url = db.clickhouse_url
    yield db
