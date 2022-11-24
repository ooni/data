import os
from pathlib import Path
from datetime import date
from click.testing import CliRunner

import pytest

import orjson

from oonidata.fingerprintdb import FingerprintDB
from oonidata.netinfo import NetinfoDB
from oonidata.dataclient import sync_measurements
from oonidata.apiclient import get_measurement_dict, get_raw_measurement

FIXTURE_PATH = (
    Path(os.path.dirname(os.path.realpath(__file__))) / ".." / "tests" / "data"
)
DATA_DIR = FIXTURE_PATH / "datadir"


@pytest.fixture(scope="session")
def datadir():
    return DATA_DIR


@pytest.fixture(scope="session")
def fingerprintdb(datadir):
    return FingerprintDB(
        datadir=datadir,
        download=True,
    )


@pytest.fixture(scope="session")
def netinfodb():
    return NetinfoDB(
        datadir=DATA_DIR,
        download=True,
    )


@pytest.fixture(scope="session")
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
def cli_runner():
    return CliRunner()
