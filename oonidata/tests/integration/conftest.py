import os
from pathlib import Path
from datetime import date
from click.testing import CliRunner

import pytest

import orjson

from oonidata.dataclient import sync_measurements
from oonidata.apiclient import get_measurement_dict_by_uid

FIXTURE_PATH = Path(os.path.dirname(os.path.realpath(__file__))) / "data"
DATA_DIR = FIXTURE_PATH / "datadir"


@pytest.fixture
def datadir():
    return DATA_DIR


@pytest.fixture
def cli_runner():
    return CliRunner()
