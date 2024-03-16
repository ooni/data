import os
from pathlib import Path
from datetime import date
from click.testing import CliRunner

import pytest

import orjson

from oonidata.dataclient import sync_measurements
from oonidata.apiclient import get_measurement_dict_by_uid

from ._sample_measurements import SAMPLE_MEASUREMENTS

FIXTURE_PATH = Path(os.path.dirname(os.path.realpath(__file__))) / "data"
DATA_DIR = FIXTURE_PATH / "datadir"


@pytest.fixture
def datadir():
    return DATA_DIR


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
def measurements(should_download=False):
    measurement_dir = FIXTURE_PATH / "measurements"
    measurement_dir.mkdir(parents=True, exist_ok=True)

    sampled_measurements = {}
    for msmt_uid in SAMPLE_MEASUREMENTS:
        sampled_measurements[msmt_uid] = measurement_dir / f"{msmt_uid}.json"
        if sampled_measurements[msmt_uid].exists() or not should_download:
            continue
        msmt = get_measurement_dict_by_uid(msmt_uid)
        with sampled_measurements[msmt_uid].open("wb") as out_file:
            out_file.write(orjson.dumps(msmt))
    return sampled_measurements


@pytest.fixture
def cli_runner():
    return CliRunner()
