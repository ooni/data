import os
from pathlib import Path
from datetime import date, datetime
import shutil
from click.testing import CliRunner

import pytest

import orjson

from oonidata.dataclient import sync_measurements, create_s3_client
from oonidata.apiclient import get_measurement_dict_by_uid

from ._fixtures import SAMPLE_MEASUREMENTS, SAMPLE_POSTCANS, SAMPLE_JSONLGZS

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


def download_from_s3(name, dst_path):
    s3_client = create_s3_client()
    # 2024030100_AM_webconnectivity.n1.0.tar.gz
    # s3://ooni-data-eu-fra/raw/20240301/raw/20240301/00/AM/webconnectivity/2024030100_AM_webconnectivity.n1.0.tar.gz
    p = name.split("_")
    cc = p[1]
    testname = p[2].split(".")[0]
    dt = datetime.strptime(p[0], "%Y%m%d%H")
    day_ts = dt.strftime("%Y%m%d")
    hour_ts = dt.strftime("%H")
    key = f"raw/{day_ts}/{hour_ts}/{cc}/{testname}/{name}"

    try:
        shutil.copyfileobj(
            s3_client.get_object(Bucket="ooni-data-eu-fra", Key=key)["Body"],
            dst_path.open("wb"),
        )
    except:
        raise Exception(f"failed to download {name} from {key}")


def make_samples(sample_name, sample_list):
    dir = FIXTURE_PATH / sample_name
    dir.mkdir(parents=True, exist_ok=True)

    samples = {}
    for name in sample_list:
        sample_path = dir / name
        if not sample_path.exists():
            download_from_s3(name, dir / name)

        samples[name] = dir / name

    return samples


@pytest.fixture
def postcans():
    return make_samples("postcans", SAMPLE_POSTCANS)


@pytest.fixture
def jsonlgzs():
    return make_samples("jsonlgzs", SAMPLE_JSONLGZS)


@pytest.fixture
def measurements():
    measurement_dir = FIXTURE_PATH / "measurements"
    measurement_dir.mkdir(parents=True, exist_ok=True)

    sample_measurements = {}
    for msmt_uid in SAMPLE_MEASUREMENTS:
        sample_measurements[msmt_uid] = measurement_dir / f"{msmt_uid}.json"
        if sample_measurements[msmt_uid].exists():
            continue
        msmt = get_measurement_dict_by_uid(msmt_uid)
        with sample_measurements[msmt_uid].open("wb") as out_file:
            out_file.write(orjson.dumps(msmt))
    return sample_measurements
