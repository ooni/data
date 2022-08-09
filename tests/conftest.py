import os
from pathlib import Path

import pytest

from oonidata.fingerprints.matcher import FingerprintDB
from oonidata.netinfo import NetinfoDB

FIXTURE_PATH = Path(os.path.dirname(os.path.realpath(__file__))) / "data"

@pytest.fixture
def fingerprintdb():
    return FingerprintDB()

@pytest.fixture
def netinfodb():
    return NetinfoDB(
        datadir=FIXTURE_PATH / "geoip",
        as_org_map_path=FIXTURE_PATH / "all_as_org_map.json"
    )