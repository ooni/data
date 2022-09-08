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
        datadir=FIXTURE_PATH / "historical-geoip" / "country-asn-databases",
        as_org_map_path=FIXTURE_PATH / "historical-geoip" / "as-orgs" / "all_as_org_map.json"
    )