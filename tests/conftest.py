import os
from pathlib import Path

import pytest

from oonidata.fingerprints.matcher import FingerprintDB
from oonidata.netinfo import NetinfoDB

FIXTURE_PATH = Path(os.path.dirname(os.path.realpath(__file__))) / "data"
DATA_DIR = FIXTURE_PATH / "datadir"


@pytest.fixture
def fingerprintdb():
    return FingerprintDB(
        datadir=DATA_DIR,
        download=True,
    )


@pytest.fixture
def netinfodb():
    return NetinfoDB(
        datadir=DATA_DIR,
        download=True,
    )
