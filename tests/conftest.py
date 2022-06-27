import pytest

from oonidata.fingerprints.matcher import FingerprintDB
from oonidata.netinfo import NetinfoDB

@pytest.fixture
def fingerprintdb():
    return FingerprintDB()

@pytest.fixture
def netinfodb():
    return NetinfoDB()
