from unittest.mock import MagicMock
from oonidata.dataformat import (
    load_measurement,
)
from oonidata.observations import (
    make_dnscheck_observations,
    make_web_connectivity_observations,
)


def test_benchmark_web_connectivity(benchmark, measurements, netinfodb):
    db = MagicMock()
    db.write_row = MagicMock()

    msmt = load_measurement(
        msmt_path=measurements[
            "20220627131742.081225_GB_webconnectivity_e1e2cf4db492b748"
        ]
    )
    benchmark(
        make_web_connectivity_observations,
        msmt=msmt,
        netinfodb=netinfodb,
    )


def test_benchmark_dnscheck(benchmark, measurements, netinfodb):
    db = MagicMock()
    db.write_row = MagicMock()

    msmt = load_measurement(
        msmt_path=measurements["20221013000000.517636_US_dnscheck_bfd6d991e70afa0e"]
    )
    benchmark(
        make_dnscheck_observations,
        msmt=msmt,
        netinfodb=netinfodb,
    )
