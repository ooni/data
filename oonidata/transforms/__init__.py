from oonidata.netinfo import NetinfoDB

from oonidata.transforms.nettests.dnscheck import DNSCheckTransformer
from oonidata.transforms.nettests.signal import SignalTransformer
from oonidata.transforms.nettests.tor import TorTransformer
from oonidata.transforms.nettests.web_connectivity import WebConnectivityTransformer

NETTEST_TRANSFORMERS = {
    "dnscheck": DNSCheckTransformer,
    "signal": SignalTransformer,
    "tor": TorTransformer,
    "web_connectivity": WebConnectivityTransformer,
}


def measurement_to_observations(msmt, netinfodb: NetinfoDB):
    if msmt.test_name in NETTEST_TRANSFORMERS:
        transformer = NETTEST_TRANSFORMERS[msmt.test_name](
            measurement=msmt, netinfodb=netinfodb
        )
        return transformer.make_observations(msmt)
    return [[]]
