from oonidata.netinfo import NetinfoDB

from oonidata.transforms.nettests.dnscheck import DNSCheckTransformer
from oonidata.transforms.nettests.facebook_messenger import FacebookMessengerTransformer
from oonidata.transforms.nettests.http_header_field_manipulation import (
    HTTPHeaderFieldManipulationTransformer,
)
from oonidata.transforms.nettests.signal import SignalTransformer
from oonidata.transforms.nettests.telegram import TelegramTransformer
from oonidata.transforms.nettests.tor import TorTransformer
from oonidata.transforms.nettests.psiphon import PsiphonTransformer
from oonidata.transforms.nettests.vanilla_tor import VanillaTorTransformer
from oonidata.transforms.nettests.web_connectivity import WebConnectivityTransformer
from oonidata.transforms.nettests.http_invalid_request_line import (
    HTTPInvalidRequestLineTransformer,
)

NETTEST_TRANSFORMERS = {
    "dnscheck": DNSCheckTransformer,
    "facebook_messenger": FacebookMessengerTransformer,
    "signal": SignalTransformer,
    "telegram": TelegramTransformer,
    "tor": TorTransformer,
    "psiphon": PsiphonTransformer,
    "vanilla_tor": VanillaTorTransformer, 
    "http_header_field_manipulation": HTTPHeaderFieldManipulationTransformer,
    "http_invalid_request_line": HTTPInvalidRequestLineTransformer,
    "web_connectivity": WebConnectivityTransformer,
}


def measurement_to_observations(msmt, netinfodb: NetinfoDB):
    if msmt.test_name in NETTEST_TRANSFORMERS:
        transformer = NETTEST_TRANSFORMERS[msmt.test_name](
            measurement=msmt, netinfodb=netinfodb
        )
        return transformer.make_observations(msmt)
    return [[]]
