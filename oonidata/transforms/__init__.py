from oonidata.netinfo import NetinfoDB

from oonidata.transforms.nettests.dnscheck import DNSCheckTransformer
from oonidata.transforms.nettests.http_header_field_manipulation import (
    HTTPHeaderFieldManipulationTransformer,
)
from oonidata.transforms.nettests.signal import SignalTransformer
from oonidata.transforms.nettests.telegram import TelegramTransformer
from oonidata.transforms.nettests.stun_reachability import StunReachabilityTransformer
from oonidata.transforms.nettests.tor import TorTransformer
from oonidata.transforms.nettests.browser_web import BrowserWebTransformer
from oonidata.transforms.nettests.urlgetter import UrlGetterTransformer
from oonidata.transforms.nettests.web_connectivity import WebConnectivityTransformer
from oonidata.transforms.nettests.http_invalid_request_line import (
    HTTPInvalidRequestLineTransformer,
)

NETTEST_TRANSFORMERS = {
    "dnscheck": DNSCheckTransformer,
    "signal": SignalTransformer,
    "telegram": TelegramTransformer,
    "stun_reachability": StunReachabilityTransformer,
    "tor": TorTransformer,
    "browser_web": BrowserWebTransformer,
    "urlgetter": UrlGetterTransformer,
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
