from datetime import datetime, timezone
from typing import List, Optional, Tuple, Union

from oonidata.models.observations import (
    HTTPMiddleboxObservation,
    WebControlObservation,
    WebObservation,
)
from .nettests.dnscheck import DNSCheckTransformer
from .nettests.http_header_field_manipulation import (
    HTTPHeaderFieldManipulationTransformer,
)
from .nettests.signal import SignalTransformer
from .nettests.facebook_messenger import FacebookMessengerTransformer
from .nettests.whatsapp import WhatsappTransformer
from .nettests.telegram import TelegramTransformer
from .nettests.stun_reachability import StunReachabilityTransformer
from .nettests.tor import TorTransformer
from .nettests.browser_web import BrowserWebTransformer
from .nettests.urlgetter import UrlGetterTransformer
from .nettests.web_connectivity import WebConnectivityTransformer
from .nettests.http_invalid_request_line import (
    HTTPInvalidRequestLineTransformer,
)

from ..netinfo import NetinfoDB

NETTEST_TRANSFORMERS = {
    "dnscheck": DNSCheckTransformer,
    "signal": SignalTransformer,
    "facebook_messenger": FacebookMessengerTransformer,
    "whatsapp": WhatsappTransformer,
    "telegram": TelegramTransformer,
    "stunreachability": StunReachabilityTransformer,
    "tor": TorTransformer,
    "browser_web": BrowserWebTransformer,
    "urlgetter": UrlGetterTransformer,
    "http_header_field_manipulation": HTTPHeaderFieldManipulationTransformer,
    "http_invalid_request_line": HTTPInvalidRequestLineTransformer,
    "web_connectivity": WebConnectivityTransformer,
}

TypeWebConnectivityObservations = Tuple[
    List[WebObservation], List[WebControlObservation]
]
TypeWebObservations = Tuple[List[WebObservation]]
TypeHTTPMiddleboxObservations = Tuple[List[HTTPMiddleboxObservation]]


def measurement_to_observations(
    msmt,
    netinfodb: NetinfoDB,
    bucket_datetime: datetime = datetime(1984, 1, 1, tzinfo=timezone.utc),
) -> Union[
    TypeWebObservations,
    TypeWebConnectivityObservations,
    TypeHTTPMiddleboxObservations,
    Tuple[(None,)],
]:
    if msmt.test_name in NETTEST_TRANSFORMERS:
        transformer = NETTEST_TRANSFORMERS[msmt.test_name](
            measurement=msmt, netinfodb=netinfodb, bucket_datetime=bucket_datetime
        )
        return transformer.make_observations(msmt)
    return (None,)
