from typing import List, Optional, Tuple, Union, overload
from datetime import datetime, timezone

from oonidata.models.observations import (
    HTTPMiddleboxObservation,
    WebControlObservation,
    WebObservation,
    OpenVPNObservation
)

from oonidata.models.nettests import (
    Signal,
    SupportedDataformats,
    Whatsapp,
    Telegram,
    StunReachability,
    Tor,
    FacebookMessenger,
    HTTPHeaderFieldManipulation,
    UrlGetter,
    WebConnectivity,
    HTTPInvalidRequestLine,
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
from .nettests.openvpn import OpenVPNTransformer
from .nettests.http_invalid_request_line import (
    HTTPInvalidRequestLineTransformer,
)
from .nettests.echcheck import ECHCheckTransformer

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
    "openvpn": OpenVPNTransformer,
    "echcheck": ECHCheckTransformer,
}

TypeWebConnectivityObservations = Tuple[
    List[WebObservation], List[WebControlObservation]
]
TypeWebObservations = Tuple[List[WebObservation]]
TypeOpenVPNObservations = Tuple[List[OpenVPNObservation]]
TypeHTTPMiddleboxObservations = Tuple[List[HTTPMiddleboxObservation]]


@overload
def measurement_to_observations(
    msmt: Union[HTTPHeaderFieldManipulation, HTTPInvalidRequestLine],
    netinfodb: NetinfoDB,
    bucket_date: str = "1984-01-01",
) -> TypeHTTPMiddleboxObservations: ...


@overload
def measurement_to_observations(
    msmt: WebConnectivity,
    netinfodb: NetinfoDB,
    bucket_date: str = "1984-01-01",
) -> TypeWebConnectivityObservations: ...


@overload
def measurement_to_observations(
    msmt: Union[
        Signal, Whatsapp, Telegram, StunReachability, Tor, FacebookMessenger, UrlGetter
    ],
    netinfodb: NetinfoDB,
    bucket_date: str = "1984-01-01",
) -> TypeWebObservations: ...


@overload
def measurement_to_observations(
    msmt: SupportedDataformats,
    netinfodb: NetinfoDB,
    bucket_date: str = "1984-01-01",
) -> TypeWebObservations: ...


def measurement_to_observations(
    msmt,
    netinfodb: NetinfoDB,
    # the bucket_date should be set for all the workflows that deal with ingesting data,
    # but it's not strictly needed. We use the special value of 1984-01-01
    # to signal that the bucket is unknown.
    bucket_date: str = "1984-01-01",
) -> Union[
    TypeWebObservations,
    TypeWebConnectivityObservations,
    TypeHTTPMiddleboxObservations,
    TypeOpenVPNObservations,
    Tuple[()],
]:
    if msmt.test_name in NETTEST_TRANSFORMERS:
        transformer = NETTEST_TRANSFORMERS[msmt.test_name](
            measurement=msmt, netinfodb=netinfodb, bucket_date=bucket_date
        )
        return transformer.make_observations(msmt)
    return ()
