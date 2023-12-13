from typing import Union

from .base_measurement import BaseMeasurement
from .dnscheck import DNSCheck
from .signal import Signal
from .facebook_messenger import FacebookMessenger
from .telegram import Telegram
from .tor import Tor
from .web_connectivity import WebConnectivity
from .whatsapp import Whatsapp
from .http_invalid_request_line import HTTPInvalidRequestLine
from .http_header_field_manipulation import HTTPHeaderFieldManipulation

SUPPORTED_CLASSES = [
    HTTPHeaderFieldManipulation,
    HTTPInvalidRequestLine,
    WebConnectivity,
    Telegram,
    Tor,
    DNSCheck,
    Signal,
    FacebookMessenger,
    Whatsapp,
    BaseMeasurement,
]
SupportedDataformats = Union[
    HTTPHeaderFieldManipulation,
    HTTPInvalidRequestLine,
    WebConnectivity,
    Telegram,
    Tor,
    DNSCheck,
    Signal,
    FacebookMessenger,
    Whatsapp,
    BaseMeasurement,
]

NETTEST_MODELS = {
    nettest_class.__test_name__: nettest_class for nettest_class in SUPPORTED_CLASSES
}
