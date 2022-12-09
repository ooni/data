from typing import Union
import typing

from .base_measurement import BaseMeasurement
from .dnscheck import DNSCheck
from .signal import Signal
from .tor import Tor
from .web_connectivity import WebConnectivity
from .whatsapp import Whatsapp

SupportedDataformats = Union[
    WebConnectivity, Tor, DNSCheck, Signal, Whatsapp, BaseMeasurement
]
NETTEST_MODELS = {
    nettest_class.__test_name__: nettest_class
    for nettest_class in typing.get_args(SupportedDataformats)
}
