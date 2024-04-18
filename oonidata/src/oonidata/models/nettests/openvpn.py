from dataclasses import dataclass
from typing import List, Optional
from oonidata.compat import add_slots
from oonidata.models.dataformats import (
    BaseTestKeys,
    Failure,
    TCPConnect,
    OpenVPNHandshake,
    OpenVPNNetworkEvent,
)
from oonidata.models.nettests.base_measurement import BaseMeasurement


@add_slots
@dataclass
class OpenVPNTestKeys(BaseTestKeys):
    failure: Failure = None
    success: Optional[bool] = False

    network_events: Optional[List[OpenVPNNetworkEvent]] = None
    openvpn_handshake: Optional[List[OpenVPNHandshake]] = None
    tcp_connect: Optional[List[TCPConnect]] = None


@add_slots
@dataclass
class OpenVPN(BaseMeasurement):
    __test_name__ = "openvpn"

    test_keys: OpenVPNTestKeys
