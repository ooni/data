from dataclasses import dataclass
from typing import List, Optional

from ..base import BaseModel

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
    success: Optional[bool] = False
    failure: Failure = None

    network_events: Optional[List[OpenVPNNetworkEvent]] = None
    tcp_connect: Optional[List[TCPConnect]] = None
    openvpn_handshake: Optional[List[OpenVPNHandshake]] = None

    bootstrap_time: Optional[float] = None
    tunnel: str = None


@add_slots
@dataclass
class OpenVPN(BaseMeasurement):
    __test_name__ = "openvpn"

    test_keys: OpenVPNTestKeys
