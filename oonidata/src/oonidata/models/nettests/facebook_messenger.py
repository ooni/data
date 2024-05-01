from dataclasses import dataclass
from typing import List, Optional

from ...compat import add_slots

from ..base import BaseModel
from ..dataformats import (
    TCPConnect,
    DNSQuery
)

from .base_measurement import BaseMeasurement


@add_slots
@dataclass
class FacebookMessengerTestKeys(BaseModel):
    facebook_b_api_dns_consistent: Optional[bool] = None
    facebook_b_api_reachable: Optional[bool] = None
    facebook_b_graph_dns_consistent: Optional[bool] = None
    facebook_b_graph_reachable: Optional[bool] = None
    facebook_dns_blocking: Optional[bool] = None
    facebook_edge_dns_consistent: Optional[bool] = None
    facebook_edge_reachable: Optional[bool] = None
    facebook_external_cdn_dns_consistent: Optional[bool] = None
    facebook_external_cdn_reachable: Optional[bool] = None
    facebook_scontent_cdn_dns_consistent: Optional[bool] = None
    facebook_scontent_cdn_reachable: Optional[bool] = None
    facebook_star_dns_consistent: Optional[bool] = None
    facebook_star_reachable: Optional[bool] = None
    facebook_stun_dns_consistent: Optional[bool] = None
    facebook_stun_reachable: Optional[bool] = None
    facebook_tcp_blocking: Optional[bool] = None

    socksproxy: Optional[str] = None
    tcp_connect: Optional[List[TCPConnect]] = None
    queries: Optional[List[DNSQuery]] = None


@add_slots
@dataclass
class FacebookMessenger(BaseMeasurement):
    __test_name__ = "facebook_messenger"

    test_keys: FacebookMessengerTestKeys
