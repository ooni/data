from dataclasses import dataclass
from typing import Dict, List, Literal, Optional, Union

from ...compat import add_slots

from ..base import BaseModel
from ..dataformats import (
    BaseTestKeys,
    DNSQuery,
    Failure,
    HTTPTransaction,
    MaybeBinaryData,
    NetworkEvent,
    TCPConnect,
    TLSHandshake,
)
from ..nettests.base_measurement import BaseMeasurement


@add_slots
@dataclass
class WebConnectivityControlHTTPRequest(BaseModel):
    body_length: Optional[int] = None
    failure: Failure = None
    title: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    status_code: Optional[int] = None


@add_slots
@dataclass
class WebConnectivityControlDNS(BaseModel):
    failure: Failure = None
    addrs: Optional[List[str]] = None


@add_slots
@dataclass
class WebConnectivityControlTCPConnectStatus(BaseModel):
    status: Optional[bool] = None
    failure: Failure = None


@add_slots
@dataclass
class WebConnectivityControlTLSStatus(BaseModel):
    status: Optional[bool] = None
    failure: Failure = None
    server_name: Optional[str] = None


@add_slots
@dataclass
class WebConnectivityControl(BaseModel):
    tcp_connect: Optional[Dict[str, WebConnectivityControlTCPConnectStatus]] = None
    http_request: Optional[WebConnectivityControlHTTPRequest] = None
    dns: Optional[WebConnectivityControlDNS] = None
    tls_handshake: Optional[Dict[str, WebConnectivityControlTLSStatus]] = None


@add_slots
@dataclass
class WebConnectivityTestKeys(BaseModel):
    dns_experiment_failure: Failure = None
    control_failure: Failure = None
    http_experiment_failure: Failure = None

    dns_consistency: Optional[str] = None

    body_length_match: Optional[bool] = None
    body_proportion: Optional[float] = None
    status_code_match: Optional[bool] = None
    headers_match: Optional[bool] = None
    title_match: Optional[bool] = None
    accessible: Optional[bool] = None
    blocking: Union[str, Literal[False], None] = None

    control: Optional[WebConnectivityControl] = None
    tls_handshakes: Optional[List[TLSHandshake]] = None
    network_events: Optional[List[NetworkEvent]] = None
    queries: Optional[List[DNSQuery]] = None
    tcp_connect: Optional[List[TCPConnect]] = None
    requests: Optional[List[HTTPTransaction]] = None

    x_status: Optional[int] = None
    x_dns_runtime: Optional[int] = None
    x_th_runtime: Optional[int] = None
    x_tcptls_runtime: Optional[int] = None
    x_http_runtime: Optional[int] = None

    client_resolver: Optional[str] = None

    retries: Optional[int] = None
    socksproxy: Optional[str] = None


@add_slots
@dataclass
class WebConnectivity(BaseMeasurement):
    __test_name__ = "web_connectivity"

    test_keys: WebConnectivityTestKeys


@add_slots
@dataclass
class TCPTTestKeys(BaseTestKeys):
    received: Optional[List[MaybeBinaryData]] = None
    sent: Optional[List[MaybeBinaryData]] = None
