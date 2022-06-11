import ujson

from base64 import b64decode

from typing import Optional, Tuple, Union, List, Any, Union
from dataclasses import dataclass

from dacite import from_dict

from oonidata.utils import trivial_id


@dataclass
class BinaryData:
    format: str
    data: str


MaybeBinaryData = Union[str, BinaryData, None]
Failure = Optional[str]


def maybe_binary_data_to_bytes(mbd: MaybeBinaryData) -> bytes:
    if isinstance(mbd, BinaryData):
        return b64decode(mbd.data)
    elif isinstance(mbd, str):
        return mbd.encode("utf-8")

    raise Exception("Invalid type")


@dataclass
class Annotations:
    network_type: Optional[str] = "unknown"
    platform: Optional[str] = "unknown"
    origin: Optional[str] = "unknown"


@dataclass
class BaseTestKeys:
    client_resolver: Optional[str]


@dataclass
class BaseMeasurement:
    measurement_uid: Optional[str]

    annotations: Annotations

    input: Union[str, List[str], None]
    report_id: str

    measurement_start_time: str

    probe_asn: str
    probe_network_name: Optional[str]
    probe_cc: str

    resolver_asn: Optional[str]
    resolver_ip: Optional[str]
    resolver_network_name: Optional[str]

    test_name: str
    test_runtime: float

    software_name: str
    software_version: str

    # XXX do we in fact want this to be so lax?
    test_keys: Optional[BaseTestKeys]


# This is not 100% accurate, ideally we would say
# List[Tuple[str, MaybeBinaryData]], yet this doesn't work because we don't have
# tuples in JSON
HeadersList = List[List[Union[str, MaybeBinaryData]]]
HeadersListBytes = List[Tuple[str, bytes]]


@dataclass
class TorInfo:
    is_tor: bool
    exit_ip: Optional[str]
    exit_name: Optional[str]


@dataclass
class HTTPBase:
    body: MaybeBinaryData
    body_bytes: Optional[bytes]
    body_is_truncated: Optional[bool]
    headers: Optional[dict[str, MaybeBinaryData]]
    headers_list: Optional[HeadersList]
    headers_list_bytes: Optional[HeadersListBytes]

    def __post_init__(self):
        if not self.headers_list and self.headers:
            self.headers_list = []
            for k, v in self.headers.items():
                self.headers_list.append([k, v])

        if self.headers_list:
            self.headers_list_bytes = []
            for header_pair in self.headers_list:
                assert len(header_pair) == 2, "Inconsistent header"
                self.headers_list_bytes.append(
                    (header_pair[0], maybe_binary_data_to_bytes(header_pair[1]))
                )

        if self.body:
            self.body_bytes = maybe_binary_data_to_bytes(self.body)


@dataclass
class HTTPRequest(HTTPBase):
    url: str
    method: Optional[str]
    tor: TorInfo
    x_transport: Optional[str] = "tcp"


@dataclass
class HTTPResponse(HTTPBase):
    code: Optional[int]


@dataclass
class HTTPTransaction:
    failure: Failure
    transaction_id: Optional[int]

    request: Optional[HTTPRequest]
    response: Optional[HTTPResponse]

    t: Optional[float]


@dataclass
class DNSAnswer:
    answer_type: str
    asn: Optional[int]
    as_org_name: Optional[str]
    expiration_limit: Optional[str]
    hostname: Optional[str]
    ipv4: Optional[str]
    ipv6: Optional[str]
    minimum_ttl: Optional[str]
    refresh_interval: Optional[str]
    responsible_name: Optional[str]
    retry_interval: Optional[str]
    serial_number: Optional[str]
    ttl: Optional[int]


@dataclass
class DNSQuery:
    dial_id: Optional[int]
    engine: Optional[str]
    failure: Failure
    hostname: Optional[str]
    query_type: str

    # XXX: Map resolver_hostname and resolver_port to this
    resolver_address: Optional[str]
    t: Optional[float]
    transaction_id: Optional[int]

    answers: Optional[List[DNSAnswer]]


@dataclass
class TCPConnectStatus:
    blocked: Optional[bool]
    success: bool
    failure: Failure


@dataclass
class TCPConnect:
    ip: str
    port: int
    status: TCPConnectStatus

    t: Optional[float]


@dataclass
class TLSHandshake:
    address: Optional[str]
    cipher_suite: Optional[str]
    failure: Failure
    negotiated_protocol: Optional[str]
    no_tls_verify: Optional[bool]
    peer_certificates: Optional[List[BinaryData]]
    server_name: Optional[str]
    t: Optional[float]
    tags: Optional[List[str]]
    tls_version: Optional[str]
    transaction_id: Optional[int]


@dataclass
class NetworkEvent:
    address: Optional[str]
    conn_id: Optional[int]
    dial_id: Optional[int]
    failure: Failure
    num_bytes: Optional[int]
    operation: str
    proto: Optional[str]
    t: float
    tags: Optional[List[str]]
    transaction_id: Optional[str]


@dataclass
class WebConnectivityControlHTTPRequest:
    body_length: Optional[int]
    failure: Failure
    title: Optional[str]
    headers: Optional[dict[str, str]]
    status_code: Optional[int]


@dataclass
class WebConnectivityControlDNS:
    failure: Failure
    addrs: Optional[List[str]]


@dataclass
class WebConnectivityControlTCPConnectStatus:
    status: Optional[bool]
    failure: Failure


@dataclass
class WebConnectivityControl:
    tcp_connect: Optional[dict[str, WebConnectivityControlTCPConnectStatus]]
    http_request: Optional[WebConnectivityControlHTTPRequest]
    dns: Optional[WebConnectivityControlDNS]


@dataclass
class WebConnectivityTestKeys(BaseTestKeys):
    dns_experiment_failure: Failure
    control_failure: Failure
    http_experiment_failure: Failure

    dns_consistency: Optional[str]

    body_length_match: Optional[bool]
    body_proportion: Optional[float]
    status_code_match: Optional[bool]
    headers_match: Optional[bool]
    title_match: Optional[bool]
    accessible: Optional[bool]
    blocking: Union[str, bool, None]

    x_status: Optional[int]
    x_dns_runtime: Optional[int]
    x_th_runtime: Optional[int]
    x_tcptls_runtime: Optional[int]
    x_http_runtime: Optional[int]

    control: Optional[WebConnectivityControl]
    tls_handshakes: Optional[List[TLSHandshake]]
    network_events: Optional[List[NetworkEvent]]
    queries: Optional[List[DNSQuery]]
    tcp_connect: Optional[List[TCPConnect]]
    requests: Optional[List[HTTPTransaction]]


@dataclass
class WebConnectivity(BaseMeasurement):
    test_keys: Optional[WebConnectivityTestKeys]


@dataclass
class TorTestTarget:
    failure: Failure
    network_events: Optional[List[NetworkEvent]]
    queries: Optional[List[DNSQuery]]
    requests: Optional[List[HTTPTransaction]]
    tls_handshakes: Optional[List[TLSHandshake]]
    tcp_connect: Optional[List[TCPConnect]]

    target_address: str
    target_name: str
    target_protocol: str


@dataclass
class TorTestKeys:
    targets: dict[str, TorTestTarget]


@dataclass
class Tor(BaseMeasurement):
    test_keys: Optional[TorTestKeys]


nettest_dataformats = {"web_connectivity": WebConnectivity, "tor": Tor}


def load_measurement(raw: bytes) -> BaseMeasurement:
    data = ujson.loads(raw)
    dc = nettest_dataformats.get(data["test_name"], BaseMeasurement)
    msm = from_dict(data_class=dc, data=data)
    if not msm.measurement_uid:
        msm.measurement_uid = trivial_id(raw=raw, msm=msm)
    return msm
