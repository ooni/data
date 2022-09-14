"""
OONI data format.

See:

- https://github.com/ooni/spec/tree/master/data-formats

- https://github.com/ooni/spec/tree/master/nettests
"""
import logging
import ujson

from base64 import b64decode

from typing import Optional, Tuple, Union, List, Union
from dataclasses import dataclass

from dacite.core import from_dict

from oonidata.utils import trivial_id

log = logging.getLogger("oonidata.dataformat")


class BaseModel:
    pass


@dataclass
class BinaryData(BaseModel):
    format: str
    data: str


MaybeBinaryData = Union[str, BinaryData, None]
Failure = Optional[str]


def guess_decode(s: bytes) -> str:
    """
    best effort decoding of a string of bytes
    """
    for encoding in ("ascii", "utf-8", "latin1"):
        try:
            return s.decode(encoding)
        except UnicodeDecodeError:
            pass
    log.warning(f"unable to decode '{s}'")
    return s.decode("ascii", "ignore")


def maybe_binary_data_to_bytes(mbd: Union[MaybeBinaryData, dict]) -> bytes:
    if isinstance(mbd, BinaryData):
        return b64decode(mbd.data)
    elif isinstance(mbd, dict):
        return b64decode(mbd["data"])
    elif isinstance(mbd, str):
        return mbd.encode("utf-8")

    raise Exception(f"Invalid type {type(mbd)} {mbd}")


@dataclass
class BaseTestKeys(BaseModel):
    client_resolver: Optional[str]


@dataclass
class BaseMeasurement(BaseModel):
    annotations: dict[str, str]

    input: Union[str, List[str], None]
    report_id: str

    measurement_start_time: str
    test_start_time: str

    probe_asn: str
    probe_network_name: Optional[str]
    probe_cc: str
    probe_ip: Optional[str]

    resolver_asn: Optional[str]
    resolver_ip: Optional[str]
    resolver_network_name: Optional[str]

    test_name: str
    test_version: str
    test_runtime: float

    software_name: str
    software_version: str

    test_helpers: Optional[dict]
    test_keys: BaseTestKeys
    data_format_version: Optional[str] = None
    measurement_uid: Optional[str] = None


# This is not 100% accurate, ideally we would say
# List[Tuple[str, MaybeBinaryData]], yet this doesn't work because we don't have
# tuples in JSON
HeadersList = List[List[Union[str, MaybeBinaryData]]]
HeadersListBytes = List[Tuple[str, bytes]]


@dataclass
class TorInfo(BaseModel):
    is_tor: bool
    exit_ip: Optional[str]
    exit_name: Optional[str]


@dataclass
class HTTPBase(BaseModel):
    body: MaybeBinaryData
    body_is_truncated: Optional[bool] = None
    headers: Optional[dict[str, MaybeBinaryData]] = None
    headers_list: Optional[HeadersList] = None
    headers_list_bytes: Optional[HeadersListBytes] = None

    body_bytes: Optional[bytes] = None

    def __post_init__(self):
        if not self.headers_list and self.headers:
            self.headers_list = []
            for k, v in self.headers.items():
                self.headers_list.append([k, v])

        if self.headers_list:
            self.headers_list_bytes = []
            for header_pair in self.headers_list:
                assert len(header_pair) == 2, "Inconsistent header"
                header_name = guess_decode(maybe_binary_data_to_bytes(header_pair[0]))
                header_value = maybe_binary_data_to_bytes(header_pair[1])
                self.headers_list_bytes.append((header_name, header_value))

        if self.body:
            self.body_bytes = maybe_binary_data_to_bytes(self.body)


@dataclass
class HTTPRequest(HTTPBase):
    url: str = ""
    method: Optional[str] = None
    tor: Optional[TorInfo] = None
    x_transport: Optional[str] = "tcp"


@dataclass
class HTTPResponse(HTTPBase):
    code: Optional[int] = None


@dataclass
class HTTPTransaction(BaseModel):
    failure: Failure

    request: Optional[HTTPRequest]
    response: Optional[HTTPResponse]

    t: Optional[float]
    transaction_id: Optional[int] = None


@dataclass
class DNSAnswer(BaseModel):
    answer_type: str
    asn: Optional[int] = None
    as_org_name: Optional[str] = None
    expiration_limit: Optional[str] = None
    hostname: Optional[str] = None
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    minimum_ttl: Optional[str] = None
    refresh_interval: Optional[str] = None
    responsible_name: Optional[str] = None
    retry_interval: Optional[str] = None
    serial_number: Optional[str] = None
    ttl: Optional[int] = None


@dataclass
class DNSQuery(BaseModel):
    failure: Failure
    hostname: str
    query_type: str

    dial_id: Optional[int] = None
    engine: Optional[str] = None

    # XXX: Map resolver_hostname and resolver_port to this
    resolver_address: Optional[str] = None
    t: Optional[float] = None
    transaction_id: Optional[int] = None

    answers: Optional[List[DNSAnswer]] = None


@dataclass
class TCPConnectStatus(BaseModel):
    blocked: Optional[bool]
    success: bool
    failure: Failure


@dataclass
class TCPConnect(BaseModel):
    ip: str
    port: int
    status: TCPConnectStatus

    t: Optional[float]


@dataclass
class TLSHandshake(BaseModel):
    failure: Failure
    peer_certificates: Optional[List[BinaryData]] = None
    address: Optional[str] = None
    cipher_suite: Optional[str] = None
    negotiated_protocol: Optional[str] = None
    no_tls_verify: Optional[bool] = None
    server_name: Optional[str] = None
    t: Optional[float] = None
    tags: Optional[List[str]] = None
    tls_version: Optional[str] = None
    transaction_id: Optional[int] = None


@dataclass
class NetworkEvent(BaseModel):
    failure: Failure
    operation: str
    t: float
    address: Optional[str] = None
    dial_id: Optional[int] = None
    num_bytes: Optional[int] = None
    proto: Optional[str] = None
    tags: Optional[List[str]] = None
    transaction_id: Optional[str] = None
    conn_id: Optional[int] = None


@dataclass
class WebConnectivityControlHTTPRequest(BaseModel):
    body_length: Optional[int]
    failure: Failure
    title: Optional[str]
    headers: Optional[dict[str, str]]
    status_code: Optional[int]


@dataclass
class WebConnectivityControlDNS(BaseModel):
    failure: Failure
    addrs: Optional[List[str]]


@dataclass
class WebConnectivityControlTCPConnectStatus(BaseModel):
    status: Optional[bool]
    failure: Failure


@dataclass
class WebConnectivityControl(BaseModel):
    tcp_connect: Optional[dict[str, WebConnectivityControlTCPConnectStatus]]
    http_request: Optional[WebConnectivityControlHTTPRequest]
    dns: Optional[WebConnectivityControlDNS]


@dataclass
class WebConnectivityTestKeys(BaseModel):
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

    control: Optional[WebConnectivityControl]
    tls_handshakes: Optional[List[TLSHandshake]]
    network_events: Optional[List[NetworkEvent]]
    queries: Optional[List[DNSQuery]]
    tcp_connect: Optional[List[TCPConnect]]
    requests: Optional[List[HTTPTransaction]]

    x_status: Optional[int] = None
    x_dns_runtime: Optional[int] = None
    x_th_runtime: Optional[int] = None
    x_tcptls_runtime: Optional[int] = None
    x_http_runtime: Optional[int] = None

    client_resolver: Optional[str] = None

    agent: Optional[str] = None
    retries: Optional[int] = None
    socksproxy: Optional[str] = None


@dataclass
class WebConnectivity(BaseMeasurement):
    test_keys: WebConnectivityTestKeys


@dataclass
class URLGetterTestKeys(BaseTestKeys):
    failure: Failure
    socksproxy: Optional[str]
    tls_handshakes: Optional[List[TLSHandshake]]
    network_events: Optional[List[NetworkEvent]]
    queries: Optional[List[DNSQuery]]
    tcp_connect: Optional[List[TCPConnect]]
    requests: Optional[List[HTTPTransaction]]


@dataclass
class DNSCheckTestKeys(BaseTestKeys):
    bootstrap: Optional[URLGetterTestKeys]
    bootstrap_failure: Optional[str]
    lookups: dict[str, URLGetterTestKeys]


@dataclass
class DNSCheck(BaseMeasurement):
    test_keys: DNSCheckTestKeys


@dataclass
class TorTestTarget(BaseModel):
    failure: Failure
    network_events: Optional[List[NetworkEvent]]
    queries: Optional[List[DNSQuery]]
    requests: Optional[List[HTTPTransaction]]
    tls_handshakes: Optional[List[TLSHandshake]]
    tcp_connect: Optional[List[TCPConnect]]

    target_address: str
    target_name: Optional[str]
    target_protocol: str


@dataclass
class TorTestKeys(BaseModel):
    targets: dict[str, TorTestTarget]


@dataclass
class Tor(BaseMeasurement):
    test_keys: TorTestKeys


nettest_dataformats = {
    "web_connectivity": WebConnectivity,
    "tor": Tor,
    "dnscheck": DNSCheck,
}


def load_measurement(raw: bytes) -> BaseMeasurement:
    data = ujson.loads(raw)
    dc = nettest_dataformats.get(data["test_name"], BaseMeasurement)
    msm = from_dict(data_class=dc, data=data)
    if not msm.measurement_uid:
        msm.measurement_uid = trivial_id(raw=raw, msm=msm)
    return msm
