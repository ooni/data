"""
OONI data format.

See:

- https://github.com/ooni/spec/tree/master/data-formats

- https://github.com/ooni/spec/tree/master/nettests
"""
import logging
import orjson
import hashlib
from base64 import b64decode

from typing import Optional, Tuple, Union, List, Union

from dataclasses import dataclass
from mashumaro.config import BaseConfig, TO_DICT_ADD_OMIT_NONE_FLAG
from mashumaro import DataClassDictMixin

from oonidata.utils import trivial_id


log = logging.getLogger("oonidata.dataformat")


class BaseModel(DataClassDictMixin):
    class Config(BaseConfig):
        # This makes it possible to call .to_dict(omit_none=True) to remove any
        # attributes of the dataclass that a None, saving up quite a bit of
        # space for unnecessary keys
        code_generation_options = [TO_DICT_ADD_OMIT_NONE_FLAG]


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
    probe_cc: str
    probe_ip: Optional[str]

    test_name: str
    test_version: str
    test_runtime: float

    software_name: str
    software_version: str

    test_keys: BaseTestKeys

    resolver_asn: Optional[str] = None
    resolver_ip: Optional[str] = None
    resolver_network_name: Optional[str] = None

    probe_network_name: Optional[str] = None

    test_helpers: Optional[dict] = None
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
    body: MaybeBinaryData = None
    body_is_truncated: Optional[bool] = None
    headers_list: Optional[HeadersList] = None

    _body_bytes = None
    _headers = None
    _headers_list_bytes = None

    @property
    def body_bytes(self):
        if not self.body:
            return None

        if self._body_bytes:
            return self._body_bytes

        self._body_bytes = maybe_binary_data_to_bytes(self.body)
        return self._body_bytes

    @property
    def headers(self):
        if not self.headers_list:
            return None

        if self._headers:
            return self._headers

        self._headers = {k: v for k, v in self.headers_list}
        return self._headers

    @property
    def headers_list_bytes(self):
        if not self.headers_list:
            return None

        if self._headers_list_bytes:
            return self._headers_list_bytes

        self._headers_list_bytes = [
            (guess_decode(maybe_binary_data_to_bytes(k)), maybe_binary_data_to_bytes(v))
            for k, v in self.headers_list
        ]
        return self.headers_list_bytes

    def __post_init__(self):
        if not self.headers_list and self.headers:
            self.headers_list = []
            for k, v in self.headers.items():
                self.headers_list.append([k, v])


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
    failure: Failure = None

    request: Optional[HTTPRequest] = None
    response: Optional[HTTPResponse] = None

    t: Optional[float] = None
    transaction_id: Optional[int] = None

    def response_sha1(self) -> str:
        if self.response and self.response.body_bytes:
            return hashlib.sha1(self.response.body_bytes).hexdigest()
        return ""


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
    hostname: str
    query_type: str

    failure: Failure = None
    dial_id: Optional[int] = None
    engine: Optional[str] = None

    # XXX: Map resolver_hostname and resolver_port to this
    resolver_address: Optional[str] = None
    t: Optional[float] = None
    transaction_id: Optional[int] = None

    answers: Optional[List[DNSAnswer]] = None


@dataclass
class TCPConnectStatus(BaseModel):
    success: bool
    blocked: Optional[bool] = None
    failure: Failure = None


@dataclass
class TCPConnect(BaseModel):
    ip: str
    port: int
    status: TCPConnectStatus

    t: Optional[float] = None


@dataclass
class TLSHandshake(BaseModel):
    failure: Failure = None
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
    operation: str
    t: float
    failure: Failure = None
    address: Optional[str] = None
    dial_id: Optional[int] = None
    num_bytes: Optional[int] = None
    proto: Optional[str] = None
    tags: Optional[List[str]] = None
    transaction_id: Optional[str] = None
    conn_id: Optional[int] = None


@dataclass
class WebConnectivityControlHTTPRequest(BaseModel):
    body_length: Optional[int] = None
    failure: Failure = None
    title: Optional[str] = None
    headers: Optional[dict[str, str]] = None
    status_code: Optional[int] = None


@dataclass
class WebConnectivityControlDNS(BaseModel):
    failure: Failure = None
    addrs: Optional[List[str]] = None


@dataclass
class WebConnectivityControlTCPConnectStatus(BaseModel):
    status: Optional[bool] = None
    failure: Failure = None


@dataclass
class WebConnectivityControl(BaseModel):
    tcp_connect: Optional[dict[str, WebConnectivityControlTCPConnectStatus]] = None
    http_request: Optional[WebConnectivityControlHTTPRequest] = None
    dns: Optional[WebConnectivityControlDNS] = None


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
    blocking: Union[str, bool, None] = None

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

    agent: Optional[str] = None
    retries: Optional[int] = None
    socksproxy: Optional[str] = None


@dataclass
class WebConnectivity(BaseMeasurement):
    test_keys: WebConnectivityTestKeys


@dataclass
class URLGetterTestKeys(BaseTestKeys):
    failure: Failure = None
    socksproxy: Optional[str] = None
    tls_handshakes: Optional[List[TLSHandshake]] = None
    network_events: Optional[List[NetworkEvent]] = None
    queries: Optional[List[DNSQuery]] = None
    tcp_connect: Optional[List[TCPConnect]] = None
    requests: Optional[List[HTTPTransaction]] = None


@dataclass
class DNSCheckTestKeys(BaseTestKeys):
    lookups: dict[str, URLGetterTestKeys]
    bootstrap: Optional[URLGetterTestKeys] = None
    bootstrap_failure: Optional[str] = None


@dataclass
class DNSCheck(BaseMeasurement):
    test_keys: DNSCheckTestKeys


@dataclass
class TorTestTarget(BaseModel):
    target_address: str
    target_protocol: str

    network_events: Optional[List[NetworkEvent]] = None
    queries: Optional[List[DNSQuery]] = None
    requests: Optional[List[HTTPTransaction]] = None
    tls_handshakes: Optional[List[TLSHandshake]] = None
    tcp_connect: Optional[List[TCPConnect]] = None
    target_name: Optional[str] = None
    failure: Failure = None


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

SupportedDataformats = Union[WebConnectivity, Tor, DNSCheck, BaseMeasurement]


def load_measurement(msmt: dict) -> SupportedDataformats:
    dc = nettest_dataformats.get(msmt["test_name"], BaseMeasurement)
    return dc.from_dict(msmt)
