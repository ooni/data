"""
OONI data format.

See:

- https://github.com/ooni/spec/tree/master/data-formats

- https://github.com/ooni/spec/tree/master/nettests
"""
import logging
import hashlib

from pathlib import Path
from base64 import b64decode

from datetime import datetime
from typing import Optional, Tuple, Union, List, Union, Dict

from dataclasses import dataclass

import orjson
from mashumaro.config import BaseConfig, TO_DICT_ADD_OMIT_NONE_FLAG
from mashumaro import DataClassDictMixin


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


def maybe_binary_data_to_str(mbd: Union[MaybeBinaryData, dict]) -> str:
    if isinstance(mbd, BinaryData):
        return guess_decode(b64decode(mbd.data))
    elif isinstance(mbd, dict):
        return guess_decode(b64decode(mbd["data"]))
    elif isinstance(mbd, str):
        return mbd

    raise Exception(f"Invalid type {type(mbd)} {mbd}")


def maybe_binary_data_to_bytes(mbd: Union[MaybeBinaryData, dict]) -> bytes:
    if isinstance(mbd, BinaryData):
        return b64decode(mbd.data)
    elif isinstance(mbd, dict):
        return b64decode(mbd["data"])
    elif isinstance(mbd, str):
        return mbd.encode("utf-8")

    raise Exception(f"Invalid type {type(mbd)} {mbd}")


def trivial_id(raw: bytes, msm: dict) -> str:
    """Generate a trivial id of the measurement to allow upsert if needed
    This is used for legacy (before measurement_uid) measurements
    - Deterministic / stateless with no DB interaction
    - Malicious/bugged msmts with collisions on report_id/input/test_name lead
    to different hash values avoiding the collision
    - Malicious/duplicated msmts that are semantically identical to the "real"
    one lead to harmless collisions
    - Sortable by date
    """
    VER = "01"
    h = hashlib.shake_128(raw).hexdigest(15)
    try:
        t = msm.get("measurement_start_time") or ""
        t = datetime.strptime(t, "%Y-%m-%d %H:%M:%S")
        ts = t.strftime("%Y%m%d")
    except:
        ts = "00000000"
    tid = f"{VER}{ts}{h}"
    return tid


@dataclass
class BaseTestKeys(BaseModel):
    client_resolver: Optional[str] = None


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
HeadersListStr = List[Tuple[str, str]]


@dataclass
class TorInfo(BaseModel):
    is_tor: bool
    exit_ip: Optional[str]
    exit_name: Optional[str]


@dataclass
class HTTPBase(BaseModel):
    body: MaybeBinaryData = None
    body_is_truncated: Optional[bool] = None
    headers: Optional[Dict[str, str]] = None
    headers_list: Optional[HeadersList] = None

    _body_bytes = None
    _body_str = None
    _headers = None
    _headers_list_bytes = None
    _headers_list_str = None

    @property
    def body_str(self) -> Optional[str]:
        if not self.body:
            return None

        if self._body_str:
            return self._body_str

        self._body_str = maybe_binary_data_to_str(self.body)
        return self._body_str

    @property
    def body_bytes(self) -> Optional[bytes]:
        if not self.body:
            return None

        if self._body_bytes:
            return self._body_bytes

        self._body_bytes = maybe_binary_data_to_bytes(self.body)
        return self._body_bytes

    @property
    def headers_str(self) -> Optional[Dict[str, str]]:
        if not self.headers_list_str:
            return None
        return {k: v for k, v in self.headers_list_str}

    @property
    def headers_bytes(self) -> Optional[Dict[str, bytes]]:
        if not self.headers_list_bytes:
            return None
        return {k: v for k, v in self.headers_list_bytes}

    @property
    def headers_list_str(self) -> Optional[List[Tuple[str, str]]]:
        if not self.headers_list:
            return None

        if self._headers_list_str:
            return self._headers_list_str

        self._headers_list_str = [
            (maybe_binary_data_to_str(k), maybe_binary_data_to_str(v))
            for k, v in self.headers_list
        ]
        return self._headers_list_str

    @property
    def headers_list_bytes(self) -> Optional[List[Tuple[str, bytes]]]:
        if not self.headers_list:
            return None

        if self._headers_list_bytes:
            return self._headers_list_bytes

        self._headers_list_bytes = [
            (guess_decode(maybe_binary_data_to_bytes(k)), maybe_binary_data_to_bytes(v))
            for k, v in self.headers_list
        ]
        return self._headers_list_bytes

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

    retries: Optional[int] = None
    socksproxy: Optional[str] = None


@dataclass
class WebConnectivity(BaseMeasurement):
    test_keys: WebConnectivityTestKeys


@dataclass
class WhatsappTestKeys(BaseTestKeys):
    failure: Optional[str] = None
    failed_operation: Optional[str] = None

    network_events: Optional[List[NetworkEvent]] = None
    tls_handshakes: Optional[List[TLSHandshake]] = None
    queries: Optional[List[DNSQuery]] = None
    tcp_connect: Optional[List[TCPConnect]] = None
    requests: Optional[List[HTTPTransaction]] = None

    registration_server_failure: Optional[str] = None
    registration_server_status: Optional[str] = None
    whatsapp_endpoints_status: Optional[str] = None
    whatsapp_endpoints_blocked: Optional[List[str]] = None
    whatsapp_endpoints_dns_inconsistent: Optional[List[str]] = None

    whatsapp_web_failure: Optional[str] = None
    whatsapp_web_status: Optional[str] = None


@dataclass
class Whatsapp(BaseMeasurement):
    test_keys: WhatsappTestKeys


SIGNAL_ROOT_CA_OLD = """-----BEGIN CERTIFICATE-----
MIID7zCCAtegAwIBAgIJAIm6LatK5PNiMA0GCSqGSIb3DQEBBQUAMIGNMQswCQYD
VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5j
aXNjbzEdMBsGA1UECgwUT3BlbiBXaGlzcGVyIFN5c3RlbXMxHTAbBgNVBAsMFE9w
ZW4gV2hpc3BlciBTeXN0ZW1zMRMwEQYDVQQDDApUZXh0U2VjdXJlMB4XDTEzMDMy
NTIyMTgzNVoXDTIzMDMyMzIyMTgzNVowgY0xCzAJBgNVBAYTAlVTMRMwEQYDVQQI
DApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMR0wGwYDVQQKDBRP
cGVuIFdoaXNwZXIgU3lzdGVtczEdMBsGA1UECwwUT3BlbiBXaGlzcGVyIFN5c3Rl
bXMxEzARBgNVBAMMClRleHRTZWN1cmUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDBSWBpOCBDF0i4q2d4jAXkSXUGpbeWugVPQCjaL6qD9QDOxeW1afvf
Po863i6Crq1KDxHpB36EwzVcjwLkFTIMeo7t9s1FQolAt3mErV2U0vie6Ves+yj6
grSfxwIDAcdsKmI0a1SQCZlr3Q1tcHAkAKFRxYNawADyps5B+Zmqcgf653TXS5/0
IPPQLocLn8GWLwOYNnYfBvILKDMItmZTtEbucdigxEA9mfIvvHADEbteLtVgwBm9
R5vVvtwrD6CCxI3pgH7EH7kMP0Od93wLisvn1yhHY7FuYlrkYqdkMvWUrKoASVw4
jb69vaeJCUdU+HCoXOSP1PQcL6WenNCHAgMBAAGjUDBOMB0GA1UdDgQWBBQBixjx
P/s5GURuhYa+lGUypzI8kDAfBgNVHSMEGDAWgBQBixjxP/s5GURuhYa+lGUypzI8
kDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQB+Hr4hC56m0LvJAu1R
K6NuPDbTMEN7/jMojFHxH4P3XPFfupjR+bkDq0pPOU6JjIxnrD1XD/EVmTTaTVY5
iOheyv7UzJOefb2pLOc9qsuvI4fnaESh9bhzln+LXxtCrRPGhkxA1IMIo3J/s2WF
/KVYZyciu6b4ubJ91XPAuBNZwImug7/srWvbpk0hq6A6z140WTVSKtJG7EP41kJe
/oF4usY5J7LPkxK3LWzMJnb5EIJDmRvyH8pyRwWg6Qm6qiGFaI4nL8QU4La1x2en
4DGXRaLMPRwjELNgQPodR38zoCMuA8gHZfZYYoZ7D7Q1wNUiVHcxuFrEeBaYJbLE
rwLV
-----END CERTIFICATE-----""".encode(
    "ascii"
)

SIGNAL_ROOT_CA_NEW = """-----BEGIN CERTIFICATE-----
MIIEjDCCAnSgAwIBAgITV+dgmSk1+75Wwn/Mjz8f+gQ9qTANBgkqhkiG9w0BAQsF
ADB1MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMN
TW91bnRhaW4gVmlldzEeMBwGA1UEChMVU2lnbmFsIE1lc3NlbmdlciwgTExDMRkw
FwYDVQQDExBTaWduYWwgTWVzc2VuZ2VyMB4XDTIyMDgyMzE2NTIxMVoXDTIzMDky
MzIyNDA1NlowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALf8th0A
N5TFsvvdfaSP1WyCMn5Ql81IF5D0pXrdE9fGDz5AaeAbCazxXU8tnjZiUr4a/BGD
h3ZxORHXJ2SA3HA2UFG+qHik59QNGkY4Jv4emTM5QLw0fcsGRgJnzb7A60LRoxGs
17jxD1zyVl/SXn/Ql3cvBrHjxPzJ6NcQG4Pek7YieH2xiMP794QUu0XJYlBx0uvx
xOI3qpw5c6oNORGY8hlwWzbv+sqvShXhteOlkzluKtIqpL8+NV206JIqLkaKFjB7
To14TSFF3tYxxsHYwDhRKPatqYpbebx3iCo0H33dL0gjoUtdvRgsdHqnUQXSqoRH
cUYCIPs3FivKNrcCAwEAAaOBiTCBhjATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNV
HRMBAf8EAjAAMB0GA1UdDgQWBBSidZq+TLJkcDuNV5j1KbOm/l+dhjAfBgNVHSME
GDAWgBS180vG5dZL0OWAa4xQw2dbvLHzcTAhBgNVHREBAf8EFzAVghNzZnUudm9p
cC5zaWduYWwub3JnMA0GCSqGSIb3DQEBCwUAA4ICAQCDchlftHXUm3sFWL86GKUs
w7nxOiJDZYR+xIVGbsUarBolEsZZkYjTDB427ZjgBS+Nfhhbrw4k2LMarkxf2TQX
aelPHRa5xNPVfkrN8xw4fv/8TLE9GSjKlrNJm1EoTZL5CYWQU+qe4CuKfAJU6h8l
xIkcik61aCeNLQoaI1L3V8tPXmmqMWpsnZmFg6YLGeMTLs4skdFqgLOnx9EF2jgO
7EAJ9HcrgSPirQeuDJKhamaLtQiqIQR8L3H4YG1FDiuOeto6f1LRCIqjH1Mye1BM
33Qg/VilLQIWp8+C4GJZ0+LO1cfatNh8tkDbrwMzUeA1nLEZHMlgXE05z00euNlQ
0+evTmJzWRKJHugPnA3vvdzy4lbYvYWaXs8pACrVpESui8I+v6jdH814lOxpDwNH
bPrxfOxhIxfFiVttCl3AQZBLJM6M0ty6/Q7bYsdNT23jKMl0AmDhj9qn/7dzYcVi
vI0XKaaJl4ov3IDbuMe0oZWhoLwzPuWxxkWDjTb8ngDnWZT1o5dAR9fltr38m42N
uA/SkxghiAMmvkC8nhEJ7yT2hme+rozPZSp1SSEDViDkA4KnnQpMcNiotCQpNOe7
YfA9uSnjHjZloRTPUgtkKQ3u8ZZprFQlS2jDE18BRGdh24V5OsCbMvFPtrEsjG4H
5xvkiIV0FpbMk4Gj8I4Hbw==
-----END CERTIFICATE-----""".encode(
    "ascii"
)

SIGNAL_PEM_STORE = (SIGNAL_ROOT_CA_OLD, SIGNAL_ROOT_CA_NEW)


@dataclass
class SignalTestKeys(BaseTestKeys):
    failure: Optional[str] = None
    failed_operation: Optional[str] = None

    network_events: Optional[List[NetworkEvent]] = None
    tls_handshakes: Optional[List[TLSHandshake]] = None
    queries: Optional[List[DNSQuery]] = None
    tcp_connect: Optional[List[TCPConnect]] = None
    requests: Optional[List[HTTPTransaction]] = None

    signal_backend_status: Optional[str] = None
    signal_backend_failure: Optional[str] = None


@dataclass
class Signal(BaseMeasurement):
    test_keys: SignalTestKeys


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
    lookups: Optional[dict[str, URLGetterTestKeys]] = None
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
    "whatsapp": Whatsapp,
    "signal": Signal,
}

SupportedDataformats = Union[WebConnectivity, Tor, DNSCheck, Whatsapp, BaseMeasurement]


def load_measurement(
    msmt: Optional[dict] = None, msmt_path: Optional[Path] = None
) -> SupportedDataformats:
    if msmt_path:
        with msmt_path.open() as in_file:
            msmt = orjson.loads(in_file.read())

    assert msmt, "either msmt or msmt_path should be set"
    dc = nettest_dataformats.get(msmt["test_name"], BaseMeasurement)
    return dc.from_dict(msmt)
