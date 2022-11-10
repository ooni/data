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


def maybe_binary_data_to_str(mbd: Union[MaybeBinaryData, Dict]) -> str:
    if isinstance(mbd, BinaryData):
        return guess_decode(b64decode(mbd.data))
    elif isinstance(mbd, dict):
        return guess_decode(b64decode(mbd["data"]))
    elif isinstance(mbd, str):
        return mbd

    raise Exception(f"Invalid type {type(mbd)} {mbd}")


def maybe_binary_data_to_bytes(mbd: Union[MaybeBinaryData, Dict]) -> bytes:
    if isinstance(mbd, BinaryData):
        return b64decode(mbd.data)
    elif isinstance(mbd, dict):
        return b64decode(mbd["data"])
    elif isinstance(mbd, str):
        return mbd.encode("utf-8")

    raise Exception(f"Invalid type {type(mbd)} {mbd}")


def trivial_id(raw: bytes, msm: Dict) -> str:
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
    annotations: Dict[str, str]

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

    test_helpers: Optional[Dict] = None
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

    network: Optional[str] = None
    address: Optional[str] = None
    alpn: Optional[str] = None

    transaction_id: Optional[int] = None

    t: Optional[float] = None
    t0: Optional[float] = None

    def response_sha1(self) -> str:
        if self.response and self.response.body_bytes:
            return hashlib.sha1(self.response.body_bytes).hexdigest()
        return ""


@dataclass
class DNSAnswer(BaseModel):
    answer_type: str
    asn: Optional[int] = None
    as_org_name: Optional[str] = None
    hostname: Optional[str] = None
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    ttl: Optional[int] = None

    # Deprecated
    expiration_limit: Optional[str] = None
    minimum_ttl: Optional[str] = None
    refresh_interval: Optional[str] = None
    responsible_name: Optional[str] = None
    retry_interval: Optional[str] = None
    serial_number: Optional[str] = None


@dataclass
class DNSQuery(BaseModel):
    hostname: str
    query_type: str

    failure: Failure = None
    engine: Optional[str] = None

    answers: Optional[List[DNSAnswer]] = None

    raw_response: Optional[str] = None
    rcode: Optional[int] = None

    resolver_address: Optional[str] = None

    transaction_id: Optional[int] = None

    t: Optional[float] = None
    t0: Optional[float] = None

    # Deprecated field
    dial_id: Optional[int] = None


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

    transaction_id: Optional[int] = None

    t: Optional[float] = None
    t0: Optional[float] = None

    # Deprecated fields
    conn_id: Optional[int] = None
    dial_id: Optional[int] = None


@dataclass
class TLSHandshake(BaseModel):
    network: Optional[str] = None
    address: Optional[str] = None
    cipher_suite: Optional[str] = None

    failure: Failure = None
    so_error: Failure = None

    negotiated_protocol: Optional[str] = None

    no_tls_verify: Optional[bool] = None
    peer_certificates: Optional[List[BinaryData]] = None

    server_name: Optional[str] = None

    tags: Optional[List[str]] = None
    tls_version: Optional[str] = None

    t: Optional[float] = None
    t0: Optional[float] = None

    transaction_id: Optional[int] = None

    # Deprecated
    conn_id: Optional[int] = None


@dataclass
class NetworkEvent(BaseModel):
    operation: str
    t: float
    failure: Failure = None
    address: Optional[str] = None
    num_bytes: Optional[int] = None
    proto: Optional[str] = None
    tags: Optional[List[str]] = None
    transaction_id: Optional[str] = None

    # Deprecated fields
    dial_id: Optional[int] = None
    conn_id: Optional[int] = None


@dataclass
class WebConnectivityControlHTTPRequest(BaseModel):
    body_length: Optional[int] = None
    failure: Failure = None
    title: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
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
    tcp_connect: Optional[Dict[str, WebConnectivityControlTCPConnectStatus]] = None
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
MIIF2zCCA8OgAwIBAgIUAMHz4g60cIDBpPr1gyZ/JDaaPpcwDQYJKoZIhvcNAQEL
BQAwdTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcT
DU1vdW50YWluIFZpZXcxHjAcBgNVBAoTFVNpZ25hbCBNZXNzZW5nZXIsIExMQzEZ
MBcGA1UEAxMQU2lnbmFsIE1lc3NlbmdlcjAeFw0yMjAxMjYwMDQ1NTFaFw0zMjAx
MjQwMDQ1NTBaMHUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYw
FAYDVQQHEw1Nb3VudGFpbiBWaWV3MR4wHAYDVQQKExVTaWduYWwgTWVzc2VuZ2Vy
LCBMTEMxGTAXBgNVBAMTEFNpZ25hbCBNZXNzZW5nZXIwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQDEecifxMHHlDhxbERVdErOhGsLO08PUdNkATjZ1kT5
1uPf5JPiRbus9F4J/GgBQ4ANSAjIDZuFY0WOvG/i0qvxthpW70ocp8IjkiWTNiA8
1zQNQdCiWbGDU4B1sLi2o4JgJMweSkQFiyDynqWgHpw+KmvytCzRWnvrrptIfE4G
PxNOsAtXFbVH++8JO42IaKRVlbfpe/lUHbjiYmIpQroZPGPY4Oql8KM3o39ObPnT
o1WoM4moyOOZpU3lV1awftvWBx1sbTBL02sQWfHRxgNVF+Pj0fdDMMFdFJobArrL
VfK2Ua+dYN4pV5XIxzVarSRW73CXqQ+2qloPW/ynpa3gRtYeGWV4jl7eD0PmeHpK
OY78idP4H1jfAv0TAVeKpuB5ZFZ2szcySxrQa8d7FIf0kNJe9gIRjbQ+XrvnN+ZZ
vj6d+8uBJq8LfQaFhlVfI0/aIdggScapR7w8oLpvdflUWqcTLeXVNLVrg15cEDwd
lV8PVscT/KT0bfNzKI80qBq8LyRmauAqP0CDjayYGb2UAabnhefgmRY6aBE5mXxd
byAEzzCS3vDxjeTD8v8nbDq+SD6lJi0i7jgwEfNDhe9XK50baK15Udc8Cr/ZlhGM
jNmWqBd0jIpaZm1rzWA0k4VwXtDwpBXSz8oBFshiXs3FD6jHY2IhOR3ppbyd4qRU
pwIDAQABo2MwYTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
HQ4EFgQUtfNLxuXWS9DlgGuMUMNnW7yx83EwHwYDVR0jBBgwFoAUtfNLxuXWS9Dl
gGuMUMNnW7yx83EwDQYJKoZIhvcNAQELBQADggIBABUeiryS0qjykBN75aoHO9bV
PrrX+DSJIB9V2YzkFVyh/io65QJMG8naWVGOSpVRwUwhZVKh3JVp/miPgzTGAo7z
hrDIoXc+ih7orAMb19qol/2Ha8OZLa75LojJNRbZoCR5C+gM8C+spMLjFf9k3JVx
dajhtRUcR0zYhwsBS7qZ5Me0d6gRXD0ZiSbadMMxSw6KfKk3ePmPb9gX+MRTS63c
8mLzVYB/3fe/bkpq4RUwzUHvoZf+SUD7NzSQRQQMfvAHlxk11TVNxScYPtxXDyiy
3Cssl9gWrrWqQ/omuHipoH62J7h8KAYbr6oEIq+Czuenc3eCIBGBBfvCpuFOgckA
XXE4MlBasEU0MO66GrTCgMt9bAmSw3TrRP12+ZUFxYNtqWluRU8JWQ4FCCPcz9pg
MRBOgn4lTxDZG+I47OKNuSRjFEP94cdgxd3H/5BK7WHUz1tAGQ4BgepSXgmjzifF
T5FVTDTl3ZnWUVBXiHYtbOBgLiSIkbqGMCLtrBtFIeQ7RRTb3L+IE9R0UB0cJB3A
Xbf1lVkOcmrdu2h8A32aCwtr5S1fBF1unlG7imPmqJfpOMWa8yIF/KWVm29JAPq8
Lrsybb0z5gg8w7ZblEuB9zOW9M3l60DXuJO6l7g+deV6P96rv2unHS8UlvWiVWDy
9qfgAJizyy3kqM4lOwBH
-----END CERTIFICATE-----""".encode(
    "ascii"
)

SIGNAL_PEM_STORE = (SIGNAL_ROOT_CA_OLD, SIGNAL_ROOT_CA_NEW)


@dataclass
class TCPTTestKeys(BaseTestKeys):
    received: Optional[List[MaybeBinaryData]] = None
    sent: Optional[List[MaybeBinaryData]] = None


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
    lookups: Optional[Dict[str, URLGetterTestKeys]] = None
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
    targets: Dict[str, TorTestTarget]


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
