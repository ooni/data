"""
In here we define all the base dataformats used in OONI Measurements.

See: https://github.com/ooni/spec/tree/master/data-formats
"""
from base64 import b64decode
import hashlib

from typing import Optional, Tuple, Union, List, Dict

from dataclasses import dataclass

from ..datautils import guess_decode
from ..compat import add_slots

from .base import BaseModel


@add_slots
@dataclass
class BinaryData(BaseModel):
    format: str
    data: str


MaybeBinaryData = Union[str, BinaryData, None]


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


Failure = Optional[str]


@add_slots
@dataclass
class BaseTestKeys(BaseModel):
    client_resolver: Optional[str] = None


# This is not 100% accurate, ideally we would say
# List[Tuple[str, MaybeBinaryData]], yet this doesn't work because we don't have
# tuples in JSON
HeadersList = List[List[Union[str, MaybeBinaryData]]]
HeadersListBytes = List[Tuple[str, bytes]]
HeadersListStr = List[Tuple[str, str]]


@add_slots
@dataclass
class TorInfo(BaseModel):
    is_tor: bool
    exit_ip: Optional[str]
    exit_name: Optional[str]


@add_slots
@dataclass
class HTTPBase(BaseModel):
    body: MaybeBinaryData = None
    body_is_truncated: Optional[bool] = None
    headers: Optional[Dict[str, str]] = None
    headers_list: Optional[HeadersList] = None

    __body_str = None
    __body_bytes = None
    __headers_list_str = None
    __headers_list_bytes = None

    @property
    def body_str(self) -> Optional[str]:
        if self.body_bytes is None:
            return None
        if self.__body_str is not None:
            return self.__body_str
        self.__body_str = guess_decode(self.body_bytes)
        return self.__body_str

    @property
    def body_bytes(self) -> Optional[bytes]:
        if self.body is None:
            return None
        if self.__body_bytes is not None:
            return self.__body_bytes
        self.__body_bytes = maybe_binary_data_to_bytes(self.body)
        return self.__body_bytes

    @property
    def headers_list_str(self) -> Optional[List[Tuple[str, str]]]:
        if not self.headers_list:
            return None
        if self.__headers_list_str is not None:
            return self.__headers_list_str
        self.__headers_list_str = [
            (maybe_binary_data_to_str(k), maybe_binary_data_to_str(v))
            for k, v in self.headers_list
        ]
        return self.__headers_list_str

    @property
    def headers_list_bytes(self) -> Optional[List[Tuple[str, bytes]]]:
        if not self.headers_list:
            return None
        if self.__headers_list_bytes is not None:
            return self.__headers_list_bytes

        self.__headers_list_bytes = [
            (guess_decode(maybe_binary_data_to_bytes(k)), maybe_binary_data_to_bytes(v))
            for k, v in self.headers_list
        ]
        return self.__headers_list_bytes

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

    def get_first_http_header_str(
        self,
        header_name: str,
        case_sensitive: bool = False,
    ) -> Optional[str]:
        r = self._get_first_http_header(
            header_name=header_name,
            headers_list=self.headers_list_str,
            case_sensitive=case_sensitive,
        )
        assert r is None or isinstance(r, str)
        return r

    def get_first_http_header_bytes(
        self,
        header_name: str,
        case_sensitive: bool = False,
    ) -> Optional[bytes]:
        r = self._get_first_http_header(
            header_name=header_name,
            headers_list=self.headers_list_bytes,
            case_sensitive=case_sensitive,
        )
        assert r is None or isinstance(r, bytes)
        return r

    def _get_first_http_header(
        self,
        header_name: str,
        headers_list: Union[HeadersListBytes, HeadersListStr, None],
        case_sensitive: bool = False,
    ) -> Union[bytes, str, None]:
        if not headers_list:
            return None

        if case_sensitive == False:
            header_name = header_name.lower()

        for k, v in headers_list:
            if case_sensitive == False:
                k = k.lower()

            if header_name == k:
                return v

    def __post_init__(self):
        if not self.headers_list and self.headers:
            self.headers_list = []
            for k, v in self.headers.items():
                self.headers_list.append([k, v])


@add_slots
@dataclass
class HTTPRequest(HTTPBase):
    url: str = ""
    method: Optional[str] = None
    tor: Optional[TorInfo] = None
    x_transport: Optional[str] = "tcp"


@add_slots
@dataclass
class HTTPResponse(HTTPBase):
    code: Optional[int] = None


@add_slots
@dataclass
class HTTPTransaction(BaseModel):
    """
    See: https://github.com/ooni/spec/blob/master/data-formats/df-001-httpt.md
    """

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


@add_slots
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


@add_slots
@dataclass
class DNSQuery(BaseModel):
    """
    See: https://github.com/ooni/spec/blob/master/data-formats/df-002-dnst.md
    """

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


@add_slots
@dataclass
class TCPConnectStatus(BaseModel):
    success: bool
    blocked: Optional[bool] = None
    failure: Union[Failure, bool] = None  # see: https://github.com/ooni/spec/pull/277


@add_slots
@dataclass
class TCPConnect(BaseModel):
    """
    See: https://github.com/ooni/spec/blob/master/data-formats/df-005-tcpconnect.md
    """

    ip: str
    port: int
    status: TCPConnectStatus

    transaction_id: Optional[int] = None

    t: Optional[float] = None
    t0: Optional[float] = None

    # Deprecated fields
    conn_id: Optional[int] = None
    dial_id: Optional[int] = None


@add_slots
@dataclass
class TLSHandshake(BaseModel):
    """
    See: https://github.com/ooni/spec/blob/master/data-formats/df-006-tlshandshake.md
    """

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


@add_slots
@dataclass
class NetworkEvent(BaseModel):
    """
    See: https://github.com/ooni/spec/blob/master/data-formats/df-008-netevents.md
    """

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
