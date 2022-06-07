import re
import hashlib
from dataclasses import dataclass
from typing import Generator, Optional, List

from oonidata.dataformat import (
    HeadersList,
    HeadersListBytes,
    WebConnectivity,
    load_measurement,
    HTTPTransaction,
    Failure,
)


def normalize_failure(failure: Failure):
    # TODO: implement a mapping between known unknowns to cleanup the data a bit
    return failure


@dataclass
class Observation:
    measurement_uid: str
    timestamp: str


@dataclass
class HTTPRequestResponseObservation(Observation):
    request_url: str
    request_redirect_from: Optional[str]
    request_body_length: int
    request_body_is_truncated: Optional[bool]
    request_headers_list: Optional[HeadersList]
    request_method: Optional[str]
    request_is_encrypted: bool

    response_body_length: int
    response_body_is_truncated: Optional[bool]
    response_body_sha1: Optional[str]
    response_body_title: Optional[str]
    response_body_meta_title: Optional[str]
    response_body_fingerprint_list: List[str]
    response_status_code: int
    response_headers_list: Optional[HeadersList]
    response_header_location: Optional[str]
    response_header_server: Optional[str]

    failure: Failure
    x_transport: Optional[str] = "tcp"


META_TITLE_REGEXP = re.compile(
    b'<meta.*?property="og:title".*?content="(.*?)"', re.IGNORECASE | re.DOTALL
)


def get_html_meta_title(body: bytes) -> bytes:
    m = META_TITLE_REGEXP.search(body, re.IGNORECASE | re.DOTALL)
    if m:
        return m.group(1)
    return b""


TITLE_REGEXP = re.compile(b"<title.*?>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def get_html_title(body: bytes) -> bytes:
    m = META_TITLE_REGEXP.search(body, re.IGNORECASE | re.DOTALL)
    if m:
        return m.group(1)
    return b""


def get_first_http_header(
    header_name: str, header_list: HeadersListBytes, case_sensitive: bool = False
) -> bytes:
    if case_sensitive == False:
        header_name = header_name.lower()

    for k, v in header_list:
        if case_sensitive == False:
            k = k.lower()

        if header_name == k:
            return v
    return b""


def make_http_request_response_observations(
    requests_list: List[HTTPTransaction],
) -> Generator[HTTPRequestResponseObservation, None, None]:
    for idx, http_transaction in enumerate(requests_list):
        hrro = HTTPRequestResponseObservation()
        hrro.request_url = http_transaction.request.url
        hrro.request_body_length = len(http_transaction.request.body_bytes)
        hrro.request_body_is_truncated = http_transaction.request.body_is_truncated
        hrro.request_headers_list = http_transaction.request.headers_list
        hrro.request_method = http_transaction.request.method

        hrro.response_body_is_truncated = http_transaction.response.body_is_truncated

        hrro.request_is_encrypted = http_transaction.request.url.startswith("https://")
        hrro.failure = normalize_failure(http_transaction.failure)

        if hrro.response.body_bytes:
            hrro.response_body_length = len(http_transaction.response.body_bytes)
            hrro.response_body_sha1 = hashlib.sha1(
                http_transaction.response.body_bytes
            ).hexdigest()
            hrro.response_body_title = get_html_title(
                http_transaction.response.body_bytes
            )
            hrro.response_body_meta_title = get_html_meta_title(
                http_transaction.response.body_bytes
            )

        hrro.response_status_code = http_transaction.response.code
        hrro.response_headers_list = http_transaction.response.headers_list

        hrro.response_header_location = get_first_http_header(
            "location", http_transaction.response.headers_list_bytes
        )
        hrro.response_header_server = get_first_http_header(
            "server", http_transaction.response.headers_list_bytes
        )
        hrro.x_transport = http_transaction.request.x_transport

        try:
            prev_request = requests_list[idx + 1]
            prev_location = get_first_http_header(
                "location", prev_request.response.headers_list_bytes
            ).decode("utf-8")
            if prev_location == hrro.request_url:
                hrro.request_redirect_from = prev_request.request.url
        except (IndexError, UnicodeDecodeError):
            pass

        yield hrro


class BaseMeasurementProcessor:
    def __init__(self, raw: bytes):
        self.measurement = load_measurement(raw)

    def transform(self) -> None:
        pass

    def gen_observations(self) -> Generator[Observation]:
        pass


class WebConnectivityProcessor(BaseMeasurementProcessor):
    measurement: WebConnectivity

    def transform(self):
        self.measurement


nettest_processors = {"web_connectivity": WebConnectivityProcessor}
