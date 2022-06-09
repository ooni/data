import pkgutil
import re
import io
import csv
from collections import OrderedDict
from typing import Optional, List
from dataclasses import dataclass, field

from oonidata.dataformat import HTTPResponse
from oonidata.datautils import get_first_http_header


@dataclass
class Fingerprint:
    name: str
    pattern: str
    location_found: str
    common_name: Optional[str] = ""
    regexp: Optional[re.Pattern] = None
    exp_url: Optional[str] = ""
    confidence_no_fp: Optional[int] = 5
    source: List[Optional[str]] = field(default_factory=list)
    scope: Optional[str] = ""
    notes: Optional[str] = ""
    expected_countries: Optional[List[str]] = field(default_factory=list)

    def matches_http(self, http_response: HTTPResponse) -> bool:
        assert self.location_found != "dns", "Cannot use a DNS signature to match HTTP"

        if self.location_found == "body":
            if not http_response.body_bytes:
                return False
            try:
                return self.regexp.search(http_response.body_bytes.decode("utf-8"))
            except UnicodeDecodeError:
                return False

        if self.location_found.startswith("header."):
            search_header = self.location_found.lstrip("header.")
            header_value = get_first_http_header(
                search_header, http_response.headers_list_bytes
            )
            try:
                return self.regexp.search(header_value.decode("utf-8"))
            except UnicodeDecodeError:
                return False
        return False


def _load_fingerprints(fn: str) -> OrderedDict[Fingerprint]:
    fingerprints = OrderedDict()
    data = pkgutil.get_data(__name__, fn)
    if not data:
        raise FileNotFoundError(f"Could not find {fn}")
    in_file = io.TextIOWrapper(io.BytesIO(data), encoding="utf-8")
    csv_reader = csv.DictReader(in_file)
    for row in csv_reader:
        fp = Fingerprint(**row)
        if fp.location_found != "dns":
            fp.regexp = re.compile(fp.pattern, re.DOTALL)
        fingerprints[fp.name] = fp
    return fingerprints


class FingerprintDB:
    def __init__(self):
        self.dns_fp = _load_fingerprints("fingerprints_dns.csv")
        self.http_fp = _load_fingerprints("fingerprints_http.csv")

    def match_http(self, http_response: HTTPResponse) -> List[Fingerprint]:
        matches = []
        for fp in self.http_fp.values():
            if fp.matches_http(http_response):
                matches.append(fp)
        return matches

    def match_dns(self, address: str) -> Optional[Fingerprint]:
        for fp in self.dns_fp.values():
            if fp.pattern == address:
                return fp
        return None

    def get_fp(self, name: str) -> Fingerprint:
        try:
            return self.dns_fp[name]
        except KeyError:
            return self.http_fp[name]
