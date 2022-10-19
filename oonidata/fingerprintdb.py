import pkgutil
import re
import io
import csv

from pathlib import Path
from collections import OrderedDict
from typing import Optional, List
from dataclasses import dataclass, field

import requests

from oonidata.dataformat import HTTPResponse
from oonidata.datautils import get_first_http_header_str


@dataclass
class Fingerprint:
    name: str
    pattern: str
    pattern_type: str
    location_found: str
    other_names: str
    exp_url: Optional[str] = ""
    confidence_no_fp: Optional[int] = 5
    source: List[Optional[str]] = field(default_factory=list)
    scope: Optional[str] = ""
    notes: Optional[str] = ""
    expected_countries: Optional[List[str]] = field(default_factory=list)

    regexp: Optional[re.Pattern] = None

    def matches_pattern(self, s: str) -> bool:
        if self.pattern_type == "full":
            return self.pattern == s

        if self.pattern_type == "contains":
            return self.pattern in s

        if self.pattern_type == "prefix":
            return s.startswith(self.pattern)

        if self.pattern_type == "regexp":
            assert (
                self.regexp is not None
            ), "regexp is not set for a regexp type pattern"
            return self.regexp.search(s) != None

        raise Exception(
            f"Found unknown fingerprint matching pattern {self.pattern_type}"
        )

    def matches_http(self, http_response: HTTPResponse) -> bool:
        assert self.location_found != "dns", "Cannot use a DNS signature to match HTTP"

        if self.location_found == "body":
            if not http_response.body_str:
                return False

            try:
                return self.matches_pattern(http_response.body_str)
            except UnicodeDecodeError:
                return False

        if self.location_found.startswith("header.") and self.regexp:
            search_header = self.location_found[len("header.") :]
            header_value = get_first_http_header_str(
                search_header, http_response.headers_list_str or []
            )
            if not header_value:
                return False

            assert isinstance(header_value, str)

            return self.matches_pattern(header_value)
        return False


def _load_fingerprints(filepath: Path) -> OrderedDict[str, Fingerprint]:
    fingerprints = OrderedDict()

    with filepath.open() as in_file:
        csv_reader = csv.DictReader(in_file)
        for row in csv_reader:
            fp = Fingerprint(**row)
            if fp.pattern_type == "regexp":
                fp.regexp = re.compile(fp.pattern, re.DOTALL)
            fingerprints[fp.name] = fp
    return fingerprints


class FingerprintDB:
    def __init__(self, datadir: Path, download: bool = False):
        self.datadir = datadir
        self.fingerprint_dir = datadir / "blocking-fingerprints"

        dns_fp_path = self.fingerprint_dir / "fingerprints_dns.csv"
        http_fp_path = self.fingerprint_dir / "fingerprints_http.csv"

        if download and (not dns_fp_path.exists() or not http_fp_path.exists()):
            self.refresh_fingerprintdb()

        self.dns_fp = _load_fingerprints(dns_fp_path)
        self.http_fp = _load_fingerprints(http_fp_path)

    def refresh_fingerprintdb(self):
        self.fingerprint_dir.mkdir(parents=True, exist_ok=True)

        for fn in ["fingerprints_http.csv", "fingerprints_dns.csv"]:
            with requests.get(
                f"https://raw.githubusercontent.com/ooni/blocking-fingerprints/main/{fn}",
                stream=True,
            ) as resp:
                resp.raise_for_status()
                output_path = self.fingerprint_dir / fn
                with output_path.with_suffix(".tmp").open("wb") as out_file:
                    for b in resp.iter_content(chunk_size=2**16):
                        out_file.write(b)

            output_path.with_suffix(".tmp").rename(output_path)

    def match_http(self, http_response: HTTPResponse) -> List[Fingerprint]:
        matches = []
        for fp in self.http_fp.values():
            if fp.matches_http(http_response):
                matches.append(fp)
        return matches

    def match_dns(self, address: Optional[str]) -> Optional[Fingerprint]:
        if not address:
            return None
        for fp in self.dns_fp.values():
            if fp.pattern == address:
                return fp
        return None

    def get_fp(self, name: str) -> Fingerprint:
        try:
            return self.dns_fp[name]
        except KeyError:
            return self.http_fp[name]
