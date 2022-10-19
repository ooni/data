import json
import shutil
import gzip
import logging
import hashlib

from typing import List
from pathlib import Path
from datetime import datetime, date
from collections import OrderedDict, namedtuple
from dataclasses import dataclass

import xml.etree.ElementTree as ET

import requests
import maxminddb

from oonidata.datautils import is_ip_bogon

log = logging.getLogger("oonidata.processing")


def file_sha1_hexdigest(filepath: Path):
    h = hashlib.sha1()
    with filepath.open("rb") as in_file:
        while True:
            b = in_file.read(2**16)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


IAItem = namedtuple("IAItem", ["identifier", "filename", "sha1"])


def list_all_ia_items(identifier: str) -> List[IAItem]:
    ia_items = []
    resp = requests.get(
        f"https://archive.org/download/{identifier}/{identifier}_files.xml"
    )
    if resp.status_code == 404:
        return []

    resp.raise_for_status()
    tree = ET.fromstring(resp.text)
    for f in tree:
        fname = f.get("name")
        if not fname:
            continue

        sha1 = f.find("sha1")
        if sha1 is not None:
            sha1 = sha1.text
        ia_items.append(IAItem(identifier=identifier, filename=fname, sha1=sha1))

    return ia_items


def download_ia_item(ia_item: IAItem, output_path: Path):
    url = f"https://archive.org/download/{ia_item.identifier}/{ia_item.filename}"
    with requests.get(url, stream=True) as resp:
        resp.raise_for_status()
        with output_path.with_suffix(".tmp").open("wb") as out_file:
            for b in resp.iter_content(chunk_size=2**16):
                out_file.write(b)

    output_path.with_suffix(".tmp").rename(output_path)
    file_sha1 = file_sha1_hexdigest(output_path)
    assert file_sha1 == ia_item.sha1, f"{file_sha1} != {ia_item.sha1}"


@dataclass
class ASInfo:
    asn: int

    as_org_name: str
    as_cc: str
    as_name: str


@dataclass
class IPInfo:
    as_info: ASInfo
    cc: str


class NetinfoDB:
    def __init__(
        self,
        datadir: Path = Path("datadir"),
        download: bool = False,
    ):
        self.datadir = datadir
        self.ip2country_as_dir = self.datadir / "ip2country-as"
        if download:
            self.refresh_netinfodb()

        try:
            with (self.ip2country_as_dir / "all_as_org_map.json").open() as in_file:
                self.as_org_map = json.load(in_file)
        except FileNotFoundError:
            log.error("unable to find all_as_org_map.json. Try setting download = True")
            raise

        self.load_ip2country_as()
        self.readers = {}

    def refresh_netinfodb(self):
        self.ip2country_as_dir.mkdir(parents=True, exist_ok=True)

        for item in list_all_ia_items("ip2country-as"):
            if (
                not item.filename.endswith(".mmdb.gz")
                and not item.filename == "all_as_org_map.json"
            ):
                continue

            output_path = self.ip2country_as_dir / item.filename
            if output_path.exists() and file_sha1_hexdigest(output_path) == item.sha1:
                continue

            log.info(f"downloading {item.filename}")
            download_ia_item(ia_item=item, output_path=output_path)

            if output_path.name.endswith(".gz"):
                dst_path = output_path.with_suffix("")
                log.info(f"decompressing to {dst_path}")
                with gzip.open(output_path) as in_file, dst_path.with_suffix(
                    ".tmp"
                ).open("wb") as out_file:
                    shutil.copyfileobj(in_file, out_file)
                dst_path.with_suffix(".tmp").rename(dst_path)

    def get_reader(self, db_path: Path):
        if db_path in self.readers:
            return self.readers[db_path]
        self.readers[db_path] = maxminddb.open_database(str(db_path))
        return self.readers[db_path]

    def load_ip2country_as(self):
        """
        Populate the OrderedDict of decompressed geoip database files that are
        inside of the datadir.
        We expect there to be two files on each date and the format of the file
        is: "%Y%m%d-ip2country_as.mmdb" ex. 20181009-ip2country_as.mmdb.gz
        """
        self.databases = OrderedDict()
        for db_path in sorted(self.ip2country_as_dir.glob("*.mmdb")):
            ts = datetime.strptime(db_path.name.split("-")[0], "%Y%m%d").date()
            self.databases[ts] = db_path

        assert len(self.databases) > 0, "Did not find any geoip database files"

    def find_db_for_date(self, day: date):
        """
        Find DB for date will return a dictionary with asn and country keys set
        which is closest in time and <= day.
        """
        chosen_db = list(self.databases.values())[0]
        for ts, db in self.databases.items():
            if ts > day:
                break
            chosen_db = db
        return chosen_db

    def lookup_asn(self, day: datetime, asn: int) -> ASInfo:
        """
        Returns information about a particular ASN on a given day, if known.
        """
        day_str = day.strftime("%Y%m%d")
        org_name, name, country = ("", "", "")
        try:
            meta_list = self.as_org_map[str(asn)]
            org_name, country, name = meta_list[0][:3]
            for meta in meta_list:
                if meta[2] > day_str:
                    break
                org_name, country, name = meta[:3]
        except KeyError:
            log.error(f"Unable to locate ASN {asn}")

        return ASInfo(asn=asn, as_org_name=org_name, as_cc=country, as_name=name)

    def lookup_ip(self, day: datetime, ip: str) -> IPInfo:
        unknown_ipinfo = IPInfo(
            ASInfo(
                asn=0,
                as_org_name="",
                as_name="",
                as_cc="",
            ),
            cc="ZZ",
        )

        db_path = self.find_db_for_date(day.date())
        assert db_path is not None

        try:
            if is_ip_bogon(ip):
                return IPInfo(
                    ASInfo(
                        asn=64666,
                        as_org_name="Bogon",
                        as_cc="ZZ",
                        as_name="",
                    ),
                    cc="ZZ",
                )
        except ValueError:
            return unknown_ipinfo

        reader = self.get_reader(db_path)
        res = None
        try:
            res = reader.get(ip)
        except ValueError:
            pass

        if not res:
            log.error(f"Failed to lookup {ip}")
            return unknown_ipinfo

        return IPInfo(
            ASInfo(
                asn=res.get("autonomous_system_number", 0),
                as_org_name=res.get("autonomous_system_organization", ""),
                as_cc=res.get("autonomous_system_country", ""),
                as_name=res.get("autonomous_system_name", ""),
            ),
            cc=res.get("country", {}).get("iso_code", "ZZ"),
        )
