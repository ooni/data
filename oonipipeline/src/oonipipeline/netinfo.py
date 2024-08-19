import shutil
import gzip
import logging

from typing import Iterable, Optional
from pathlib import Path
from datetime import datetime, date
from collections import OrderedDict
from dataclasses import dataclass

import orjson

import requests
from requests.adapters import HTTPAdapter, Retry

import maxminddb

from oonidata.datautils import is_ip_bogon
import boto3
from botocore import UNSIGNED as BOTO_UNSIGNED
from botocore.config import Config as BotoConfig


log = logging.getLogger("oonidata.processing")

BotoUnsignedConfig = BotoConfig(signature_version=BOTO_UNSIGNED)

retry_strategy = Retry(total=4, backoff_factor=0.1)

req_session = requests.Session()
req_session.mount("http://", HTTPAdapter(max_retries=retry_strategy))
req_session.mount("https://", HTTPAdapter(max_retries=retry_strategy))


def iter_ip2countryas() -> Iterable[tuple]:
    s3 = boto3.resource("s3", config=BotoUnsignedConfig)

    for obj in s3.Bucket("ooni-data-eu-fra").objects.filter(Prefix="ip2country-as/"):
        if obj.size == 0:
            continue
        yield (obj.key, obj.size, obj.e_tag)


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
        max_age_seconds: Optional[int] = None,
    ):
        self.datadir = datadir
        self.ip2country_as_dir = self.datadir / "ip2country-as"
        self.last_updated_file = self.ip2country_as_dir / "LAST_UPDATED.txt"
        self.max_age_seconds = max_age_seconds
        if download and self.should_update():
            print("DOWNLOADING")
            self.refresh_netinfodb()

        try:
            with (self.ip2country_as_dir / "all_as_org_map.json").open() as in_file:
                self.as_org_map = orjson.loads(in_file.read())
        except FileNotFoundError:
            log.error("unable to find all_as_org_map.json. Try setting download = True")
            raise

        self.load_ip2country_as()
        self.readers = {}

    def should_update(self):
        if self.max_age_seconds is None or self.last_updated_file.exists() is False:
            return True

        last_updated = datetime.fromisoformat(self.last_updated_file.read_text())
        age = datetime.now() - last_updated
        return age.seconds >= self.max_age_seconds

    def update_last_updated(self):
        self.last_updated_file.write_text(datetime.now().isoformat())

    def refresh_netinfodb(self):
        print("refreshing netinfodb")
        self.ip2country_as_dir.mkdir(parents=True, exist_ok=True)

        for key, size, _ in iter_ip2countryas():
            filename = key.split("/")[-1]
            output_path = self.ip2country_as_dir / filename
            if output_path.exists() and output_path.stat().st_size == size:
                continue

            log.info(f"downloading {filename}")

            s3_client = boto3.client("s3", config=BotoUnsignedConfig)
            with output_path.open("wb") as out_file:
                s3_client.download_fileobj("ooni-data-eu-fra", key, out_file)

            if output_path.name.endswith(".gz"):
                dst_path = output_path.with_suffix("")
                log.info(f"decompressing to {dst_path}")
                with gzip.open(output_path) as in_file, dst_path.with_suffix(
                    ".tmp"
                ).open("wb") as out_file:
                    shutil.copyfileobj(in_file, out_file)
                dst_path.with_suffix(".tmp").rename(dst_path)
        self.update_last_updated()

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
        if asn == 0:
            return ASInfo(asn=asn, as_org_name="Unknown", as_cc="ZZ", as_name="Unknown")

        if asn >= 64512 and asn <= 65535:
            return ASInfo(
                asn=asn,
                as_org_name="Private use (RFC1930)",
                as_cc="ZZ",
                as_name="Private use (RFC1930)",
            )

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

        db_path = self.find_db_for_date(day.date())
        assert db_path is not None

        reader = self.get_reader(db_path)
        res = None
        try:
            res = reader.get(ip)
        except ValueError:
            pass

        if not res:
            log.debug(f"Failed to lookup {ip}")
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
