import os
import json
import shutil
import gzip
import logging
from collections import OrderedDict

from dataclasses import dataclass
from datetime import datetime, date
from pathlib import Path
from functools import lru_cache

import maxminddb

log = logging.getLogger("oonidata.processing")

@dataclass
class ASInfo:
    asn: int

    as_org_name: str
    as_cc: str

@dataclass
class IPInfo:
    as_info: ASInfo
    cc: str



class NetinfoDB:
    def __init__(self, datadir : Path = Path("geoip"), as_org_map_path : Path = Path("all_as_org_map.json")):
        self.datadir = datadir
        with as_org_map_path.open() as in_file:
            self.as_org_map = json.load(in_file)
        self.load_databases()
        self.readers = {}

    def get_reader(self, db_path : Path):
        if db_path in self.readers:
            return self.readers[db_path]
        self.readers[db_path] = maxminddb.open_database(str(db_path))
        return self.readers[db_path]

    def load_databases(self):
        """
        Populate the OrderedDict of decompressed geoip database files that are
        inside of the datadir.
        If the files are compressed, we first decompress each of them.
        We expect there to be two files on each date and the format of the file
        is: "%Y%m%d-(country|asn).(dat|mmdb)(.gz)?".
        Where dat or mmdb indicates if the format is the legacy maxmind GeoIP or
        GeoIP2 formats respectively.
        """
        for db_path in self.datadir.glob("*.gz"):
            decompressed_path = db_path.with_suffix("")
            if decompressed_path.exists():
                continue
            with gzip.open(db_path) as in_file, decompressed_path.open("wb") as out_file:
                shutil.copyfileobj(in_file, out_file)

        db_files = {}
        for db_path in self.datadir.glob("*"):
            if db_path.match("*.gz"):
                continue
            ts = datetime.strptime(db_path.name.split("-")[0], "%Y%m%d").date()
            db_files[ts] = db_files.get(ts, {})
            if db_path.match("*-country-asn.mmdb"):
                db_files[ts] = db_path
            else:
                log.warning(f"Unknown file type inside of datadir {db_path}")

        self.databases = OrderedDict()
        for ts in sorted(db_files.keys()):
            self.databases[ts] = db_files[ts]
        
        assert self.databases

    def find_db_for_date(self, day : date):
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
        org_name, country = ("",  "")
        try:
            meta_list = self.as_org_map[str(asn)]
            org_name, country = meta_list[0][:2]
            for meta in meta_list:
                if meta[2] > day_str:
                    break
                org_name, country = meta[:2]
        except KeyError:
            log.error(f"Unable to locate ASN {asn}")

        return ASInfo(asn=asn, as_org_name=org_name, as_cc=country)

    def lookup_ip(self, day: datetime, ip: str) -> IPInfo:
        db_path = self.find_db_for_date(day.date())
        assert db_path is not None

        reader = self.get_reader(db_path)
        res : dict = reader.get(ip)
        if not res:
            log.error(f"Failed to lookup {ip}")
            return IPInfo(
                ASInfo(
                    asn=0,
                    as_org_name="",
                    as_cc="",
                ),
                cc="ZZ"
            )

        asn = res.get("asn", 0)
        as_org_name = res.get("as_org_name", "")
        as_cc = res.get("as_org_cc", "")
        cc = res.get("country", {}).get("iso_code", "ZZ")

        return IPInfo(
            ASInfo(
                asn=asn,
                as_org_name=as_org_name,
                as_cc=as_cc,
            ),
            cc=cc
        )