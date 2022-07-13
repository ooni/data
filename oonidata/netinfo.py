import os
import shutil
import gzip
import logging

from glob import glob
from typing import Optional, Generator
from dataclasses import dataclass
from datetime import datetime, date
from pathlib import Path
from functools import lru_cache

import requests
import maxminddb
import GeoIP
from lxml import html

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
    def __init__(self, datadir : Path = Path("geoip")):
        self.datadir = datadir
        self.load_databases()
    
    def load_databases(self):
        for db_path in self.datadir.glob("*.gz"):
            decompressed_path = db_path.with_suffix("")
            if decompressed_path.exists():
                continue
            with gzip.open(db_path) as in_file, decompressed_path.open("wb") as out_file:
                shutil.copyfileobj(in_file, out_file)
        
        for db_path in self.datadir.glob("*"):
            if db_path.match("*.gz"):
                continue


    def find_closest_date_with_data(self, day : date):
        # Linear time search, not the fastest, but whatevas
        closest_ts = min(map(
            lambda r: r.split("-")[-2], glob(f"{self.datadir}/routeviews-prefix2as/*/*")),
            key=lambda r: abs(datetime.strptime(r, "%Y%m%d").date() - day)
        )
        return datetime.strptime(closest_ts, "%Y%m%d").date()

    def lookup_asn(self, day: datetime, asn: int) -> ASInfo:
        """
        Returns information about a particular ASN on a given day, if known.
        """
        as_org_map = self.get_as_org_map(day.date())
        org_name, country = as_org_map.get(str(asn), ("", ""))
        return ASInfo(asn=asn, as_org_name=org_name, as_cc=country)

    def lookup_ip(self, day: datetime, ip: str) -> IPInfo:
        rt = self.get_radix_tree(day.date())
        res = None
        try:
            res = rt.search_best(ip)
        except ValueError:
            pass

        if not res:
            log.error(f"Failed to lookup {ip}")
            return IPInfo(
                ASInfo(
                    asn=0,
                    as_org_name="",
                    as_cc=""
                ),
                cc=""
            )
        return IPInfo(
            ASInfo(
                asn=res.data["asn"],
                as_org_name=res.data["as_org_name"],
                as_cc=res.data["as_cc"],
            ),
            cc=""
        )
