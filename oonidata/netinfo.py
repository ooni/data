from multiprocessing.sharedctypes import Value
import os
import gzip
import logging

from glob import glob
from typing import Optional, Generator
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache

import requests
import radix
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

def links_in_folder(url):
    assert url.endswith("/")
    resp = requests.get(url)
    tree = html.fromstring(resp.text)
    return [f"{url}{href}" for href in tree.xpath("//a[@href]/text()")[5:]]

def iter_prefix2as_urls(since, until):
    current_date = since
    while current_date <= until:
        ts = current_date.strftime("%Y/%m")
        base_url = f"https://publicdata.caida.org/datasets/routing/routeviews-prefix2as/{ts}/"
        for url in links_in_folder(base_url):
            ts = datetime.strptime(url.split("/")[-1].split("-")[2], "%Y%m%d")
            yield url
            if ts <= until:
                break

        month = current_date.month + 1
        year = current_date.year
        if month > 12:
            year += 1
        month = month % 12
        current_date = datetime(year, month, 1)

def iter_as_org_urls(since, until) -> Generator[str, None, None]:
    """
    Return the URLs to download the AS organisation dumps in the given range. If
    we don't find anything in the range we return the URL of the DB file closest
    to the since date.
    """
    base_url = f"https://publicdata.caida.org/datasets/as-organizations/"
    found = False

    all_links = list(filter(lambda x: x.endswith("txt.gz"), links_in_folder(base_url)))
    closest_link = all_links[0]
    min_delta = abs(datetime.strptime(closest_link.split("/")[-1].split(".")[0], "%Y%m%d") - since)
    for url in all_links:
        ts = datetime.strptime(url.split("/")[-1].split(".")[0], "%Y%m%d")
        if ts <= until and ts >= since:
            found = True
            yield url

        if min_delta > abs(ts - since):
            min_delta = abs(ts - since)
            closest_link = url
    
    if not found:
        yield closest_link

class NetinfoDB:
    def __init__(self, datadir="asdata"):
        self.datadir = datadir

    def download_data(self, since, until, ignore_existing=True):
        log.info(f"Download prefix2as_data for {since}-{until}")
        for url in iter_prefix2as_urls(since, until):
            filename = os.path.basename(os.path.basename(url)).rstrip(".gz")
            year = filename.split("-")[2][:4]
            os.makedirs(os.path.join(self.datadir, "routeviews-prefix2as", year), exist_ok=True)
            local_path = os.path.join(self.datadir, "routeviews-prefix2as", year, filename)
            if ignore_existing == True and os.path.exists(local_path):
                continue
            with requests.get(url, stream=True) as resp:
                d = gzip.decompress(resp.content)
                with open(local_path, "wb") as out_file:
                    out_file.write(d)

        for url in iter_as_org_urls(since, until):
            filename = os.path.basename(os.path.basename(url)).rstrip(".gz")
            os.makedirs(os.path.join(self.datadir, "as-organizations"), exist_ok=True)
            local_path = os.path.join(self.datadir, "as-organizations", filename)
            if ignore_existing == True and os.path.exists(local_path):
                continue
            with requests.get(url, stream=True) as resp:
                d = gzip.decompress(resp.content)
                with open(local_path, "wb") as out_file:
                    out_file.write(d)

    @lru_cache(maxsize=32)
    def build_as_org_map(self, ts):
        as_org_map = {}
        path = glob(f"{self.datadir}/as-organizations/{ts}*")[0]

        # Taken from: https://github.com/ooni/asn-db-generator/blob/master/parse_caida.py
        asn_to_org_id = {}
        org_id_to_name = {}
        with open(path) as in_file:
            for line in in_file:
                if line.startswith("#"):
                    continue

                chunks = line.split("|")
                try:
                    asn = int(chunks[0])
                    changed, aut_name, org_id, _, source = chunks[1:]
                    assert asn not in asn_to_org_id
                    asn_to_org_id[asn] = org_id
                    continue
                except ValueError:
                    pass
                
                org_id, changed, name, country, source = chunks
                o = org_id.split("-")
                try:
                    int(o[-1])
                    assert o[0] in ("@del", "@family")
                    # type 1: @del-131860|20110801||KR|APNIC
                    # type 2: @family-76580||Super Telecom, Ltd.|HK|APNIC
                    continue

                except ValueError:
                    assert o[-1] in (
                        "AFRINIC",
                        "APNIC",
                        "ARIN",
                        "LACNIC",
                        "RIPE",
                        "JPNIC",
                    ), o

                    if o[0].startswith("@"):
                        assert o[0] == "@aut"
                        # type 3:
                        # @aut-11816-LACNIC|20051208|SetarNet|AW|LACNIC
                        continue

                    # type 4:
                    # BANKP-1-ARIN|20190820|BankPlus|US|ARIN
                    assert org_id not in org_id_to_name
                    org_id_to_name[org_id] = (name, country)
                    continue
        for asn, org_id in asn_to_org_id.items():
            try:
                as_org_map[str(asn)] = org_id_to_name[org_id]
            except KeyError:
                pass

        return as_org_map

    def get_as_org_map(self, day):
        closest_ts = min(map(
            lambda r: r.split(".")[0].split("/")[-1], glob(f"{self.datadir}/as-organizations/*")),
            key=lambda r: abs(datetime.strptime(r, "%Y%m%d") - day)
        )
        return self.build_as_org_map(closest_ts)

    def iter_prefixes(self, day):
        path = glob(f"{self.datadir}/routeviews-prefix2as/{day.strftime('%Y')}/routeviews-rv2-{day.strftime('%Y%m%d')}-*")[0]
        with open(path) as in_file:
            for entry in in_file:
                if entry == "":
                    continue
                ip, mask_len, asn = entry.split("\t")
                asn = asn.strip()
                # We ignore multi origin and AS sets, discarding anything but
                # the first AS for a given prefix.
                # TODO: figure out if taking the first one is a good idea and if
                # we should instead be using a smarter heuristic for this.
                asn = asn.split("_")[0].split(",")[0]
                yield ip.strip(), mask_len.strip(), int(asn)

    @lru_cache(maxsize=32)
    def build_radix_tree(self, day) -> radix.Radix:
        as_org_map = self.get_as_org_map(day)
        rtree = radix.Radix()
        for ip, mask_len, asn in self.iter_prefixes(day):
            rnode = rtree.add(ip, int(mask_len))
            org_name, country = as_org_map.get(str(asn), ("", ""))
            rnode.data["asn"] = asn
            rnode.data["as_org_name"] = org_name
            rnode.data["as_cc"] = country
        return rtree

    def find_closest_date_with_data(self, day):
        # Linear time search, not the fastest, but whatevas
        closest_ts = min(map(
            lambda r: r.split("-")[-2], glob(f"{self.datadir}/routeviews-prefix2as/*/*")),
            key=lambda r: abs(datetime.strptime(r, "%Y%m%d") - day)
        )
        return datetime.strptime(closest_ts, "%Y%m%d")

    def get_radix_tree(self, day):
        try:
            return self.build_radix_tree(day)
        except IndexError:
            day = self.find_closest_date_with_data(day)
            return self.build_radix_tree(day)

    def lookup_asn(self, day: datetime, asn: int) -> ASInfo:
        """
        Returns information about a particular ASN on a given day, if known.
        """
        as_org_map = self.get_as_org_map(day)
        org_name, country = as_org_map.get(str(asn), ("", ""))
        return ASInfo(asn=asn, as_org_name=org_name, as_cc=country)

    def lookup_ip(self, day: datetime, ip: str) -> IPInfo:
        rt = self.get_radix_tree(day)
        res = rt.search_best(ip)
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
