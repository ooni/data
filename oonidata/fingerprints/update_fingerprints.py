import io
import re
import json
import ast
from typing import Optional, List
from dataclasses import dataclass, field, fields, asdict
import requests
import csv

from oonidata.utils import fingerprints as ooni_fingerprint

CP_FINGERPRINTS_CP = "https://raw.githubusercontent.com/censoredplanet/censoredplanet-analysis/master/pipeline/metadata/data/blockpage_signatures.json"
CP_FALSE_POSITIVE_CP = "https://raw.githubusercontent.com/censoredplanet/censoredplanet-analysis/master/pipeline/metadata/data/false_positive_signatures.json"
CL_DNS = "https://raw.githubusercontent.com/citizenlab/filtering-annotations/841940d6fcee5a794aeddb02eee43a7775cfeda3/data/v1/dns.csv"
CL_HTTP = "https://raw.githubusercontent.com/citizenlab/filtering-annotations/master/data/v1/http.csv"


@dataclass
class Fingerprint:
    name: str
    pattern: str
    location_found: str
    common_name: Optional[str] = ""
    exp_url: Optional[str] = ""
    confidence_no_fp: Optional[int] = 5
    source: List[Optional[str]] = field(default_factory=list)
    scope: Optional[str] = ""
    notes: Optional[str] = ""
    expected_countries: Optional[List[str]] = field(default_factory=list)


# Scope can be one of:
# "nat" national level blockpage
# "isp" ISP level blockpage
# "prod" text pattern related to a middlebox product
# "inst" text pattern related to a voluntary instition blockpage (school, office)
# "vbw" vague blocking word

# OONI scopes are:
# blocking locality: global > country > isp > local

ooni_scope_to_cl = {
    "global": "vbw",
    "country": "nat",
    "isp": "isp",
    "local": "inst",
}


def main():
    fingerprints = []
    body_fp_strings = set()
    header_fp_strings = set()
    dns_fp_responses = set()

    def maybe_add_fingerprint(fp: Fingerprint) -> None:
        if fp.location_found == "body" and fp.pattern in body_fp_strings:
            print(f"Duplicate body fp {fp.name} ({fp.source})")
            return

        if fp.location_found == "header.location" and fp.pattern in header_fp_strings:
            print(f"Duplicate header fp {fp.name} ({fp.source})")
            return
        if fp.location_found == "dns" and fp.pattern in dns_fp_responses:
            print(f"Duplicate dns fp {fp.name} ({fp.source})")
            return

        fingerprints.append(fp)
        if fp.location_found == "body":
            body_fp_strings.add(fp.pattern)
        if fp.location_found == "header.location":
            header_fp_strings.add(fp.pattern)
        if fp.location_found == "dns":
            dns_fp_responses.add(fp.pattern)

    print(f"Fetching CL fingerprints from {CL_HTTP}")
    resp = requests.get(CL_HTTP)
    assert resp.status_code == 200
    csv_reader = csv.DictReader(io.StringIO(resp.text))
    for row in csv_reader:
        fp = Fingerprint(
            name="cl." + row["name"],
            location_found=row["location_found"],
            pattern=re.escape(row["pattern"]),
            confidence_no_fp=row["confidence_no_fp"],
            exp_url=row["exp_url"],
            source=ast.literal_eval(row["source"]),
            scope=row["scope"],
            expected_countries=ast.literal_eval(row["expected_countries"]),
            notes=row["notes"],
        )
        if fp.location_found == "header":
            fp.location_found = "header.location"
        maybe_add_fingerprint(fp)

    print(f"Fetching CL fingerprints from {CL_DNS}")
    resp = requests.get(CL_DNS)
    assert resp.status_code == 200
    csv_reader = csv.DictReader(io.StringIO(resp.text))
    for row in csv_reader:
        fp = Fingerprint(
            name="cl." + row["name"],
            location_found="dns",
            pattern=row["response"],
            confidence_no_fp=row["confidence_no_fp"],
            exp_url=row["exp_url"],
            source=ast.literal_eval(row["source"]),
            scope=row["scope"],
            expected_countries=ast.literal_eval(row["expected_countries"]),
            notes=row["notes"],
        )
        maybe_add_fingerprint(fp)

    print(f"Fetching CP fingerprints from {CP_FINGERPRINTS_CP}")
    resp = requests.get(CP_FINGERPRINTS_CP)
    for line in resp.text.split("\n"):
        if line == "":
            continue
        d = json.loads(line)
        pattern = d["pattern"]
        fp_name = "cp." + d["fingerprint"]
        if pattern.startswith("http://") or pattern.startswith("https://"):
            maybe_add_fingerprint(
                Fingerprint(
                    name=fp_name,
                    source=["censored planet"],
                    location_found="body",
                    pattern=pattern,
                )
            )
            maybe_add_fingerprint(
                Fingerprint(
                    name=fp_name,
                    source=["censored planet"],
                    location_found="header.location",
                    pattern="^" + pattern,
                )
            )
            continue

        if pattern.lower().startswith("Location: "):
            maybe_add_fingerprint(
                Fingerprint(
                    name=fp_name,
                    source=["censored planet"],
                    location_found="header.location",
                    pattern="^" + pattern.lstrip("Location: "),
                )
            )
            continue

        maybe_add_fingerprint(
            Fingerprint(
                name=fp_name,
                source=["censored planet"],
                location_found="body",
                pattern=pattern,
            )
        )

    for cc, fingerprint_list in ooni_fingerprint.items():
        for idx, fp in enumerate(fingerprint_list):
            fp_name = f"ooni.{cc.lower()}_{idx}"
            location_found = ""
            if "body_match" in fp:
                location_found = "body"
                pattern = re.escape(fp["body_match"])
            elif "header_name" in fp:
                header_name = fp["header_name"].lower()
                location_found = f"header.{header_name}"
                if "header_prefix" in fp:
                    pattern = "^" + re.escape(fp["header_prefix"])
                elif "header_full" in fp:
                    pattern = "^" + re.escape(fp["header_full"]) + "$"
                else:
                    raise Exception("Unknown header position")
            elif "dns_full" in fp:
                pattern = fp["dns_full"]
                location_found = "dns"

            maybe_add_fingerprint(
                Fingerprint(
                    location_found=location_found,
                    name=fp_name,
                    pattern=pattern,
                    confidence_no_fp=5,
                    exp_url="",
                    source=["ooni"],
                    scope=ooni_scope_to_cl.get(fp["locality"]),
                    expected_countries=[cc],
                    notes="",
                )
            )

    fieldnames = [f.name for f in fields(Fingerprint)]
    with open("fingerprints_http.csv", "w") as out_file:
        writer = csv.DictWriter(out_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(
            map(
                lambda fp: asdict(fp),
                filter(lambda fp: fp.location_found != "dns", fingerprints),
            )
        )

    with open("fingerprints_dns.csv", "w") as out_file:
        writer = csv.DictWriter(out_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(
            map(
                lambda fp: asdict(fp),
                filter(lambda fp: fp.location_found == "dns", fingerprints),
            )
        )


main()
