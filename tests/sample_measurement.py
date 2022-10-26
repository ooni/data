import sys
from typing import Optional
import requests
from urllib.parse import urlparse, parse_qs

def print_sample_line(report_id: str, input: Optional[str]):
    params = params = {"report_id": report_id}
    if input:
        params["input"] = input
    r = requests.get("https://api.ooni.io/api/v1/measurement_meta", params=params)
    j = r.json()
    measurement_uid = j["measurement_uid"]
    line = f'("{measurement_uid}", "{report_id}", '
    if input:
        line += f'"{input}"),'
    else:
        line += "None),"
    print(line)
    return measurement_uid


samples = [
    (
        "20220627T131610Z_webconnectivity_GB_5089_n1_hPwPFmWSlBooLToC",
        "https://ooni.org/",
    ),
    (
        "20220608T122003Z_webconnectivity_IR_58224_n1_AcrDNmCaHeCbDoNj",
        "https://www.youtube.com/",
    ),
    (
        "20220608T120927Z_webconnectivity_RU_41668_n1_wuoaKW00hbGU12Yw",
        "http://proxy.org/",
    ),
    (
        "20220626T215355Z_webconnectivity_IR_206065_n1_aoeFoexkL6onyiqN",
        "https://thepiratebay.org/",
    ),
    (
        "20220627T134105Z_webconnectivity_DE_3209_n1_OxtDrquootq2Ud5G",
        "https://thepiratebay.org/",
    ),
    (
        "20220627T125710Z_webconnectivity_FR_5410_n1_KMkIWk9q4gZRq9gS",
        "https://thepiratebay.org/",
    ),
    (
        "20220625T234722Z_webconnectivity_HU_20845_n1_Kg7ARyGpKG58zIZU",
        "https://thepiratebay.org/",
    ),
]


def print_samples():
    uids = []
    for report_id, input in samples:
        uids.append(print_sample_line(report_id, input))
    for u in uids:
        print(f'measurements["{u}"]')


def main():
    if len(sys.argv) < 2:
        print("Usage: sample_measurement.py report_id | explorer_url [input]")
        sys.exit(1)

    input = None
    report_id = sys.argv[1]
    if len(sys.argv) > 2:
        input = sys.argv[2]

    if "explorer.ooni.org" in report_id:
        p = urlparse(report_id)
        report_id = p.path.split("/")[-1]
        qs = parse_qs(p.query)
        if "input" in qs:
            input = qs["input"][0]

    uid = print_sample_line(report_id, input)
    print(f'measurements["{uid}"]')


if __name__ == "__main__":
    main()
