from pathlib import Path
from typing import Optional
import orjson
import requests


def get_raw_measurement(report_id: str, input: Optional[str] = None) -> bytes:
    params = params = {"report_id": report_id, "full": True}
    if input:
        params["input"] = input
    r = requests.get("https://api.ooni.io/api/v1/measurement_meta", params=params)
    j = r.json()
    return j["raw_measurement"].encode("utf-8")


def get_measurement_dict(report_id: str, input: Optional[str] = None) -> dict:
    params = params = {"report_id": report_id, "full": True}
    if input:
        params["input"] = input
    r = requests.get("https://api.ooni.io/api/v1/measurement_meta", params=params)
    j = r.json()
    msmt_dict = orjson.loads(j["raw_measurement"])
    msmt_dict["measurement_uid"] = j["measurement_uid"]
    return msmt_dict


def get_measurement_dict_by_uid(measurement_uid: str) -> dict:
    r = requests.get(f"https://api.ooni.io/api/v1/measurement/{measurement_uid}")
    msmt_dict = r.json()
    msmt_dict["measurement_uid"] = measurement_uid
    return msmt_dict
