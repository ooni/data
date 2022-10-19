import requests
from typing import Optional


def get_raw_measurement(report_id: str, input: Optional[str] = None) -> bytes:
    params = params = {"report_id": report_id, "full": True}
    if input:
        params["input"] = input
    r = requests.get("https://api.ooni.io/api/v1/measurement_meta", params=params)
    j = r.json()
    return j["raw_measurement"].encode("utf-8")
