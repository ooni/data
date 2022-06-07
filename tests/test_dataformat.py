import requests

from typing import Optional

from oonidata.dataformat import load_measurement


def get_raw_measurement(report_id: str, input: Optional[str] = None):
    params = params = {"report_id": report_id, "full": True}
    if input:
        params["input"] = input
    r = requests.get("https://api.ooni.io/api/v1/measurement_meta", params=params)
    j = r.json()
    return j["raw_measurement"]


def test_dataformat_web_connectivity():
    raw_msmt = get_raw_measurement(
        "20220607T115805Z_webconnectivity_BR_270374_n1_69vdpoRbUpU1Lwjz",
        "https://ooni.org/",
    )
    msmt = load_measurement(raw_msmt)
    assert msmt.measurement_start_time.startswith("2022")
    assert len(msmt.test_keys.requests) > 0

    raw_msmt = get_raw_measurement(
        "20220107T222039Z_webconnectivity_IL_42925_n1_18Kwpmtx9nYVVoeM",
        "https://ooni.org/",
    )
    msmt = load_measurement(raw_msmt)
    assert msmt.measurement_start_time.startswith("2022")
    assert len(msmt.test_keys.requests) > 0
