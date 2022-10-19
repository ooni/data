from base64 import b64encode
from copy import deepcopy

import orjson

from oonidata.dataformat import WebConnectivity, load_measurement, HTTPTransaction
from oonidata.apiclient import get_raw_measurement


def test_dataformat_web_connectivity():
    raw_msmt = get_raw_measurement(
        "20220607T115805Z_webconnectivity_BR_270374_n1_69vdpoRbUpU1Lwjz",
        "https://ooni.org/",
    )
    msmt = load_measurement(orjson.loads(raw_msmt))
    assert msmt.measurement_start_time.startswith("2022")
    assert isinstance(msmt, WebConnectivity)
    assert msmt.test_keys
    assert msmt.test_keys.requests
    assert len(msmt.test_keys.requests) > 0

    raw_msmt = get_raw_measurement(
        "20220107T222039Z_webconnectivity_IL_42925_n1_18Kwpmtx9nYVVoeM",
        "https://ooni.org/",
    )
    msmt = load_measurement(orjson.loads(raw_msmt))
    assert isinstance(msmt, WebConnectivity)
    assert msmt.measurement_start_time.startswith("2022")
    assert msmt.test_keys
    assert msmt.test_keys.requests
    assert len(msmt.test_keys.requests) > 0


def test_http_transaction():
    data = {
        "failure": None,
        "request": {
            "body": "",
            "body_is_truncated": False,
            "headers_list": [
                [
                    "User-Agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
                ]
            ],
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"
            },
            "method": "POST",
            "tor": {"exit_ip": None, "exit_name": None, "is_tor": False},
            "url": "http://example.com/",
        },
        "response": {
            "body": "XXX",
            "body_is_truncated": False,
            "code": 501,
            "headers_list": [["Server", "nginx/0.3.33"]],
            "headers": {
                "Server": "nginx/0.3.33",
            },
        },
        "transaction_id": 1,
    }
    msmt = HTTPTransaction.from_dict(data)
    assert msmt.response
    assert msmt.response.body_str == msmt.response.body

    data1 = deepcopy(data)
    del data1["response"]["headers_list"]
    msmt = HTTPTransaction.from_dict(data1)
    # Creation of the headers_list from headers is working
    assert msmt.response
    assert msmt.response.headers_list_str
    assert msmt.response.headers_list_str[0][0] == "Server"

    assert msmt.response.headers_list_bytes
    assert msmt.response.headers_list_bytes[0][0] == "Server"
    assert msmt.response.headers_list_bytes[0][1] == b"nginx/0.3.33"

    assert msmt.response.headers_list_str
    assert msmt.response.headers_list_str[0][1] == "nginx/0.3.33"

    # Body bytes creation works in the case of base64 data
    data2 = deepcopy(data)
    data2["response"]["body"] = {"format": "base64", "data": b64encode(b"XXX")}
    msmt = HTTPTransaction.from_dict(data2)

    assert msmt.response
    assert msmt.response.headers_list_str
    assert msmt.response.headers_list_str[0][0] == "Server"
    assert msmt.response.body_bytes == b"XXX"
