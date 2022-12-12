from typing import Optional, Tuple
from urllib.parse import urlparse, parse_qs

EXPLORER_URLS = {
    "20221101_ru_tcp_blocked_twitter": "https://explorer.ooni.org/measurement/20221101T055122Z_webconnectivity_RU_8402_n1_lG7OkFM4GicboQ36?input=https%3A%2F%2Ftwitter.com%2F"
}


def get_report_id_input(explorer_url: str) -> Tuple[str, Optional[str]]:
    p = urlparse(explorer_url)
    input_ = parse_qs(p.query).get("input", [None])[0]
    report_id = p.path.split("/")[-1]
    return report_id, input_
