from dataclasses import dataclass, field
from datetime import date, timedelta
import logging

from typing import Any, Dict, Optional, Tuple, List
from urllib.parse import urlparse
from oonidata.observations import WebControlObservation
from oonidata.datautils import one_day_dict

from oonidata.db.connections import ClickhouseConnection

log = logging.getLogger("oonidata.processing")


@dataclass
class WebGroundTruth:
    vp_asn: int
    vp_cc: str
    is_trusted_vp: bool

    hostname: str
    ip: Optional[str]
    port: Optional[int]

    dns_failure: Optional[str]
    dns_success: Optional[bool]

    tcp_failure: Optional[str]
    tcp_success: Optional[bool]

    tls_failure: Optional[str]
    tls_success: Optional[bool]
    tls_is_certificate_valid: Optional[bool]

    http_request_url: Optional[str]
    http_failure: Optional[str]
    http_success: Optional[bool]
    http_response_body_length: Optional[int]

    count: int


def make_ground_truths_from_web_control(
    web_control_observations: List[WebControlObservation],
    count: int = 1,
) -> List[WebGroundTruth]:
    wgt_list = []
    for obs in web_control_observations:
        wgt = WebGroundTruth(
            vp_asn=0,
            vp_cc="ZZ",
            is_trusted_vp=True,
            hostname=obs.hostname,
            ip=obs.ip,
            port=obs.port,
            dns_failure=obs.dns_failure,
            dns_success=obs.dns_success,
            tcp_failure=obs.tcp_failure,
            tcp_success=obs.tcp_success,
            tls_failure=obs.tls_failure,
            tls_success=obs.tls_success,
            tls_is_certificate_valid=obs.tls_failure is None
            and obs.tls_success is True,
            http_request_url=obs.http_request_url,
            http_failure=obs.http_failure,
            http_success=obs.http_success,
            http_response_body_length=obs.http_response_body_length,
            count=count,
        )
        wgt_list.append(wgt)
    return wgt_list


def get_web_ground_truth(
    db: ClickhouseConnection, measurement_day: date
) -> List[WebGroundTruth]:
    start_day = measurement_day.strftime("%Y-%m-%d")
    end_day = (measurement_day + timedelta(days=1)).strftime("%Y-%m-%d")
    wgt_list = []
    column_names = [
        "hostname",
        "ip",
        "port",
        "dns_failure",
        "dns_success",
        "tcp_failure",
        "tcp_success",
        "tls_failure",
        "tls_success",
        "tls_is_certificate_valid",
        "http_request_url",
        "http_success",
        "http_failure",
        "http_response_body_length",
    ]
    q = """
    SELECT (
        hostname,
        ip,
        port,
        dns_failure,
        dns_success,
        tcp_failure,
        tcp_success,
        tls_failure,
        tls_success,
        (tls_failure is NULL AND tls_success = 1) AS tls_is_certificate_valid,
        http_request_url,
        http_failure,
        http_success,
        http_response_body_length,
        COUNT()
    )
    FROM obs_web_ctrl
    WHERE measurement_start_time > %(start_day)s AND measurement_start_time < %(end_day)s
    """
    q += "GROUP BY "
    q += ",".join(column_names)

    for res in db.execute_iter(q, dict(start_day=start_day, end_day=end_day)):
        row = res[0]
        wgt_dict = {k: row[idx] for idx, k in enumerate(column_names + ["count"])}
        wgt_dict["vp_cc"] = "ZZ"
        wgt_dict["vp_asn"] = 0
        wgt_dict["is_trusted_vp"] = True
        wgt_list.append(WebGroundTruth(**wgt_dict))
    return wgt_list


class WebGroundTruthDB:
    def __init__(self, ground_truths: List[WebGroundTruth]):
        self.truths = ground_truths

    def lookup(
        self,
        probe_cc: str,
        probe_asn: int,
        hostname: Optional[str] = None,
        ip: Optional[str] = None,
        port: Optional[int] = None,
        http_request_url: Optional[str] = None,
    ) -> List[WebGroundTruth]:
        matches = []
        for gt in self.truths:
            # We want to exclude all the ground truths that are from the same
            # vantage point as the probe
            if gt.vp_asn == probe_asn and gt.vp_cc == probe_cc:
                continue
            if hostname and gt.hostname != hostname:
                continue
            if ip and gt.ip != ip:
                continue
            if port is not None and gt.port != port:
                continue
            if http_request_url and gt.http_request_url != http_request_url:
                continue
            matches.append(gt)
        return matches


class BodyDB:
    def __init__(self, db: ClickhouseConnection):
        self.db = db

    def lookup(self, body_sha1: str) -> List[str]:
        return []
