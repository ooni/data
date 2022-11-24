from dataclasses import dataclass, field
import dataclasses
from datetime import date, timedelta, datetime
import logging
import sqlite3

from typing import Any, Dict, Optional, Tuple, List, NamedTuple
from urllib.parse import urlparse
from oonidata.netinfo import NetinfoDB
from oonidata.observations import WebControlObservation
from oonidata.datautils import one_day_dict

from oonidata.compat import add_slots
from oonidata.db.connections import ClickhouseConnection

log = logging.getLogger("oonidata.processing")


class WebGroundTruth(NamedTuple):
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

    timestamp: datetime
    count: int

    ip_asn: Optional[int]
    ip_as_org_name: Optional[str]


def make_ground_truths_from_web_control(
    web_control_observations: List[WebControlObservation],
    count: int = 1,
) -> List[WebGroundTruth]:
    wgt_list = []
    # TODO: pass a netinfodb to lookup the ip_asn and ip_as_org_name
    for obs in web_control_observations:
        wgt = WebGroundTruth(
            vp_asn=0,
            vp_cc="ZZ",
            timestamp=obs.measurement_start_time,
            is_trusted_vp=True,
            hostname=obs.hostname,
            ip=obs.ip,
            ip_asn=0,
            ip_as_org_name="",
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
        "timestamp",
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
        toStartOfDay(measurement_start_time) as timestamp,
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
        # We add these later in the ground truth DB
        wgt_dict["ip_asn"] = 0
        wgt_dict["ip_as_org_name"] = ""
        wgt_list.append(WebGroundTruth(**wgt_dict))
    return wgt_list


class WebGroundTruthDB:
    def __init__(self, ground_truths: List[WebGroundTruth], netinfodb: NetinfoDB):
        self.db = sqlite3.connect(":memory:")
        self.db.execute(
            """
        CREATE TABLE ground_truth (
            vp_asn INT,
            vp_cc TEXT,
            is_trusted_vp INT,

            timestamp TEXT,

            hostname TEXT,
            ip TEXT,
            ip_asn INT,
            ip_as_org_name TEXT,
            port TEXT,

            dns_failure TEXT,
            dns_success INT,

            tcp_failure TEXT,
            tcp_success INT,

            tls_failure TEXT,
            tls_success INT,
            tls_is_certificate_valid INT,

            http_request_url TEXT,
            http_failure TEXT,
            http_success INT,
            http_response_body_length INT,
            count INT
        )
        """
        )
        self.db.commit()
        self.db.execute("CREATE INDEX vp_idx ON ground_truth(vp_asn, vp_cc)")
        self.db.execute("CREATE INDEX hostname_idx ON ground_truth(hostname)")
        self.db.execute("CREATE INDEX ip_port_idx ON ground_truth(ip, port)")
        self.db.execute(
            "CREATE INDEX http_request_url_idx ON ground_truth(http_request_url)"
        )
        self.db.commit()
        self.column_names = WebGroundTruth._fields

        c_str = ",".join(self.column_names)
        v_str = ",".join(["?" for _ in range(len(self.column_names))])
        q_str = f"INSERT INTO ground_truth ({c_str}) VALUES ({v_str})"
        for gt in ground_truths:
            row = gt
            if gt.ip:
                ip_info = netinfodb.lookup_ip(gt.timestamp, gt.ip)
                row = gt[:-2] + (ip_info.as_info.asn, ip_info.as_info.as_org_name)
            self.db.execute(q_str, row)
        self.db.commit()

    def lookup(
        self,
        probe_cc: str,
        probe_asn: int,
        hostname: Optional[str] = None,
        ip: Optional[str] = None,
        port: Optional[int] = None,
        http_request_url: Optional[str] = None,
    ) -> List[WebGroundTruth]:
        c_str = ",\n".join(self.column_names)
        q = f"""
        SELECT
        {c_str}
        FROM ground_truth
        WHERE vp_asn != ? AND vp_cc != ?
        """
        # We want to exclude all the ground truths that are from the same
        # vantage point as the probe
        q_args = [probe_cc, probe_asn]
        if hostname:
            q += " AND hostname = ? "
            q_args.append(hostname)
        if ip:
            q += " AND ip = ? "
            q_args.append(ip)
        if port:
            q += " AND port = ? "
            q_args.append(port)

        if http_request_url:
            q += " AND http_request_url = ? "
            q_args.append(port)
        matches = []
        for row in self.db.execute(q, q_args):
            gt = WebGroundTruth(*row)
            matches.append(gt)
        return matches


class BodyDB:
    def __init__(self, db: ClickhouseConnection):
        self.db = db

    def lookup(self, body_sha1: str) -> List[str]:
        return []
