from datetime import date, timedelta, datetime
import logging
import sqlite3
from collections.abc import Iterable

from typing import Any, Generator, Optional, Tuple, List, NamedTuple
from oonidata.models.observations import WebControlObservation, WebObservation
from oonidata.netinfo import NetinfoDB

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


def iter_ground_truths_from_web_control(
    web_control_observations: List[WebControlObservation],
    netinfodb: NetinfoDB,
    count: int = 1,
) -> Generator[Tuple[Tuple[str, ...], List], None, None]:
    # TODO: pass a netinfodb to lookup the ip_asn and ip_as_org_name
    for obs in web_control_observations:
        ip_as_org_name = ""
        ip_asn = 0
        if obs.ip:
            ip_info = netinfodb.lookup_ip(obs.measurement_start_time, obs.ip)
            ip_asn = ip_info.as_info.asn
            ip_as_org_name = ip_info.as_info.as_org_name

        wgt = WebGroundTruth(
            vp_asn=0,
            vp_cc="ZZ",
            timestamp=obs.measurement_start_time,
            is_trusted_vp=True,
            hostname=obs.hostname,
            ip=obs.ip,
            ip_asn=ip_asn,
            ip_as_org_name=ip_as_org_name,
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
        yield WebGroundTruth._fields, list(wgt)


def iter_web_ground_truths(
    db: ClickhouseConnection, netinfodb: NetinfoDB, measurement_day: date
) -> Generator[Tuple[List[str], List], None, None]:
    start_day = measurement_day.strftime("%Y-%m-%d")
    end_day = (measurement_day + timedelta(days=1)).strftime("%Y-%m-%d")
    column_names = [
        "timestamp",
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
        "http_failure",
        "http_success",
    ]
    q = """
    SELECT (
        toStartOfDay(measurement_start_time) as timestamp,
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
        arrayMax(topK(1)(http_response_body_length)) as http_response_body_length,
        COUNT()
    )
    FROM obs_web_ctrl
    WHERE measurement_start_time > %(start_day)s AND measurement_start_time < %(end_day)s
    """
    q += "GROUP BY "
    q += ",".join(column_names)

    for res in db.execute_iter(q, dict(start_day=start_day, end_day=end_day)):
        row = res[0]

        c_names = column_names + [
            "http_response_body_length",
            "count",
            "ip_asn",
            "ip_as_org_name",
            "vp_asn",
            "vp_cc",
            "is_trusted_vp",
        ]
        row_extra: List[Any] = [None, None]
        # TODO move this directly into the obs_web_ctrl table
        if row[2]:
            ip_info = netinfodb.lookup_ip(row[0], row[2])
            row_extra = [ip_info.as_info.asn, ip_info.as_info.as_org_name]

        # vp_asn, vp_cc, is_trusted_vp
        row_extra.append(0)
        row_extra.append("ZZ")
        row_extra.append(1)

        yield c_names, row + tuple(row_extra)


class WebGroundTruthDB:
    """
    The Web Ground Truth database is used by the websites experiment results
    processor for looking up ground truths related to a particular set of
    measurements.

    Currently it's implemented through an in-memory SQLite databases which
    contains all the ground_truths for a particular day.
    """

    _indexes = (
        ("hostname_idx", "hostname, vp_asn, vp_cc"),
        ("ip_port_idx", "ip, port, vp_asn, vp_cc"),
        ("http_request_url_idx", "http_request_url, vp_asn, vp_cc"),
    )
    column_names = WebGroundTruth._fields

    def __init__(self, connect_str: str = ":memory:"):
        self._table_name = "ground_truth"
        self.db = sqlite3.connect(connect_str)
        self.db.execute("pragma synchronous = normal;")
        self.db.execute("pragma journal_mode = WAL;")
        self.db.execute("pragma temp_store = memory;")

    def build_from_rows(self, rows: Iterable):
        self.db.execute(self.create_query)
        self.db.commit()

        for column_names, row in rows:
            v_str = ",".join(["?" for _ in range(len(column_names))])
            q_insert_with_values = (
                f"{self.insert_query(column_names=column_names)} VALUES ({v_str})"
            )
            self.db.execute(q_insert_with_values, row)
        self.db.commit()
        self.db.execute("pragma vacuum;")
        self.db.execute("pragma optimize;")
        self.create_indexes()

    def build_from_existing(self, db_str: str):
        with sqlite3.connect(db_str) as src_db:
            self.db = sqlite3.connect(":memory:")
            src_db.backup(self.db)

    def close(self):
        self.db.close()

    def create_indexes(self):
        for idx_name, idx_value in self._indexes:
            self.db.execute(
                f"CREATE INDEX {self._table_name}_{idx_name} ON {self._table_name}({idx_value})"
            )
        self.db.commit()

    @property
    def create_query(self):
        return f"""
        CREATE TABLE {self._table_name} (
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

    def insert_query(self, column_names: List[str]):
        c_str = ",".join(column_names)
        q_str = f"INSERT INTO {self._table_name} ({c_str})\n"
        return q_str

    def select_query(
        self,
        table_name: str,
        probe_cc: str,
        probe_asn: int,
        hostnames: Optional[List[str]] = None,
        ip_ports: Optional[List[Tuple[str, Optional[int]]]] = None,
        http_request_urls: Optional[List[str]] = None,
    ) -> Tuple[str, List]:
        assert (
            hostnames or ip_ports or http_request_urls
        ), "one of either hostnames or ip_ports or http_request_urls should be set"
        c_str = ",\n".join(
            map(
                lambda r: r if r != "count" else "SUM(count) as count",
                self.column_names,
            )
        )
        q = f"""
        SELECT
        {c_str}
        FROM {table_name}
        WHERE vp_asn != ? AND vp_cc != ? AND (
        """
        # We want to exclude all the ground truths that are from the same
        # vantage point as the probe
        q_args = [probe_cc, probe_asn]

        sub_query_parts = []
        if hostnames:
            sub_q = "("
            sub_q += "OR ".join(
                # When hostname was supplied, we only care about it in relation to DNS resolutions
                [" hostname = ? AND dns_success = 1 " for _ in range(len(hostnames))]
            )
            sub_q += ")"
            q_args += hostnames
            sub_query_parts.append(sub_q)

        if ip_ports:
            sub_q = "("
            ip_port_l = []
            for ip, port in ip_ports:
                assert ip is not None, "empty IP in query"
                ip_port_q = "(ip = ?"
                q_args.append(ip)
                if port is not None:
                    ip_port_q += " AND port = ?"
                    q_args.append(port)
                ip_port_q += ")"
                ip_port_l.append(ip_port_q)
            sub_q += "OR ".join(ip_port_l)
            sub_q += ")"
            sub_query_parts.append(sub_q)

        if http_request_urls:
            sub_q = "("
            sub_q += "OR ".join(
                [" http_request_url = ?" for _ in range(len(http_request_urls))]
            )
            sub_q += ")"
            q_args += http_request_urls
            sub_query_parts.append(sub_q)

        q += "OR ".join(sub_query_parts)
        q += ")"
        q += "GROUP BY "
        aggregate_columns = list(self.column_names)
        aggregate_columns.remove("count")
        q += ", ".join(aggregate_columns)
        return q, q_args

    def iter_select(
        self,
        probe_cc: str,
        probe_asn: int,
        hostnames: Optional[List[str]] = None,
        ip_ports: Optional[List[Tuple[str, Optional[int]]]] = None,
        http_request_urls: Optional[List[str]] = None,
    ) -> Generator[Tuple[Tuple[str, ...], Any], None, None]:
        q, q_args = self.select_query(
            table_name=self._table_name,
            probe_cc=probe_cc,
            probe_asn=probe_asn,
            hostnames=hostnames,
            ip_ports=ip_ports,
            http_request_urls=http_request_urls,
        )
        for row in self.db.execute(q, q_args):
            yield self.column_names, row

    def lookup(
        self,
        probe_cc: str,
        probe_asn: int,
        hostnames: Optional[List[str]] = None,
        ip_ports: Optional[List[Tuple[str, Optional[int]]]] = None,
        http_request_urls: Optional[List[str]] = None,
    ) -> List[WebGroundTruth]:
        iter_rows = self.iter_select(
            probe_cc=probe_cc,
            probe_asn=probe_asn,
            hostnames=hostnames,
            ip_ports=ip_ports,
            http_request_urls=http_request_urls,
        )
        matches = []
        for column_names, row in iter_rows:
            gt = WebGroundTruth(**dict(zip(column_names, row)))
            matches.append(gt)
        return matches

    def lookup_by_web_obs(self, web_obs: List[WebObservation]) -> List[WebGroundTruth]:
        """
        Returns the list of WebGroundTruth that are relevant to a particular set
        of related web observations.

        Every web_obs in the list needs to be related to the same probe_cc,
        probe_asn pair.
        """
        to_lookup_hostnames = set()
        to_lookup_ip_ports = set()
        to_lookup_http_request_urls = set()
        probe_cc = web_obs[0].probe_cc
        probe_asn = web_obs[0].probe_asn
        for web_o in web_obs:
            # All the observations in this group should be coming from the
            # same probe
            assert web_o.probe_cc == probe_cc
            assert web_o.probe_asn == probe_asn
            if web_o.hostname is not None:
                to_lookup_hostnames.add(web_o.hostname)
            if web_o.ip is not None:
                to_lookup_ip_ports.add((web_o.ip, web_o.port))
            if web_o.http_request_url is not None:
                to_lookup_http_request_urls.add(web_o.http_request_url)

        return self.lookup(
            probe_cc=probe_cc,
            probe_asn=probe_asn,
            ip_ports=list(to_lookup_ip_ports),
            http_request_urls=list(to_lookup_http_request_urls),
            hostnames=list(to_lookup_hostnames),
        )


class BodyDB:
    def __init__(self, db: ClickhouseConnection):
        self.db = db

    def lookup(self, body_sha1: str) -> List[str]:
        return []
