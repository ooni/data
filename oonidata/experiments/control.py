from dataclasses import dataclass, field
from datetime import date
import logging

from typing import Any, Dict, Optional, Tuple, List
from urllib.parse import urlparse
from oonidata.dataformat import WebConnectivity, WebConnectivityControl
from oonidata.datautils import one_day_dict

from oonidata.db.connections import ClickhouseConnection

log = logging.getLogger("oonidata.processing")


@dataclass
class TCPControl:
    address: str
    reachable_cc_asn: List[Tuple[str, int]] = field(default_factory=list)
    unreachable_cc_asn: List[Tuple[str, int]] = field(default_factory=list)


def make_tcp_control_map(
    day: date, domain_name: str, db: ClickhouseConnection
) -> Dict[str, TCPControl]:
    tcp_control_map = {}
    q_params = one_day_dict(day)
    q_params["domain_name"] = domain_name

    q = """SELECT probe_cc, probe_asn, ip, port, failure FROM obs_tcp
    WHERE domain_name = %(domain_name)s 
    AND timestamp >= %(start_day)s
    AND timestamp <= %(end_day)s
    GROUP BY probe_cc, probe_asn, ip, port, failure;
    """
    res = db.execute(q, q_params)
    if isinstance(res, list) and len(res) > 0:
        for probe_cc, probe_asn, ip, port, failure in res:
            address = f"{ip}:{port}"
            tcp_control_map[address] = tcp_control_map.get(address, TCPControl(address))
            if not failure:
                tcp_control_map[address].reachable_cc_asn.append((probe_cc, probe_asn))
            else:
                tcp_control_map[address].unreachable_cc_asn.append(
                    (probe_cc, probe_asn)
                )
    return tcp_control_map


@dataclass
class HTTPControl:
    url: str
    failure_cc_asn: List[Tuple[str, int]] = field(default_factory=list)
    ok_cc_asn: List[Tuple[str, int]] = field(default_factory=list)

    response_body_length: int = 0
    response_body_sha1: str = ""
    response_body_title: str = ""
    response_body_meta_title: str = ""

    response_status_code: int = 0


def maybe_get_first(l: list, default_value: Any = None) -> Optional[Any]:
    try:
        return l[0]
    except IndexError:
        return default_value


def make_http_control_map(
    day: date, domain_name: str, db: ClickhouseConnection
) -> Dict[str, HTTPControl]:
    http_control_map = {}

    q_params = one_day_dict(day)
    q_params["domain_name"] = domain_name

    q = """SELECT probe_cc, probe_asn, request_url, failure FROM obs_http
    WHERE domain_name = %(domain_name)s 
    AND timestamp >= %(start_day)s
    AND timestamp <= %(end_day)s
    GROUP BY probe_cc, probe_asn, request_url, failure;
    """
    res = db.execute(q, q_params)
    if isinstance(res, list) and len(res) > 0:
        for probe_cc, probe_asn, request_url, failure in res:
            http_control_map[request_url] = http_control_map.get(
                request_url, HTTPControl(request_url)
            )
            if not failure:
                http_control_map[request_url].ok_cc_asn.append((probe_cc, probe_asn))
            else:
                http_control_map[request_url].failure_cc_asn.append(
                    (probe_cc, probe_asn)
                )

    q = """SELECT request_url,
    topK(1)(response_body_sha1),
    topK(1)(response_body_length),
    topK(1)(response_body_title),
    topK(1)(response_body_meta_title),
    topK(1)(response_status_code)
    FROM obs_http
    WHERE failure IS NULL
    AND domain_name = %(domain_name)s 
    AND timestamp >= %(start_day)s
    AND timestamp <= %(end_day)s
    GROUP BY request_url;
    """
    res = db.execute(q, q_params)
    if isinstance(res, list) and len(res) > 0:
        for (
            request_url,
            response_body_sha1,
            response_body_length,
            response_body_title,
            response_body_meta_title,
            response_status_code,
        ) in res:
            http_control_map[request_url] = http_control_map.get(
                request_url, HTTPControl(request_url)
            )
            http_control_map[request_url].response_body_sha1 = maybe_get_first(
                response_body_sha1, ""
            )
            http_control_map[request_url].response_body_length = maybe_get_first(
                response_body_length, ""
            )
            http_control_map[request_url].response_body_title = maybe_get_first(
                response_body_title, ""
            )
            http_control_map[request_url].response_body_meta_title = maybe_get_first(
                response_body_meta_title, ""
            )
            http_control_map[request_url].response_status_code = maybe_get_first(
                response_status_code, ""
            )

    return http_control_map


@dataclass
class DNSControl:
    domain: str
    nxdomain_cc_asn: List[Tuple[str, int]] = field(default_factory=list)
    failure_cc_asn: List[Tuple[str, int]] = field(default_factory=list)
    ok_cc_asn: List[Tuple[str, int]] = field(default_factory=list)
    tls_consistent_answers: List[str] = field(default_factory=list)
    answers_map: Dict[str, List[Tuple[str, str]]] = field(default_factory=dict)


def make_dns_control(
    day: date, domain_name: str, db: ClickhouseConnection
) -> DNSControl:
    dns_baseline = DNSControl(domain_name)

    q_params = one_day_dict(day)
    q_params["domain_name"] = domain_name

    q = """SELECT DISTINCT(ip) FROM obs_tls
    WHERE is_certificate_valid = 1 
    AND domain_name = %(domain_name)s 
    AND timestamp >= %(start_day)s
    AND timestamp <= %(end_day)s;
    """
    res = db.execute(q, q_params)
    if isinstance(res, list) and len(res) > 0:
        dns_baseline.tls_consistent_answers = [row[0] for row in res]

    q = """SELECT probe_cc, probe_asn, failure, answer FROM obs_dns
    WHERE domain_name = %(domain_name)s 
    AND timestamp >= %(start_day)s
    AND timestamp <= %(end_day)s
    GROUP BY probe_cc, probe_asn, failure, answer;
    """
    res = db.execute(q, q_params)
    if isinstance(res, list) and len(res) > 0:
        for probe_cc, probe_asn, failure, ip in res:
            if not failure:
                dns_baseline.ok_cc_asn.append((probe_cc, probe_asn))
                dns_baseline.answers_map[probe_cc] = dns_baseline.answers_map.get(
                    probe_cc, []
                )
                if ip:
                    dns_baseline.answers_map[probe_cc].append((probe_asn, ip))
                else:
                    log.error(
                        f"No IP present for {domain_name} {probe_cc} ({probe_asn}) in baseline"
                    )
            else:
                dns_baseline.failure_cc_asn.append((probe_cc, probe_asn))
                if failure == "dns_nxdomain_error":
                    dns_baseline.nxdomain_cc_asn.append((probe_cc, probe_asn))

    return dns_baseline


def make_dns_control_from_wc(
    msmt_input: str, control: WebConnectivityControl
) -> DNSControl:
    domain_name = urlparse(msmt_input).hostname

    assert domain_name is not None, "domain_name is None"

    if not control or not control.dns:
        return DNSControl(domain=domain_name)

    nxdomain_cc_asn = []
    if control.dns.failure == "dns_nxdomain_error":
        nxdomain_cc_asn.append(("ZZ", 0))

    ok_cc_asn = []
    failure_cc_asn = []
    if control.dns.failure is not None:
        failure_cc_asn.append(("ZZ", 0))
    else:
        ok_cc_asn.append(("ZZ", 0))

    answers_map = {}
    if control.dns.addrs:
        answers_map["ZZ"] = [(0, ip) for ip in control.dns.addrs]

    return DNSControl(
        domain=domain_name,
        answers_map=answers_map,
        ok_cc_asn=ok_cc_asn,
        nxdomain_cc_asn=nxdomain_cc_asn,
        failure_cc_asn=failure_cc_asn,
    )


def make_tcp_control_from_wc(
    control: WebConnectivityControl,
) -> Dict[str, TCPControl]:
    if not control or not control.tcp_connect:
        return {}

    tcp_b_map = {}
    for key, status in control.tcp_connect.items():
        if status.failure == None:
            tcp_b_map[key] = TCPControl(address=key, reachable_cc_asn=[("ZZ", 0)])
        else:
            tcp_b_map[key] = TCPControl(address=key, unreachable_cc_asn=[("ZZ", 0)])
    return tcp_b_map


def make_http_control_from_wc(
    msmt: WebConnectivity, control: WebConnectivityControl
) -> Dict[str, HTTPControl]:
    if not control or not control.http_request:
        return {}

    if not msmt.test_keys.requests:
        return {}

    http_b_map = {}
    # We make the baseline apply to every URL in the response chain, XXX evaluate how much this is a good idea
    for http_transaction in msmt.test_keys.requests:
        if not http_transaction.request:
            continue

        url = http_transaction.request.url
        if control.http_request.failure == None:
            http_b_map[url] = HTTPControl(
                url=url,
                response_body_title=control.http_request.title or "",
                response_body_length=control.http_request.body_length or 0,
                response_status_code=control.http_request.status_code or 0,
                response_body_meta_title="",
                response_body_sha1="",
                ok_cc_asn=[("ZZ", 0)],
            )
        else:
            http_b_map[url] = HTTPControl(
                url=url,
                response_body_title="",
                response_body_length=0,
                response_status_code=0,
                response_body_meta_title="",
                response_body_sha1="",
                failure_cc_asn=[("ZZ", 0)],
            )
    return http_b_map
