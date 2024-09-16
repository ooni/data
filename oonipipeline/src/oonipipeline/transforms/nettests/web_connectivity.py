from copy import deepcopy
from datetime import datetime, timezone
from typing import Dict, List, Tuple
from urllib.parse import urlparse
from oonidata.datautils import is_ip_bogon
from oonidata.models.nettests import WebConnectivity
from oonidata.models.observations import (
    MeasurementMeta,
    ProbeMeta,
    WebControlObservation,
    WebObservation,
)

from ..measurement_transformer import MeasurementTransformer

from ...netinfo import NetinfoDB


def make_web_control_observations(
    msmt: WebConnectivity,
    measurement_meta: MeasurementMeta,
    netinfodb: NetinfoDB,
) -> List[WebControlObservation]:
    web_ctrl_obs: List[WebControlObservation] = []

    if msmt.test_keys.control_failure or msmt.test_keys.control is None:
        # TODO: do we care to note these failures somewhere?
        return web_ctrl_obs

    # Very malformed input, not much to be done here
    if not isinstance(msmt.input, str):
        return web_ctrl_obs

    # The hostname is implied from the input
    hostname = urlparse(msmt.input).hostname
    if not hostname:
        return web_ctrl_obs

    created_at = datetime.now(timezone.utc).replace(tzinfo=None)
    # Reference for new-style web_connectivity:
    # https://explorer.ooni.org/measurement/20220924T215758Z_webconnectivity_IR_206065_n1_2CRoWBNJkWc7VyAs?input=https%3A%2F%2Fdoh.dns.apple.com%2Fdns-query%3Fdns%3Dq80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB

    if msmt.test_keys.control.dns and msmt.test_keys.control.dns.failure:
        obs = WebControlObservation(
            measurement_meta=measurement_meta,
            hostname=hostname,
            created_at=created_at,
        )
        obs.dns_failure = msmt.test_keys.control.dns.failure
        web_ctrl_obs.append(obs)

    dns_ips = set()
    if msmt.test_keys.control.dns and msmt.test_keys.control.dns.addrs:
        dns_ips = set(list(msmt.test_keys.control.dns.addrs))

    addr_map: Dict[str, WebControlObservation] = {}
    if msmt.test_keys.control.tcp_connect:
        for addr, res in msmt.test_keys.control.tcp_connect.items():
            p = urlparse("//" + addr)

            obs = WebControlObservation(
                measurement_meta=measurement_meta,
                hostname=hostname,
                created_at=created_at,
            )
            assert p.hostname, "missing hostname in tcp_connect control key"
            obs.ip = p.hostname
            obs.port = p.port
            obs.tcp_failure = res.failure
            obs.tcp_success = res.failure is None

            addr_map[addr] = obs

    if msmt.test_keys.control.tls_handshake:
        for addr, res in msmt.test_keys.control.tls_handshake.items():
            if addr in addr_map:
                obs = addr_map[addr]
            else:
                p = urlparse("//" + addr)
                assert p.hostname, "missing hostname in tls_handshakes control key"
                obs = WebControlObservation(
                    measurement_meta=measurement_meta,
                    hostname=p.hostname,
                    port=p.port,
                    created_at=created_at,
                )

            obs.tls_failure = res.failure
            obs.tls_server_name = res.server_name
            obs.tls_success = res.failure is None

            addr_map[addr] = obs

    mapped_dns_ips = set()
    for obs in addr_map.values():
        assert obs.ip, "missing IP in ctrl observation"
        if obs.ip:
            obs.ip_is_bogon = is_ip_bogon(obs.ip)
            ip_info = netinfodb.lookup_ip(
                obs.measurement_meta.measurement_start_time, obs.ip
            )
            if ip_info:
                obs.ip_cc = ip_info.cc
                obs.ip_asn = ip_info.as_info.asn
                obs.ip_as_org_name = ip_info.as_info.as_org_name
                obs.ip_as_cc = ip_info.as_info.as_cc

        if obs.ip in dns_ips:
            # We care to include the IPs for which we got a resolution in the
            # same row as the relevant TLS and TCP controls, but if we don't
            # have them, we want to write a row with just that.
            obs.dns_success = True
            mapped_dns_ips.add(obs.ip)

        web_ctrl_obs.append(obs)

    for ip in dns_ips - mapped_dns_ips:
        obs = WebControlObservation(
            measurement_meta=measurement_meta,
            hostname=hostname,
            created_at=created_at,
        )
        obs.ip = ip
        obs.dns_success = True
        web_ctrl_obs.append(obs)

    if msmt.test_keys.control.http_request:
        obs = WebControlObservation(
            measurement_meta=measurement_meta,
            hostname=hostname,
            created_at=created_at,
        )
        obs.http_request_url = msmt.input
        obs.http_failure = msmt.test_keys.control.http_request.failure
        obs.http_success = msmt.test_keys.control.http_request.failure is None
        obs.http_response_body_length = msmt.test_keys.control.http_request.body_length
        web_ctrl_obs.append(obs)

    for idx, obs in enumerate(web_ctrl_obs):
        obs.observation_idx = idx

    return web_ctrl_obs


class WebConnectivityTransformer(MeasurementTransformer):
    def make_observations(
        self, msmt: WebConnectivity
    ) -> Tuple[List[WebObservation], List[WebControlObservation]]:
        http_observations = self.make_http_observations(msmt.test_keys.requests)
        dns_observations = self.make_dns_observations(msmt.test_keys.queries)
        tcp_observations = self.make_tcp_observations(msmt.test_keys.tcp_connect)
        tls_observations = self.make_tls_observations(
            tls_handshakes=msmt.test_keys.tls_handshakes,
            network_events=msmt.test_keys.network_events,
        )
        probe_analysis = msmt.test_keys.blocking
        if probe_analysis is False:
            probe_analysis = "false"
        web_observations = self.consume_web_observations(
            dns_observations=dns_observations,
            tcp_observations=tcp_observations,
            tls_observations=tls_observations,
            http_observations=http_observations,
            probe_analysis=probe_analysis,
        )

        web_ctrl_observations = make_web_control_observations(
            msmt,
            measurement_meta=self.measurement_meta,
            netinfodb=self.netinfodb,
        )
        return (web_observations, web_ctrl_observations)
