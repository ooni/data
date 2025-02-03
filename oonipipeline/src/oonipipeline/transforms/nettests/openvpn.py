from datetime import datetime
from typing import Dict, List, Optional, Tuple
from oonidata.models.dataformats import OpenVPNHandshake, OpenVPNNetworkEvent
from oonidata.models.nettests import OpenVPN
from oonidata.models.observations import (
    OpenVPNObservation,
    TunnelObservation,
    WebObservation,
)

from ..measurement_transformer import MeasurementTransformer, normalize_failure
from ..measurement_transformer import measurement_to_openvpn_observation


def count_key_exchange_packets(network_events: List[OpenVPNNetworkEvent]) -> int:
    """
    return number of packets exchanged in the SENT_KEY state
    """
    n = 0
    for evt in network_events:
        if evt.stage == "SENT_KEY" and evt.operation.startswith("packet_"):
            n += 1
    return n


def make_openvpn_timing_map(
    network_events: List[OpenVPNNetworkEvent],
) -> Dict[str, float]:

    timings = {}
    # TODO(ain): condition to test version >= xyz
    if len(network_events) != 0:
        for evt in network_events:
            if evt.packet is not None:
                if evt.packet.opcode == "P_CONTROL_HARD_RESET_CLIENT_V2":
                    timings["openvpn_handshake_hr_client"] = evt.t
                elif evt.packet.opcode == "P_CONTROL_HARD_RESET_SERVER_V2":
                    timings["openvpn_handshake_hr_server"] = evt.t
                elif evt.tags and "client_hello" in evt.tags:
                    timings["openvpn_handshake_clt_hello"] = evt.t
                elif evt.tags and "server_hello" in evt.tags:
                    timings["openvpn_handshake_srv_hello"] = evt.t
            if evt.operation == "state" and evt.stage == "GOT_KEY":
                timings["openvpn_handshake_got_keys"] = evt.t
            if evt.operation == "state" and evt.stage == "GENERATED_KEYS":
                timings["openvpn_handshake_gen_keys"] = evt.t

        timings["openvpn_handshake_key_exchg_n"] = count_key_exchange_packets(
            network_events
        )

    return timings


class OpenVPNTransformer(MeasurementTransformer):

    def make_observations(
        self, msmt: OpenVPN
    ) -> Tuple[List[OpenVPNObservation], List[WebObservation]]:
        if not msmt.test_keys:
            return ([], [])

        # def make_openvpn_observations(
        #     self,
        #     tcp_observations: Optional[List[TCPConnect]],
        #     openvpn_handshakes: List[OpenVPNHandshake],
        #     network_events: Optional[List[OpenVPNNetworkEvent]],
        #     bootstrap_time: float,
        # ) -> List[TunnelObservation]:
        #     """
        #     Returns a list of OpenVPNObservations by mapping all related
        #     TCPObservations, OpenVPNNetworkevents and OpenVPNHandshakes.
        #     """

        openvpn_obs_list: List[TunnelObservation] = []

        assert msmt.test_keys is not None
        assert msmt.test_keys.openvpn_handshake is not None
        idx = 1
        for hs in msmt.test_keys.openvpn_handshake:
            to = TunnelObservation(
                measurement_meta=self.measurement_meta,
                probe_meta=self.probe_meta,
                failure=normalize_failure(hs.failure),
                success=hs.failure == None,
                label="",
                protocol="openvpn",
                transport=hs.transport,
                ip=hs.ip,
                observation_idx=idx,
                port=hs.port,
                bootstrap_time=msmt.test_keys.bootstrap_time or -1,
            )

            to.timing_map = make_openvpn_timing_map(msmt.test_keys.network_events or [])
            to.timing_map["handshake_t"] = hs.t
            to.timing_map["handshake_t0"] = hs.t0
            to.failure_map["handshake"] = hs.failure or ""
            idx += 1

            openvpn_obs_list.append(to)

        web_observations = (
            self.consume_web_observations(
                dns_observations=[],
                tcp_observations=self.make_tcp_observations(msmt.test_keys.tcp_connect),
                tls_observations=[],
                http_observations=[],
            ),
        )
        return (openvpn_obs, web_observations)
