from typing import List, Tuple
from oonidata.models.nettests import OpenVPN
from oonidata.models.observations import OpenVPNObservation

from ..measurement_transformer import MeasurementTransformer


class OpenVPNTransformer(MeasurementTransformer):
    def make_observations(self, msmt: OpenVPN) -> Tuple[List[OpenVPNObservation]]:
        openvpn_obs_list = []
        if not msmt.test_keys:
            return (openvpn_obs_list,)

        tcp_observations = self.make_tcp_observations(msmt.tcp_connect)

        return self.make_openvpn_observations(
            tcp_observations=tcp_observations,
            openvpn_handshakes=msmt.openvpn_handshake,
            network_events=msmt.network_events,
            bootstrap_time=msmt.bootstrap_time,
        )
