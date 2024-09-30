from typing import List, Tuple
from oonidata.models.nettests import OpenVPN
from oonidata.models.observations import OpenVPNObservation

from ..measurement_transformer import MeasurementTransformer


class OpenVPNTransformer(MeasurementTransformer):
    def make_observations(self, msmt: OpenVPN) -> Tuple[List[OpenVPNObservation]]:
        if not msmt.test_keys:
            return ([],)

        openvpn_obs = self.make_openvpn_observations(
            tcp_observations=self.make_tcp_observations(msmt.test_keys.tcp_connect),
            openvpn_handshakes=msmt.test_keys.openvpn_handshake,
            network_events=msmt.test_keys.network_events,
            bootstrap_time=msmt.test_keys.bootstrap_time,
        )

        return (openvpn_obs, )
