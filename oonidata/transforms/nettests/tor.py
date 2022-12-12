from typing import List, Tuple
from oonidata.models.nettests import Tor
from oonidata.models.observations import WebObservation
from oonidata.transforms.nettests.measurement_transformer import MeasurementTransformer


class TorTransformer(MeasurementTransformer):
    def make_observations(self, msmt: Tor) -> Tuple[List[WebObservation]]:
        web_obs_list = []
        for target_id, target_msmt in msmt.test_keys.targets.items():
            http_observations = self.make_http_observations(target_msmt.requests)
            dns_observations = self.make_dns_observations(target_msmt.queries)
            tcp_observations = self.make_tcp_observations(target_msmt.tcp_connect)
            tls_observations = self.make_tls_observations(
                target_msmt.tls_handshakes,
                target_msmt.network_events,
            )
            web_obs_list += self.consume_web_observations(
                dns_observations=dns_observations,
                tcp_observations=tcp_observations,
                tls_observations=tls_observations,
                http_observations=http_observations,
                target_id=target_id,
            )

        return (web_obs_list,)
