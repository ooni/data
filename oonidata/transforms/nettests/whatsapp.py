from typing import List, Tuple
from oonidata.models.nettests import Whatsapp
from oonidata.models.observations import WebObservation
from oonidata.transforms.nettests.measurement_transformer import MeasurementTransformer


class WhatsappTransformer(MeasurementTransformer):
    def make_observations(self, msmt: Whatsapp) -> Tuple[List[WebObservation]]:
        dns_observations = self.make_dns_observations(msmt.test_keys.queries)
        tcp_observations = self.make_tcp_observations(msmt.test_keys.tcp_connect)
        tls_observations = self.make_tls_observations(
            msmt.test_keys.tls_handshakes, 
            msmt.test_keys.network_events,
        )
        http_observations = self.make_http_observations(msmt.test_keys.requests)

        return (
            self.consume_web_observations(
                dns_observations=dns_observations,
                tcp_observations=tcp_observations,
                tls_observations=tls_observations,
                http_observations=http_observations,
            )
        )
