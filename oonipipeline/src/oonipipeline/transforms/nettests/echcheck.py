from typing import List, Tuple

from oonidata.models.nettests import ECHCheck
from oonidata.models.observations import WebObservation

from ..measurement_transformer import MeasurementTransformer


class ECHCheckTransformer(MeasurementTransformer):
    def make_observations(self, msmt: ECHCheck) -> Tuple[List[WebObservation]]:
        dns_observations = []
        tcp_observations = []
        tls_observations = []

        if msmt.test_keys.queries:
           dns_observations = self.make_dns_observations(msmt.test_keys.queries)
        if msmt.test_keys.tcp_connect:
           tcp_observations = self.make_tcp_observations(msmt.test_keys.tcp_connect)

        if msmt.test_keys.tls_handshakes:
           tls_observations = self.make_tls_observations(
              tls_handshakes=msmt.test_keys.tls_handshakes,
              network_events=msmt.test_keys.network_events,
           )
        elif msmt.test_keys.control and msmt.test_keys.target:
            target = msmt.test_keys.target
            target.echconfig = "GREASE"
            tls_observations = self.make_tls_observations(
                  tls_handshakes=[msmt.test_keys.control, target],
                  network_events=msmt.test_keys.network_events,
            )

        return (self.consume_web_observations(
            dns_observations=dns_observations,
            tcp_observations=tcp_observations,
            tls_observations=tls_observations,
            http_observations=[]
        ), )
