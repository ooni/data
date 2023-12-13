from typing import List, Tuple
from oonidata.models.nettests import FacebookMessenger
from oonidata.models.observations import WebObservation
from oonidata.transforms.nettests.measurement_transformer import MeasurementTransformer


class FacebookMessengerTransformer(MeasurementTransformer):
    def make_observations(self, msmt: FacebookMessenger) -> Tuple[List[WebObservation]]:

        dns_observations = self.make_dns_observations(msmt.test_keys.queries)
        tcp_observations = self.make_tcp_observations(msmt.test_keys.tcp_connect)

        return (
            self.consume_web_observations(
                dns_observations=dns_observations,
                tcp_observations=tcp_observations,
            )
        )
