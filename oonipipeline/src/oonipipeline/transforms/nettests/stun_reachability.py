from typing import List, Tuple

from oonidata.models.nettests import StunReachability
from oonidata.models.observations import WebObservation

from ..measurement_transformer import MeasurementTransformer


class StunReachabilityTransformer(MeasurementTransformer):
    def make_observations(self, msmt: StunReachability) -> Tuple[List[WebObservation]]:
        dns_observations = self.make_dns_observations(msmt.test_keys.queries)

        return (self.consume_web_observations(dns_observations=dns_observations),)
