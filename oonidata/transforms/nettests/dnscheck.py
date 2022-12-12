from typing import List, Tuple

from oonidata.models.nettests import DNSCheck
from oonidata.models.observations import WebObservation
from oonidata.transforms.nettests.measurement_transformer import MeasurementTransformer


class DNSCheckTransformer(MeasurementTransformer):
    def make_observations(self, msmt: DNSCheck) -> Tuple[List[WebObservation]]:
        web_obs_list = []

        if msmt.test_keys.bootstrap:
            web_obs_list += self.consume_web_observations(
                dns_observations=self.make_dns_observations(
                    msmt.test_keys.bootstrap.queries
                ),
            )

        lookup_map = msmt.test_keys.lookups or {}
        for lookup in lookup_map.values():
            web_obs_list += self.consume_web_observations(
                dns_observations=self.make_dns_observations(lookup.queries),
                http_observations=self.make_http_observations(lookup.requests),
                tcp_observations=self.make_tcp_observations(lookup.tcp_connect),
                tls_observations=self.make_tls_observations(
                    tls_handshakes=lookup.tls_handshakes,
                    network_events=lookup.network_events,
                ),
            )

        return (web_obs_list,)
