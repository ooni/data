from typing import List, Tuple

from oonidata.models.nettests import BrowserWeb
from oonidata.models.observations import WebObservation
from oonidata.transforms.nettests.measurement_transformer import MeasurementTransformer, make_web_observation


class BrowserWebTransformer(MeasurementTransformer):
    def make_observations(self, msmt: BrowserWeb) -> Tuple[List[WebObservation]]:
        bw_obs = make_web_observation(self.measurement_meta, self.netinfodb)
        
        bw_obs.http_failure = msmt.test_keys.result
        bw_obs.http_runtime = msmt.test_keys.load_time_ms

        return (
            ([bw_obs],)
        )
