from typing import List, Tuple
import dataclasses
from oonidata.models.nettests import BrowserWeb
from oonidata.models.observations import WebObservation

from ..measurement_transformer import MeasurementTransformer


class BrowserWebTransformer(MeasurementTransformer):
    def make_observations(self, msmt: BrowserWeb) -> Tuple[List[WebObservation]]:
        bw_obs = WebObservation(**dataclasses.asdict(self.measurement_meta))

        bw_obs.http_failure = msmt.test_keys.result
        bw_obs.http_runtime = msmt.test_keys.load_time_ms

        return ([bw_obs],)
