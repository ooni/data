from datetime import datetime, timezone
from typing import List, Tuple
from oonidata.models.nettests import BrowserWeb
from oonidata.models.observations import WebObservation

from ..measurement_transformer import MeasurementTransformer


class BrowserWebTransformer(MeasurementTransformer):
    def make_observations(self, msmt: BrowserWeb) -> Tuple[List[WebObservation]]:
        bw_obs = WebObservation(
            measurement_meta=self.measurement_meta,
            probe_meta=self.probe_meta,
            http_failure=msmt.test_keys.result,
            http_runtime=msmt.test_keys.load_time_ms,
        )
        return ([bw_obs],)
