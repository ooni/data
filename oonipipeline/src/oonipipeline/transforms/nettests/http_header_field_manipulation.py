import dataclasses
from datetime import datetime, timezone
import orjson
from typing import List, Tuple
from oonidata.models.nettests import HTTPHeaderFieldManipulation
from oonidata.models.observations import HTTPMiddleboxObservation

from ..measurement_transformer import MeasurementTransformer


class HTTPHeaderFieldManipulationTransformer(MeasurementTransformer):
    def make_observations(
        self, msmt: HTTPHeaderFieldManipulation
    ) -> Tuple[List[HTTPMiddleboxObservation]]:
        mb_obs = HTTPMiddleboxObservation(
            hfm_success=True,
            observation_id=f"{msmt.measurement_uid}_0",
            created_at=datetime.now(timezone.utc).replace(microsecond=0, tzinfo=None),
            **dataclasses.asdict(self.measurement_meta),
        )

        if msmt.test_keys.requests is None or len(msmt.test_keys.requests) == 0:
            mb_obs.hfm_failure = "missing_requests"
            mb_obs.hfm_success = False
            return ([mb_obs],)

        http_transaction = msmt.test_keys.requests[0]
        if not http_transaction.response:
            mb_obs.hfm_failure = msmt.test_keys.requests[0].failure
            if not mb_obs.hfm_failure:
                mb_obs.hfm_failure = "missing_response"
            mb_obs.hfm_success = False
            return ([mb_obs],)

        if http_transaction.response.body_str is None:
            mb_obs.hfm_failure = "missing_response_body"
            mb_obs.hfm_success = False
            return ([mb_obs],)

        if http_transaction.request is None or http_transaction.request.headers is None:
            mb_obs.hfm_failure = "malformed_request"
            mb_obs.hfm_success = False
            return ([mb_obs],)

        try:
            http_transaction.request.headers
            resp = orjson.loads(http_transaction.response.body_str)
        except:
            pass

        return ([mb_obs],)
