import dataclasses
from typing import List, Tuple
from oonidata.models.nettests import VanillaTor
from oonidata.models.observations import CircumventionToolObservation
from oonidata.transforms.nettests.measurement_transformer import MeasurementTransformer


class VanillaTorTransformer(MeasurementTransformer):
    def make_observations(self, msmt: VanillaTor) -> Tuple[List[CircumventionToolObservation]]:
        ct_obs = CircumventionToolObservation(
            observation_id=f"{msmt.measurement_uid}_0",
            created_at=datetime.utcnow().replace(microsecond=0),
            **dataclasses.asdict(self.measurement_meta),
        )

        ct_obs.bootstrap_time = msmt.test_keys.bootstrap_time,
        ct.tor_failure = msmt.test_keys.failure
        ct.tor_error = msmt.test_keys.error
        ct.tor_success = msmt.test_keys.success
        ct.tor_timeout = msmt.test_keys.timeout
    
        ct.tor_logs = msmt.test_keys.tor_logs
        ct.tor_progress = msmt.test_keys.tor_progress
        ct.tor_progress_tag = msmt.test_keys.tor_progress_tag
        ct.tor_progress_summary = msmt.test_keys.tor_progress_summary
        ct.tor_version = msmt.test_keys.tor_version
        ct.tor_transport_name = msmt.test_keys.transport_name

        return ([ct_obs],)
