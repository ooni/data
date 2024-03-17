import dataclasses
from datetime import datetime, timezone
from typing import List, Tuple
from oonidata.models.dataformats import maybe_binary_data_to_bytes
from oonidata.models.nettests import HTTPInvalidRequestLine
from oonidata.models.observations import HTTPMiddleboxObservation

from ..measurement_transformer import MeasurementTransformer


def detect_target_index(sent_data):
    """
    Tries to guess the target index based on the sent data. This allows us to
    map consistently the datapoints onto the same column in the DB.

    0: test_random_invalid_method
    1: test_random_invalid_field_count
    2: test_random_big_request_method
    3: test_random_invalid_version_number
    4: test_squid_cache_manager
    """
    p = sent_data.split(" ")
    # 0: test_random_invalid_method
    # request_line = randomSTR(4) + " / HTTP/1.1\n\r"
    if len(p[0]) == 4:
        return 0

    # test_random_invalid_field_count
    # request_line = ' '.join(randomStr(5) for x in range(4)) + '\n\r'
    if len(p) == 4:
        return 1

    # test_random_big_request_method
    # request-line = randomStr(1024) + ' / HTTP/1.1\n\r'
    if len(p[0]) == 1024:
        return 2

    # test_random_invalid_version_number
    # request_line = 'GET / HTTP/' + randomStr(3)
    if p[0] == "GET" and p[1] == "/" and p[2].strip() != "HTTP/1.1":
        return 3

    # test_squid_cache_manager
    # request_line = 'GET cache_object://localhost/ HTTP/1.0\n\r'
    if "cache_object://localhost/" in sent_data:
        return 4

    raise Exception(f"Unable to guess index for {sent_data}")


class HTTPInvalidRequestLineTransformer(MeasurementTransformer):
    def make_observations(
        self, msmt: HTTPInvalidRequestLine
    ) -> Tuple[List[HTTPMiddleboxObservation]]:
        mb_obs = HTTPMiddleboxObservation(
            hirl_success=True,
            observation_id=f"{msmt.measurement_uid}_0",
            created_at=datetime.now(timezone.utc).replace(microsecond=0, tzinfo=None),
            **dataclasses.asdict(self.measurement_meta),
        )
        if not msmt.test_keys.sent:
            mb_obs.hirl_failure = "missing_sent"
            mb_obs.hirl_success = False
            return ([mb_obs],)

        if not msmt.test_keys.received:
            mb_obs.hirl_failure = "missing_received"
            mb_obs.hirl_success = False
            return ([mb_obs],)

        for i in [0, 1, 2, 3, 4]:
            try:
                if msmt.test_keys.sent[i] != msmt.test_keys.received[i]:
                    target_idx = detect_target_index(msmt.test_keys.sent[i])
                    received_data = maybe_binary_data_to_bytes(
                        msmt.test_keys.received[i]
                    )
                    sent_data = maybe_binary_data_to_bytes(msmt.test_keys.sent[i])
                    assert isinstance(
                        received_data, bytes
                    ), "received data is not bytes"
                    setattr(mb_obs, f"hirl_received_{target_idx}", received_data)
                    setattr(mb_obs, f"hirl_sent_{target_idx}", sent_data)

            except IndexError:
                mb_obs.hirl_failure = f"missing_received_{i}"
                mb_obs.hirl_success = False
                return ([mb_obs],)
        return ([mb_obs],)
