import dataclasses
import logging
from datetime import datetime, timezone
from typing import List, Tuple
from oonidata.models.dataformats import maybe_binary_data_to_bytes
from oonidata.models.nettests import TLSMiddlebox
from oonidata.models.observations import MiddleboxObservation, MeasurementMeta
from ...netinfo import NetinfoDB

from ..measurement_transformer import MeasurementTransformer

log = logging.getLogger("oonidata.transforms.tlsmiddlebox")

class MiddleboxTransformer(MeasurementTransformer):
    def make_observations(
        self, msmt: TLSMiddlebox
    ) -> List[MiddleboxObservation]:

        middlebox_observations: List[MiddleboxObservation] = []

        created_at = datetime.now(timezone.utc).replace(tzinfo=None)

        traces = msmt.test_keys.iterative_trace or []

        dns_observations = self.make_dns_observations(msmt.test_keys.queries)
        tcp_observations = self.make_tcp_observations(msmt.test_keys.tcp_connect)
        icmp_observations = []
        tls_observations = []

        for trace_idx, trace in enumerate(traces):
            # TCP Trace
            if trace.tcp_traceroute is not None:
                for iteration_idx, hop in enumerate(trace.tcp_traceroute.iterations or []):
                    obs = MiddleboxObservation(
                        measurement_meta=self.measurement_meta,
                        probe_meta=self.probe_meta,
                        created_at=created_at,
                        trace_idx=trace_idx,
                        iteration_idx=iteration_idx,
                        ttl=hop.ttl,
                        trace_type="tcp",
                    )

                    middlebox_observations.append(obs)

                    icmp_obs = self.make_icmp_observations(
                        icmp_errors=[hop.icmp_error] if hop.icmp_error else []
                    )

                    for icmp_o in icmp_obs:
                        icmp_observations.append((trace_idx, iteration_idx, icmp_o, "tcp"))

            # Control Trace
            if trace.control_trace is not None:
                for iteration_idx, hop in enumerate(trace.control_trace.iterations or []):
                    obs = MiddleboxObservation(
                        measurement_meta=self.measurement_meta,
                        probe_meta=self.probe_meta,
                        created_at=created_at,
                        trace_idx=trace_idx,
                        iteration_idx=iteration_idx,
                        ttl=hop.ttl,
                        trace_type="control",
                    )
                    middlebox_observations.append(obs)

                    tls_obs = self.make_tls_observations(
                        tls_handshakes=[hop.handshake] if hop.handshake else [],
                        network_events=[],
                    )

                    for tls_o in tls_obs:
                        tls_observations.append((trace_idx, iteration_idx, tls_o, "control"))

            # Target Trace
            if trace.target_trace is not None:
                for iteration_idx, hop in enumerate(trace.target_trace.iterations or []):
                    obs = MiddleboxObservation(
                        measurement_meta=self.measurement_meta,
                        probe_meta=self.probe_meta,
                        created_at=created_at,
                        trace_idx=trace_idx,
                        iteration_idx=iteration_idx,
                        ttl=hop.ttl,
                        trace_type="target",
                    )
                    middlebox_observations.append(obs)

                    tls_obs = self.make_tls_observations(
                        tls_handshakes=[hop.handshake] if hop.handshake else [],
                        network_events=[],
                    )

                    for tls_o in tls_obs:
                        tls_observations.append((trace_idx, iteration_idx, tls_o, "target"))


        observations = self.consume_middlebox_observations(
                        middlebox_observations=middlebox_observations,
                        icmp_observations=icmp_observations,
                        tls_observations=tls_observations,
                    )

        return observations