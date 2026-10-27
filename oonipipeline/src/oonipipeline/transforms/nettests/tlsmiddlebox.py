import dataclasses
from datetime import datetime, timezone
from typing import List, Tuple
from oonidata.models.dataformats import maybe_binary_data_to_bytes
from oonidata.models.nettests import TLSMiddlebox
from oonidata.models.observations import TLSMiddleboxObservation

from ...netinfo import NetinfoDB

from ..measurement_transformer import MeasurementTransformer

log = logging.getLogger("oonidata.transforms.tlsmiddlebox")

class TLSMiddleboxTransformer(MeasurementTransformer):
    def make_observations(
        self, msmt: TLSMiddlebox
    ) -> Tuple[List[TLSMiddleboxObservation]]:
        dns_observations = self.make_dns_observations(msmt.test_keys.queries)
        tcp_observations = self.make_tcp_observations(msmt.test_keys.tcp_connect)
        tls_observations = self.make_tls_observations(
            tls_handshakes=msmt.test_keys.tls_handshakes,
            network_events=msmt.test_keys.network_events,
        )
        probe_analysis = msmt.test_keys.blocking
        if probe_analysis is False:
            probe_analysis = "false"

        # The probe also tests addresses resolved by the control, which have no
        # corresponding DNS query in the measurement. We use the control DNS
        # resolution to attribute those TCP/TLS observations to the hostname of
        # the input URL.
        ip_hostname_hints: Dict[str, str] = {}
        input_hostname = (
            urlparse(msmt.input).hostname if isinstance(msmt.input, str) else None
        )
        if (
            input_hostname
            and msmt.test_keys.control
            and msmt.test_keys.control.dns
            and msmt.test_keys.control.dns.addrs
        ):
            for addr in msmt.test_keys.control.dns.addrs:
                ip_hostname_hints[addr] = input_hostname

        web_observations = self.consume_web_observations(
            dns_observations=dns_observations,
            tcp_observations=tcp_observations,
            tls_observations=tls_observations,
            http_observations=http_observations,
            probe_analysis=probe_analysis,
            ip_hostname_hints=ip_hostname_hints,
        )

        web_ctrl_observations = make_web_control_observations(
            msmt,
            measurement_meta=self.measurement_meta,
            netinfodb=self.netinfodb,
        )
        return (web_observations, web_ctrl_observations)