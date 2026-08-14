from base64 import b64decode
from datetime import datetime, timedelta
from pathlib import Path
from pprint import pprint
import random
from typing import Any, Dict, List, Tuple
from unittest.mock import MagicMock

from oonipipeline.analysis.web_analysis import (
    get_analysis_web_fuzzy_logic,
)
from oonipipeline.tasks.observations import write_observations_to_db
import pytest

from oonidata.dataclient import load_measurement
from oonidata.models.nettests.signal import Signal
from oonidata.models.nettests.web_connectivity import WebConnectivity
from oonidata.models.observations import (
    WebControlObservation,
    WebObservation,
)
from oonidata.datautils import validate_cert_chain

from oonipipeline.transforms.nettests.signal import SIGNAL_PEM_STORE
from oonipipeline.transforms.observations import measurement_to_observations


# @pytest.mark.skip(reason="TODO(art): fixme")
# def test_signal(fingerprintdb, netinfodb, measurements):
#     signal_old_ca = load_measurement(
#         msmt_path=measurements["20221016235944.266268_GB_signal_1265ff650ee17b44"]
#     )
#     assert isinstance(signal_old_ca, Signal)
#     assert signal_old_ca.test_keys.tls_handshakes

#     for tls_handshake in signal_old_ca.test_keys.tls_handshakes:
#         assert tls_handshake.peer_certificates
#         assert tls_handshake.server_name
#         certificate_chain = list(
#             map(lambda c: b64decode(c.data), tls_handshake.peer_certificates)
#         )
#         validate_cert_chain(
#             datetime(2021, 10, 16),
#             certificate_chain=certificate_chain,
#             pem_cert_store=SIGNAL_PEM_STORE,
#         )

#     signal_new_ca = load_measurement(
#         msmt_path=measurements["20221020235950.432819_NL_signal_27b05458f186a906"]
#     )
#     assert isinstance(signal_new_ca, Signal)
#     assert signal_new_ca.test_keys.tls_handshakes

#     for tls_handshake in signal_new_ca.test_keys.tls_handshakes:
#         assert tls_handshake.peer_certificates
#         assert tls_handshake.server_name
#         certificate_chain = list(
#             map(lambda c: b64decode(c.data), tls_handshake.peer_certificates)
#         )
#         validate_cert_chain(
#             datetime(2022, 10, 20),
#             certificate_chain=certificate_chain,
#             pem_cert_store=SIGNAL_PEM_STORE,
#         )

#     web_observations = measurement_to_observations(signal_new_ca, netinfodb=netinfodb)[
#         0
#     ]
#     er = list(
#         make_signal_experiment_result(
#             web_observations=web_observations,
#             fingerprintdb=fingerprintdb,
#         )
#     )
#     assert er[0].anomaly == False
#     assert er[0].confirmed == False

#     signal_blocked_uz = load_measurement(
#         msmt_path=measurements["20210926222047.205897_UZ_signal_95fab4a2e669573f"]
#     )
#     assert isinstance(signal_blocked_uz, Signal)
#     web_observations = measurement_to_observations(
#         signal_blocked_uz, netinfodb=netinfodb
#     )[0]
#     blocking_event = list(
#         make_signal_experiment_result(
#             web_observations=web_observations,
#             fingerprintdb=fingerprintdb,
#         )
#     )
#     assert blocking_event[0].anomaly == True
#     assert blocking_event[0].confirmed == False
#     tls_be = list(
#         filter(
#             lambda be: be.outcome_category == "tls",
#             blocking_event,
#         )
#     )
#     assert len(tls_be) > 0

#     signal_blocked_ir = load_measurement(
#         msmt_path=measurements["20221018174612.488229_IR_signal_f8640b28061bec06"]
#     )
#     assert isinstance(signal_blocked_ir, Signal)
#     web_observations = measurement_to_observations(
#         signal_blocked_ir, netinfodb=netinfodb
#     )[0]
#     blocking_event = list(
#         make_signal_experiment_result(
#             web_observations=web_observations,
#             fingerprintdb=fingerprintdb,
#         )
#     )
#     assert blocking_event[0].anomaly == True
#     dns_outcomes = list(
#         filter(
#             lambda be: be.outcome_category == "dns",
#             blocking_event,
#         )
#     )
#     assert len(dns_outcomes) > 0
#     assert blocking_event[0].confirmed == True


def perform_analysis(
    db,
    netinfodb,
    measurements,
    measurement_uid: str,
):
    msmt = load_measurement(msmt_path=measurements[measurement_uid])
    ts = datetime.strptime(msmt.measurement_start_time, "%Y-%m-%d %H:%M:%S")
    write_observations_to_db(
        db=db,
        netinfodb=netinfodb,
        msmt=msmt,
        bucket_date="1984-01-01",
    )
    db.flush()
    analysis_list = list(
        get_analysis_web_fuzzy_logic(
            db=db,
            start_time=ts - timedelta(days=1),
            end_time=ts + timedelta(days=1),
            probe_cc=[],
            measurement_uid=measurement_uid,
        )
    )
    assert len(analysis_list) == 1
    return analysis_list[0]


def test_website_web_analysis_blocked(db, netinfodb, measurements):
    measurement_uid = "20221110235922.335062_IR_webconnectivity_e4114ee32b8dbf74"
    analysis = perform_analysis(
        db=db,
        netinfodb=netinfodb,
        measurements=measurements,
        measurement_uid=measurement_uid,
    )
    assert analysis["dns_blocked_max"] > 0.9


def test_website_web_analysis_plaintext_ok(db, netinfodb, measurements):
    measurement_uid = "20220608132401.787399_AM_webconnectivity_2285fc373f62729e"
    analysis = perform_analysis(
        db=db,
        netinfodb=netinfodb,
        measurements=measurements,
        measurement_uid=measurement_uid,
    )
    assert analysis["dns_blocked_max"] < 0.2
    assert analysis["tcp_blocked_max"] < 0.2
    assert analysis["tls_blocked_max"] < 0.2
    # assert analysis["http_blocked_max"] < 0.5
    assert analysis["dns_ok_max"] > 0.8
    assert analysis["tcp_ok_max"] > 0.8


def test_website_web_analysis_blocked_2(db, netinfodb, measurements):
    measurement_uid = "20220627030703.592775_IR_webconnectivity_80e199b3c572f8d3"
    analysis = perform_analysis(
        db=db,
        netinfodb=netinfodb,
        measurements=measurements,
        measurement_uid=measurement_uid,
    )
    assert analysis["dns_blocked_max"] > 0.8
    assert analysis["dns_ok_max"] < 0.2


def test_website_dns_blocking_event(db, netinfodb, measurements):
    measurement_uid = "20220627134426.194308_DE_webconnectivity_15675b61ec62e268"
    analysis = perform_analysis(
        db=db,
        netinfodb=netinfodb,
        measurements=measurements,
        measurement_uid=measurement_uid,
    )
    assert analysis["dns_blocked_max"] > 0.8
    assert analysis["dns_ok_max"] < 0.2


def test_website_dns_blocking_event_2(db, netinfodb, measurements):
    measurement_uid = "20220627125833.737451_FR_webconnectivity_bca9ad9d3371919a"
    analysis = perform_analysis(
        db=db,
        netinfodb=netinfodb,
        measurements=measurements,
        measurement_uid=measurement_uid,
    )
    assert analysis["dns_blocked_max"] > 0.6
    assert analysis["dns_ok_max"] < 0.4


def test_website_dns_ok(db, netinfodb, measurements):
    measurement_uid = "20220625234824.235023_HU_webconnectivity_3435a5df0e743d39"
    analysis = perform_analysis(
        db=db,
        netinfodb=netinfodb,
        measurements=measurements,
        measurement_uid=measurement_uid,
    )
    assert analysis["dns_ok_max"] == 1.0
    assert analysis["tcp_ok_max"] == 1.0
    assert analysis["tls_ok_max"] == 1.0


# # Check this for wc 0.5 overwriting tls analsysis
# # 20231031000227.813597_MY_webconnectivity_2f0b80761373aa7e
def test_website_experiment_results(measurements, netinfodb, db):
    measurement_uid = "20221101055235.141387_RU_webconnectivity_046ce024dd76b564"
    analysis = perform_analysis(
        db=db,
        netinfodb=netinfodb,
        measurements=measurements,
        measurement_uid=measurement_uid,
    )
    assert analysis["dns_blocked_max"] < 0.5
    assert analysis["tcp_blocked_max"] > 0.6
    assert analysis["top_tcp_failure"] == "generic_timeout_error"
    assert analysis["tls_blocked_max"] == 0.0


def test_website_web_analysis_down(measurements, netinfodb, db):
    measurement_uid = "20240420235427.477327_US_webconnectivity_9b3cac038dc2ba22"
    analysis = perform_analysis(
        db=db,
        netinfodb=netinfodb,
        measurements=measurements,
        measurement_uid=measurement_uid,
    )
    assert analysis["dns_blocked_max"] < 0.5
    assert analysis["tcp_down_max"] > 0.6
    assert analysis["top_tcp_failure"] == "generic_timeout_error"
    assert analysis["tls_blocked_max"] == 0.0


def test_website_web_analysis_blocked_connect_reset(measurements, netinfodb, db):
    measurement_uid = "20240302000048.790188_RU_webconnectivity_e7ffd3bc0f525eb7"
    analysis = perform_analysis(
        db=db,
        netinfodb=netinfodb,
        measurements=measurements,
        measurement_uid=measurement_uid,
    )
    assert analysis["dns_blocked_max"] < 0.5
    assert analysis["tcp_blocked_max"] < 0.5
    assert analysis["tls_blocked_max"] > 0.7
    assert analysis["top_tls_failure"] == "connection_reset"


def test_website_web_analysis_nxdomain_down(measurements, netinfodb, db):
    measurement_uid = "20240302000050.000654_SN_webconnectivity_fe4221088fbdcb0a"
    analysis = perform_analysis(
        db=db,
        netinfodb=netinfodb,
        measurements=measurements,
        measurement_uid=measurement_uid,
    )
    assert analysis["dns_down_max"] > 0.6
    assert analysis["top_dns_failure"] == "dns_nxdomain_error"


def test_website_web_analysis_nxdomain_blocked(measurements, netinfodb, db):
    measurement_uid = "20240302000305.316064_EG_webconnectivity_397bca9091b07444"
    analysis = perform_analysis(
        db=db,
        netinfodb=netinfodb,
        measurements=measurements,
        measurement_uid=measurement_uid,
    )
    assert analysis["dns_blocked_max"] > 0.6
    assert analysis["top_dns_failure"] == "dns_nxdomain_error"


def test_website_web_analysis_blocked_inconsistent_country(measurements, netinfodb, db):
    measurement_uid = "20240309112858.009725_SE_webconnectivity_dce757ef4ec9b6c8"
    analysis = perform_analysis(
        db=db,
        netinfodb=netinfodb,
        measurements=measurements,
        measurement_uid=measurement_uid,
    )
    assert analysis["dns_ok_max"] < 0.3
    assert analysis["dns_blocked_max"] > 0.5
    assert analysis["top_dns_failure"] == None


# --------------------------------------------------------------------------
# web_connectivity 0.5 QA fixtures
#
# tests/data/wc05_qa/<case>.json is a copy of the measurement.json from
# probe-cli's own QA corpus, at
# probe-cli/internal/minipipeline/testdata/webconnectivity/generated/<case>/,
# one per censorship/edge-case scenario, named after the scenario itself
# (e.g. "tlsBlockingConnectionResetWithConsistentDNS"). probe-cli uses these
# to test its own minipipeline package; here we replay the same raw
# measurements through oonipipeline's web_analysis fuzzy-logic rules and
# check that the *_blocked_max/_down_max/_ok_max/top_*_failure signals it
# derives line up with what each scenario is supposed to look like.
#
# top_probe_analysis is a passthrough of the measurement's own
# test_keys.blocking field (see WebConnectivityTransformer.make_observations),
# so asserting on it also verifies that field survives the observations
# pipeline unchanged.
# --------------------------------------------------------------------------

WC05_QA_TESTDATA_DIR = Path(__file__).parent / "data" / "wc05_qa"

# Maps each QA scenario directory name to the subset of the analysis row
# that's distinctive for that scenario. A 2-tuple is an inclusive (lo, hi)
# range for a fuzzy-logic score; any other value (including None) must match
# exactly.
WC05_QA_CASES: Dict[str, Dict[str, Any]] = {
    "badSSLWithExpiredCertificate": {
        "tls_ok_max": (0.0, 0.1),
        "tls_down_max": (0.5, 1.0),
        "top_tls_failure": "ssl_invalid_certificate",
    },
    "badSSLWithUnknownAuthorityWithConsistentDNS": {
        "tls_ok_max": (0.0, 0.1),
        "tls_down_max": (0.5, 1.0),
        "top_tls_failure": "ssl_unknown_authority",
    },
    "badSSLWithUnknownAuthorityWithInconsistentDNS": {
        # A second, legitimately-resolved IP completes the TLS handshake, so
        # despite the bad-cert IP the layer isn't reported as blocked/down.
        "tls_ok_max": (0.9, 1.0),
        "top_tls_failure": "ssl_unknown_authority",
        "top_probe_analysis": "dns",
    },
    "badSSLWithWrongServerName": {
        "tls_ok_max": (0.0, 0.1),
        "tls_down_max": (0.5, 1.0),
        "top_tls_failure": "ssl_invalid_hostname",
    },
    "cloudflareCAPTCHAWithHTTP": {
        "tls_ok_max": (0.9, 1.0),
        "top_probe_analysis": "http-diff",
    },
    "cloudflareCAPTCHAWithHTTPS": {
        # Same CAPTCHA interstitial, but over HTTPS the encrypted body can't
        # be diffed against the control, so it isn't flagged.
        "tls_ok_max": (0.9, 1.0),
        "top_probe_analysis": "false",
    },
    "controlFailureWithSuccessfulHTTPSWebsite": {
        "tls_ok_max": (0.9, 1.0),
        "top_probe_analysis": "false",
    },
    "controlFailureWithSuccessfulHTTPWebsite": {
        "tcp_ok_max": (0.9, 1.0),
        "top_probe_analysis": None,
    },
    "dnsBlockingAndroidDNSCacheNoData": {
        "tls_ok_max": (0.9, 1.0),
        "top_probe_analysis": "dns",
    },
    "dnsBlockingBOGON": {
        "tcp_ok_max": (0.9, 1.0),
        "top_probe_analysis": "dns",
    },
    "dnsBlockingNXDOMAIN": {
        "dns_ok_max": (0.9, 1.0),
        "top_probe_analysis": "dns",
    },
    "dnsHijackingToLocalhostWithHTTP": {
        "tcp_ok_max": (0.9, 1.0),
        "top_probe_analysis": "dns",
    },
    "dnsHijackingToLocalhostWithHTTPS": {
        "tls_ok_max": (0.9, 1.0),
        "top_probe_analysis": "dns",
    },
    "dnsHijackingToProxyWithHTTPSURL": {
        # The hijack redirects to a working proxy that serves valid content,
        # so nothing downstream looks blocked.
        "tls_ok_max": (0.9, 1.0),
        "top_probe_analysis": "false",
    },
    "dnsHijackingToProxyWithHTTPURL": {
        "tcp_ok_max": (0.9, 1.0),
        "top_probe_analysis": "false",
    },
    "ghostDNSBlockingWithHTTP": {
        "dns_down_max": (0.5, 1.0),
        "top_dns_failure": "dns_nxdomain_error",
        "top_probe_analysis": "dns",
    },
    "ghostDNSBlockingWithHTTPS": {
        "dns_down_max": (0.5, 1.0),
        "top_dns_failure": "dns_nxdomain_error",
        "top_probe_analysis": "dns",
    },
    "httpBlockingConnectionReset": {
        "tcp_ok_max": (0.9, 1.0),
        "tls_ok_max": (0.9, 1.0),
        "top_probe_analysis": "http-failure",
    },
    "httpDiffWithConsistentDNS": {
        "top_probe_analysis": "http-diff",
    },
    "httpDiffWithInconsistentDNS": {
        # DNS inconsistency outranks the http-diff signal.
        "top_probe_analysis": "dns",
    },
    "idnaWithoutCensorshipLowercase": {
        "tls_ok_max": (0.9, 1.0),
        "top_probe_analysis": "false",
    },
    "idnaWithoutCensorshipWithFirstLetterUppercase": {
        "tls_ok_max": (0.9, 1.0),
        "top_probe_analysis": "false",
    },
    "largeFileWithHTTP": {
        "tcp_ok_max": (0.9, 1.0),
        "top_probe_analysis": "false",
    },
    "largeFileWithHTTPS": {
        "tls_ok_max": (0.9, 1.0),
        "top_probe_analysis": "false",
    },
    "localhostWithHTTP": {
        "tcp_blocked_max": (0.0, 0.05),
        "tls_blocked_max": (0.0, 0.05),
        "top_probe_analysis": "false",
    },
    "localhostWithHTTPS": {
        "tcp_blocked_max": (0.0, 0.05),
        "tls_blocked_max": (0.0, 0.05),
        "top_probe_analysis": "false",
    },
    "redirectWithBrokenLocationForHTTP": {
        "top_probe_analysis": "http-failure",
    },
    "redirectWithBrokenLocationForHTTPS": {
        "top_probe_analysis": "http-failure",
    },
    # In these redirect-chain cases the failure happens on the hop's own IP,
    # which isn't corroborated by control/TLS-consistency data, so the fuzzy
    # rules score that layer as inconclusive/ok rather than blocked; only the
    # raw failure string (top_*_failure, an unweighted mode) surfaces it.
    "redirectWithConsistentDNSAndThenConnectionRefusedForHTTP": {
        "tcp_ok_max": (0.9, 1.0),
        "top_tcp_failure": "connection_refused",
        "top_probe_analysis": "http-failure",
    },
    "redirectWithConsistentDNSAndThenConnectionRefusedForHTTPS": {
        "tcp_ok_max": (0.9, 1.0),
        "top_tcp_failure": "connection_refused",
        "top_probe_analysis": "http-failure",
    },
    "redirectWithConsistentDNSAndThenConnectionResetForHTTP": {
        "tls_ok_max": (0.9, 1.0),
        "top_tls_failure": "connection_reset",
        "top_probe_analysis": "http-failure",
    },
    "redirectWithConsistentDNSAndThenConnectionResetForHTTPS": {
        "tls_ok_max": (0.9, 1.0),
        "top_tls_failure": "connection_reset",
        "top_probe_analysis": "http-failure",
    },
    "redirectWithConsistentDNSAndThenEOFForHTTP": {
        "tls_ok_max": (0.9, 1.0),
        "top_tls_failure": "eof_error",
        "top_probe_analysis": "http-failure",
    },
    "redirectWithConsistentDNSAndThenEOFForHTTPS": {
        "tls_ok_max": (0.9, 1.0),
        "top_tls_failure": "eof_error",
        "top_probe_analysis": "http-failure",
    },
    "redirectWithConsistentDNSAndThenNXDOMAIN": {
        "top_dns_failure": "dns_nxdomain_error",
        "top_probe_analysis": "dns",
    },
    "redirectWithConsistentDNSAndThenTimeoutForHTTP": {
        "tls_ok_max": (0.9, 1.0),
        "top_tls_failure": "generic_timeout_error",
        "top_probe_analysis": "http-failure",
    },
    "redirectWithConsistentDNSAndThenTimeoutForHTTPS": {
        "tls_ok_max": (0.9, 1.0),
        "top_tls_failure": "generic_timeout_error",
        "top_probe_analysis": "http-failure",
    },
    "redirectWithMoreThanTenRedirectsAndHTTP": {
        "top_probe_analysis": "false",
    },
    "redirectWithMoreThanTenRedirectsAndHTTPS": {
        "top_probe_analysis": "false",
    },
    "successWithHTTP": {
        "tcp_ok_max": (0.9, 1.0),
        "top_probe_analysis": "false",
    },
    "successWithHTTPS": {
        "tls_ok_max": (0.9, 1.0),
        "top_probe_analysis": "false",
    },
    "tcpBlockingConnectTimeout": {
        "tcp_blocked_max": (0.5, 1.0),
        "tcp_ok_max": (0.0, 0.05),
        "top_tcp_failure": "generic_timeout_error",
        "top_probe_analysis": "tcp_ip",
    },
    "tcpBlockingConnectionRefusedWithInconsistentDNS": {
        "top_tcp_failure": "connection_refused",
        "top_probe_analysis": "dns",
    },
    "throttlingWithHTTP": {
        "top_probe_analysis": "http-failure",
    },
    "throttlingWithHTTPS": {
        "top_probe_analysis": "http-failure",
    },
    "tlsBlockingConnectionResetWithConsistentDNS": {
        "tls_blocked_max": (0.5, 1.0),
        "tls_ok_max": (0.0, 0.05),
        "top_tls_failure": "connection_reset",
        "top_probe_analysis": "http-failure",
    },
    "tlsBlockingConnectionResetWithInconsistentDNS": {
        "tls_blocked_max": (0.5, 1.0),
        "tls_ok_max": (0.0, 0.05),
        "top_tls_failure": "connection_reset",
        "top_probe_analysis": "dns",
    },
    "websiteDownNXDOMAIN": {
        # The control gets NXDOMAIN too, so it's classified as the site
        # being down rather than as censorship.
        "dns_down_max": (0.5, 1.0),
        "top_dns_failure": "dns_nxdomain_error",
        "top_probe_analysis": "false",
    },
    "websiteDownNoAddrs": {
        "top_probe_analysis": "false",
    },
    "websiteDownTCPConnect": {
        # The control fails to connect too, so this reads as the site being
        # down rather than as censorship.
        "tcp_down_max": (0.5, 1.0),
        "top_tcp_failure": "connection_refused",
        "top_probe_analysis": "false",
    },
}


def perform_wc05_qa_analysis(db, netinfodb, case_name: str):
    msmt_path = WC05_QA_TESTDATA_DIR / f"{case_name}.json"
    msmt = load_measurement(msmt_path=msmt_path)
    # These QA fixtures don't carry a measurement_uid (it's assigned by the
    # collector on ingestion), but the observations/analysis pipeline
    # requires one, so use the scenario name, which is unique within the
    # corpus.
    msmt.measurement_uid = case_name
    ts = datetime.strptime(msmt.measurement_start_time, "%Y-%m-%d %H:%M:%S")
    write_observations_to_db(
        db=db,
        netinfodb=netinfodb,
        msmt=msmt,
        bucket_date="1984-01-01",
    )
    db.flush()
    analysis_list = list(
        get_analysis_web_fuzzy_logic(
            db=db,
            start_time=ts - timedelta(days=1),
            end_time=ts + timedelta(days=1),
            probe_cc=[],
            measurement_uid=case_name,
        )
    )
    assert len(analysis_list) == 1
    return analysis_list[0]


@pytest.mark.parametrize("case_name", sorted(WC05_QA_CASES.keys()))
def test_website_web_analysis_wc05_qa_corpus(db, netinfodb, case_name):
    analysis = perform_wc05_qa_analysis(db, netinfodb, case_name)
    for field, expected in WC05_QA_CASES[case_name].items():
        got = analysis[field]
        if isinstance(expected, tuple):
            lo, hi = expected
            assert lo <= got <= hi, (
                f"{case_name}: expected {field} in [{lo}, {hi}], got {got}"
            )
        else:
            assert got == expected, (
                f"{case_name}: expected {field} == {expected!r}, got {got!r}"
            )
