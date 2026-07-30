from typing import List

import pytest

from oonidata.dataclient import load_measurement
from oonidata.models.nettests.dnscheck import DNSCheck
from oonidata.models.nettests.echcheck import ECHCheck
from oonidata.models.nettests.telegram import Telegram
from oonidata.models.nettests.signal import Signal
from oonidata.models.nettests.facebook_messenger import FacebookMessenger
from oonidata.models.nettests.whatsapp import Whatsapp
from oonidata.models.nettests.web_connectivity import WebConnectivity
from oonidata.models.nettests.stun_reachability import StunReachability
from oonidata.models.nettests.urlgetter import UrlGetter
from oonidata.models.nettests.browser_web import BrowserWeb
from oonidata.models.observations import WebObservation

from oonipipeline.transforms.measurement_transformer import (
    MeasurementTransformer,
    find_tls_handshake_events_without_transaction_id,
)
from oonipipeline.transforms.observations import (
    TypeWebObservations,
    measurement_to_observations,
)


def test_wc_v5_observations(netinfodb, measurements):
    msmt = load_measurement(
        msmt_path=measurements[
            "20220924222854.036406_IR_webconnectivity_7aedefe4aaac824c"
        ]
    )
    assert isinstance(msmt, WebConnectivity)
    bucket_date = "2022-09-24"
    obs_tup = measurement_to_observations(
        msmt=msmt, netinfodb=netinfodb, bucket_date=bucket_date
    )
    assert len(obs_tup) == 2
    web_obs, web_ctrl_obs = obs_tup
    assert isinstance(web_obs[0], WebObservation)
    assert len(web_obs) == 15
    assert len(web_ctrl_obs) == 13


def test_wc_v5_cn_bug_observations(netinfodb, measurements):
    msmt = load_measurement(
        msmt_path=measurements[
            "20241101171509.547086_CN_webconnectivity_f0ec3f0e369cec9b"
        ]
    )
    assert isinstance(msmt, WebConnectivity)
    bucket_date = "2024-11-17"
    obs_tup = measurement_to_observations(
        msmt=msmt, netinfodb=netinfodb, bucket_date=bucket_date
    )
    assert len(obs_tup) == 2
    web_obs, web_ctrl_obs = obs_tup
    assert isinstance(web_obs[0], WebObservation)
    assert len(web_obs) == 4
    assert len(web_ctrl_obs) == 2


def test_http_observations(measurements, netinfodb):
    msmt = load_measurement(
        msmt_path=measurements[
            "20220608132401.787399_AM_webconnectivity_2285fc373f62729e"
        ]
    )
    mt = MeasurementTransformer(
        measurement=msmt, netinfodb=netinfodb, bucket_date="2022-06-08"
    )
    assert isinstance(msmt, WebConnectivity)
    all_http_obs = [
        obs
        for obs in mt.make_http_observations(
            msmt.test_keys.requests,
        )
    ]
    assert len(all_http_obs) == 2
    assert all_http_obs[0].request_url == "https://hahr.am/"

    msmt = load_measurement(
        msmt_path=measurements[
            "20220608155654.044764_AM_webconnectivity_ccb727b4812234a5"
        ]
    )
    mt = MeasurementTransformer(
        measurement=msmt, netinfodb=netinfodb, bucket_date="2022-06-08"
    )
    assert isinstance(msmt, WebConnectivity)
    all_dns_obs = [
        obs
        for obs in mt.make_dns_observations(
            msmt.test_keys.queries,
        )
    ]

    assert len(all_dns_obs) == 4
    assert all_dns_obs[0].answer == "172.67.187.120"

    all_tcp_obs = [
        obs
        for obs in mt.make_tcp_observations(
            msmt.test_keys.tcp_connect,
        )
    ]
    assert len(all_tcp_obs) == 4

    all_tls_obs = [
        obs
        for obs in mt.make_tls_observations(
            tls_handshakes=msmt.test_keys.tls_handshakes,
            network_events=msmt.test_keys.network_events,
        )
    ]
    assert len(all_tls_obs) == 2
    assert all_tls_obs[0].handshake_time
    assert all_tls_obs[0].handshake_time > 0
    assert all_tls_obs[0].handshake_last_operation
    assert all_tls_obs[0].handshake_last_operation.startswith("write_")
    assert all_tls_obs[0].ip == "172.67.187.120"
    assert all_tls_obs[0].port == 443

    assert all_tls_obs[1].ip == "104.21.32.206"
    assert all_tls_obs[1].port == 443

    http_blocked = load_measurement(
        msmt_path=measurements[
            "20220608121828.356206_RU_webconnectivity_80e3fa60eb2cd026"
        ]
    )
    mt = MeasurementTransformer(
        measurement=http_blocked, netinfodb=netinfodb, bucket_date="2022-06-08"
    )
    assert isinstance(http_blocked, WebConnectivity)
    all_http_obs = [
        obs
        for obs in mt.make_http_observations(
            http_blocked.test_keys.requests,
        )
    ]
    assert all_http_obs[-1].request_url == "http://proxy.org/"


def test_wc_v5_observations_chained(netinfodb, measurements):
    msmt = load_measurement(
        msmt_path=measurements[
            "20220924222854.036406_IR_webconnectivity_7aedefe4aaac824c"
        ]
    )
    assert isinstance(msmt, WebConnectivity)
    bucket_date = "2022-09-24"
    obs_tup = measurement_to_observations(
        msmt=msmt, netinfodb=netinfodb, bucket_date=bucket_date
    )
    assert len(obs_tup) == 2
    web_obs: List[WebObservation] = obs_tup[0]

    # TODO: there is something weird here.
    # Both DNS query answers are labeled with
    # transaction_id=2.
    # transaction_id=3 is mapped to one of these two with transaction_id=2, it's
    # unclear to me if that is a bug in the because it's unclear where the TCP
    # transaction with ID 3 got it's data from.

    # XXX commented out, see above comment
    # transaction_ids = list(map(lambda o: o.transaction_id, chained_observations))
    # assert len(transaction_ids) == len(set(transaction_ids))
    assert len(web_obs) == 15


# TODO:
# Investigate why this is failing:
# https://explorer.ooni.org/measurement/20221003T005456Z_webconnectivity_IR_44244_n1_efHx49XR5Na6XLQ2?input=https://raw.githubusercontent.com/ooni/spec/master/README.md
def test_wc_observations_chained(netinfodb, measurements):
    msmt = load_measurement(
        msmt_path=measurements[
            "20220608121828.356206_RU_webconnectivity_80e3fa60eb2cd026"
        ]
    )
    assert isinstance(msmt, WebConnectivity)
    bucket_date = "2022-06-08"
    obs_tup = measurement_to_observations(
        msmt=msmt, netinfodb=netinfodb, bucket_date=bucket_date
    )
    assert len(obs_tup) == 2
    web_obs = obs_tup[0]

    # Check if DNS and TCP connect observations are being linked together
    assert len(list(filter(lambda o: o.ip == "188.186.154.79", web_obs))) == 1
    assert len(web_obs) == 4

    msmt = load_measurement(
        msmt_path=measurements[
            "20221114002335.786418_BR_webconnectivity_6b203219ec4ded0e"
        ]
    )
    bucket_date = "2022-11-14"
    assert isinstance(msmt, WebConnectivity)
    obs_tup = measurement_to_observations(
        msmt=msmt, netinfodb=netinfodb, bucket_date=bucket_date
    )
    assert len(obs_tup) == 2
    web_obs: List[WebObservation] = obs_tup[0]

    assert len(list(filter(lambda o: o.ip == "172.67.16.69", web_obs))) == 1
    assert len(web_obs) == 4


def test_dnscheck_obs(netinfodb, measurements):
    msmt = load_measurement(
        msmt_path=measurements["20221013000000.517636_US_dnscheck_bfd6d991e70afa0e"]
    )
    assert isinstance(msmt, DNSCheck)
    obs_tup = measurement_to_observations(
        msmt=msmt, netinfodb=netinfodb, bucket_date="2022-10-13"
    )
    assert len(obs_tup) == 1
    web_obs = obs_tup[0]
    assert len(web_obs) == 20


def test_telegram_obs(netinfodb, measurements):
    msmt = load_measurement(
        msmt_path=measurements["20230427235943.206438_US_telegram_ac585306869eca7b"]
    )
    assert isinstance(msmt, Telegram)
    obs_tup = measurement_to_observations(
        msmt=msmt, netinfodb=netinfodb, bucket_date="2023-04-27"
    )
    assert len(obs_tup) == 1
    web_obs = obs_tup[0]

    for wo in web_obs:
        assert isinstance(wo, WebObservation)
        if wo.dns_engine:
            assert wo.dns_t
        if wo.tcp_success is not None:
            assert wo.tcp_t
        if wo.http_request_url:
            assert wo.http_t
        if wo.tls_cipher_suite:
            assert wo.tls_t
    assert len(web_obs) == 33


def test_stunreachability_obs(netinfodb, measurements):
    msmt = load_measurement(
        msmt_path=measurements[
            "20221224235924.922622_BR_stunreachability_905c61a34356a9b2"
        ]
    )
    assert isinstance(msmt, StunReachability)
    bucket_date = "2022-11-24"
    obs_tup = measurement_to_observations(
        msmt=msmt, netinfodb=netinfodb, bucket_date=bucket_date
    )
    assert len(obs_tup) == 1
    web_obs: List[WebObservation] = obs_tup[0]

    assert isinstance(web_obs[0], WebObservation)
    assert len(web_obs) == 1
    assert web_obs[0].dns_engine == "system"
    assert web_obs[0].dns_answer == "206.53.159.130"


def test_signal_obs(netinfodb, measurements):
    msmt = load_measurement(
        msmt_path=measurements["20221016235944.266268_GB_signal_1265ff650ee17b44"]
    )
    assert isinstance(msmt, Signal)
    bucket_date = "2021-10-16"
    obs_tup = measurement_to_observations(
        msmt=msmt, netinfodb=netinfodb, bucket_date=bucket_date
    )
    assert len(obs_tup) == 1
    web_obs: List[WebObservation] = obs_tup[0]

    for wo in web_obs:
        if wo.dns_engine:
            assert wo.dns_t
        if wo.tcp_success is not None:
            assert wo.tcp_t
        if wo.http_request_url:
            assert wo.http_t
        if wo.tls_cipher_suite:
            assert wo.tls_t
    assert len(web_obs) == 19


def test_urlgetter_obs(netinfodb, measurements):
    msmt = load_measurement(
        msmt_path=measurements["20211224011542.635260_IR_urlgetter_38d73cdfee442409"]
    )
    assert isinstance(msmt, UrlGetter)
    bucket_date = "2021-11-24"
    obs_tup = measurement_to_observations(
        msmt=msmt, netinfodb=netinfodb, bucket_date=bucket_date
    )
    assert len(obs_tup) == 1
    web_obs: List[WebObservation] = obs_tup[0]

    for wo in web_obs:
        if wo.dns_engine:
            assert wo.dns_t
        if wo.tcp_success is not None:
            assert wo.tcp_t
        if wo.http_request_url:
            assert wo.http_t
        if wo.tls_cipher_suite:
            assert wo.tls_t
    assert len(web_obs) == 6

    msmt = load_measurement(
        msmt_path=measurements["20221224180301.892770_VE_urlgetter_0a02e27d0c651b8f"]
    )
    assert isinstance(msmt, UrlGetter)
    bucket_date = "2021-11-24"
    obs_tup = measurement_to_observations(
        msmt=msmt, netinfodb=netinfodb, bucket_date=bucket_date
    )
    assert len(obs_tup) == 1
    web_obs: List[WebObservation] = obs_tup[0]

    for wo in web_obs:
        if wo.dns_engine:
            assert wo.dns_t
        if wo.tcp_success is not None:
            assert wo.tcp_t
        if wo.http_request_url:
            assert wo.http_t
        if wo.tls_cipher_suite:
            assert wo.tls_t
    assert len(web_obs) == 2


def test_whatsapp_obs(netinfodb, measurements):
    msmt = load_measurement(
        msmt_path=measurements["20211018232506.972850_IN_whatsapp_44970a56806dbfb3"]
    )
    assert isinstance(msmt, Whatsapp)
    bucket_date = "2021-10-18"
    obs_tup = measurement_to_observations(
        msmt=msmt, netinfodb=netinfodb, bucket_date=bucket_date
    )
    assert len(obs_tup) == 1
    web_obs: List[WebObservation] = obs_tup[0]

    for wo in web_obs:
        if wo.dns_engine:
            assert wo.dns_t
        if wo.tcp_success is not None:
            assert wo.tcp_t
        if wo.http_request_url:
            assert wo.http_t
        if wo.tls_cipher_suite:
            assert wo.tls_t
    assert len(web_obs) == 137


def test_browserweb_obs(netinfodb, measurements):
    msmt = load_measurement(
        msmt_path=measurements["20231222154141.824397_US_browserweb_615428b4802b5297"]
    )
    assert isinstance(msmt, BrowserWeb)
    bucket_date = "2023-12-22"
    obs_tup = measurement_to_observations(
        msmt=msmt, netinfodb=netinfodb, bucket_date=bucket_date
    )
    assert len(obs_tup) == 1
    web_obs: List[WebObservation] = obs_tup[0]

    assert len(web_obs) == 1
    assert isinstance(web_obs[0], WebObservation)
    assert web_obs[0].http_failure == "error"


def test_facebook_messenger_obs(netinfodb, measurements):
    msmt = load_measurement(
        msmt_path=measurements[
            "20220124235953.650143_ES_facebookmessenger_0e048a26b89a9d70"
        ]
    )
    assert isinstance(msmt, FacebookMessenger)
    bucket_date = "2022-01-24"
    obs_tup = measurement_to_observations(
        msmt=msmt, netinfodb=netinfodb, bucket_date=bucket_date
    )
    assert len(obs_tup) == 1
    web_obs: List[WebObservation] = obs_tup[0]

    # Based on https://github.com/ooni/spec/blob/master/nettests/ts-019-facebook-messenger.md
    spec_hostname_set = set(
        [
            "stun.fbsbx.com",
            "b-api.facebook.com",
            "b-graph.facebook.com",
            "edge-mqtt.facebook.com",
            "external.xx.fbcdn.net",
            "scontent.xx.fbcdn.net",
            "star.c10r.facebook.com",
        ]
    )

    hostname_set = set()
    for wo in web_obs:
        if wo.dns_engine:
            assert wo.dns_t
        if wo.tcp_success is not None:
            assert wo.tcp_t
        hostname_set.add(wo.hostname)
    assert hostname_set == spec_hostname_set
    assert len(web_obs) == 14


def test_echcheck_obs_tls_handshakes(netinfodb, measurements):
    msmt = load_measurement(
        msmt_path=measurements["20250120145930.582606_US_echcheck_899a304b7beef05c"]
    )
    assert isinstance(msmt, ECHCheck)
    assert msmt.test_version == '0.2.0'

    obs_tup = measurement_to_observations(
        msmt=msmt, netinfodb=netinfodb, bucket_date="2022-10-13"
    )
    assert len(obs_tup) == 1
    web_obs = obs_tup[0]
    assert len(web_obs) == 3
    assert any(wo.tls_echconfig == "GREASE" for wo in web_obs)


def test_echcheck_obs_control_and_target(netinfodb, measurements):
    msmt = load_measurement(
        msmt_path=measurements["20240714111032.898994_GB_echcheck_f10079cac5cdf770"]
    )
    assert isinstance(msmt, ECHCheck)
    assert msmt.test_version == '0.1.2'

    obs_tup = measurement_to_observations(
        msmt=msmt, netinfodb=netinfodb, bucket_date="2022-10-13"
    )
    assert len(obs_tup) == 1
    web_obs = obs_tup[0]
    assert len(web_obs) == 2
    assert any(wo.tls_echconfig == "GREASE" for wo in web_obs)


def test_tls_handshake_time(netinfodb, measurements):

    def check_hs_time_consistency(msmt, tt):
        assert isinstance(msmt, tt)
        assert msmt.test_keys.tls_handshakes and len(msmt.test_keys.tls_handshakes) > 0
        assert msmt.test_keys.network_events
        for idx, tls_h in enumerate(msmt.test_keys.tls_handshakes):
            tls_hs_events = find_tls_handshake_events_without_transaction_id(
                tls_h, idx, msmt.test_keys.network_events
            )
            assert tls_hs_events
            assert tls_hs_events[0].operation == "connect"
            assert tls_hs_events[-1].operation == "tls_handshake_done"
            assert tls_hs_events[-1].t - tls_hs_events[0].t > 0

    check_hs_time_consistency(
        load_measurement(
            msmt_path=measurements["20250319232753.365760_TR_whatsapp_b813f5e363550580"]
        ),
        Whatsapp,
    )
    check_hs_time_consistency(
        load_measurement(
            msmt_path=measurements["20250310005913.071112_TR_signal_e00d1c8955b29d01"]
        ),
        Signal,
    )
    check_hs_time_consistency(
        load_measurement(
            msmt_path=measurements["20250310011757.066396_TR_telegram_7a6b42661eb78d6f"]
        ),
        Telegram,
    )


def test_scrubbed_ip(netinfodb, measurements):
    msmt = load_measurement(
        msmt_path=measurements[
            "20250125135854.612046_AU_webconnectivity_45560dd5efe1035c"
        ]
    )
    assert isinstance(msmt, WebConnectivity)

    obs_tup = measurement_to_observations(
        msmt=msmt, netinfodb=netinfodb, bucket_date="2022-10-13"
    )
    assert len(obs_tup) == 2
    web_obs = obs_tup[0]
    ctrl_obs = obs_tup[1]
    assert len(web_obs) == 4
    assert len(ctrl_obs) == 5

    msmt = load_measurement(
        msmt_path=measurements["20250201172431.190360_CZ_signal_ef68029a5fff6e29"]
    )
    assert isinstance(msmt, Signal)

    obs_tup = measurement_to_observations(
        msmt=msmt, netinfodb=netinfodb, bucket_date="2022-10-13"
    )
    assert len(obs_tup) == 1
    web_obs = obs_tup[0]
    assert len(web_obs) == 31
    assert len(ctrl_obs) == 5


# --- target_id tagging for the IM tests -------------------------------------
#
# These tests probe fixed, named platform endpoints rather than a per-measurement
# URL, so their observations carry no `input` to group by. WebObservation.target_id
# is what identifies the endpoint; assert it is populated and that tagging did not
# perturb the observation counts asserted above.

IM_EXPECTED_TARGETS = {
    "20230427235943.206438_US_telegram_ac585306869eca7b": (
        "telegram",
        {"telegram/dc_pool", "telegram/web"},
    ),
    "20210926222047.205897_UZ_signal_95fab4a2e669573f": (
        "signal",
        {
            "signal/chat",
            "signal/directory",
            "signal/cdn",
            "signal/sfu",
            "signal/storage",
            "signal/uptime",
        },
    ),
    "20211018232506.972850_IN_whatsapp_44970a56806dbfb3": (
        "whatsapp",
        {"whatsapp/endpoints", "whatsapp/registration", "whatsapp/web"},
    ),
    "20220124235953.650143_ES_facebookmessenger_0e048a26b89a9d70": (
        "facebook_messenger",
        {
            "facebook_messenger/star",
            "facebook_messenger/b_api",
            "facebook_messenger/b_graph",
            "facebook_messenger/edge",
            "facebook_messenger/external_cdn",
            "facebook_messenger/scontent_cdn",
            "facebook_messenger/stun",
        },
    ),
}


@pytest.mark.parametrize(
    "measurement_uid,platform,expected_targets",
    [(uid, p, t) for uid, (p, t) in IM_EXPECTED_TARGETS.items()],
    ids=[p for _, (p, _) in IM_EXPECTED_TARGETS.items()],
)
def test_im_observations_are_tagged_with_targets(
    netinfodb, measurements, measurement_uid, platform, expected_targets
):
    from oonipipeline.targets import TARGETS_BY_ID

    msmt = load_measurement(msmt_path=measurements[measurement_uid])
    web_obs = measurement_to_observations(msmt=msmt, netinfodb=netinfodb)[0]

    seen = {wo.target_id for wo in web_obs if wo.target_id}
    assert seen == expected_targets

    # Every tagged id must be a declared target, so a typo in a transformer
    # can't invent one.
    for target_id in seen:
        assert target_id in TARGETS_BY_ID
        assert TARGETS_BY_ID[target_id].platform == platform

    # Every observation that identifies an endpoint gets tagged. Rows with
    # neither a hostname nor an IP carry no endpoint identity and are exempt.
    untagged = [wo for wo in web_obs if not wo.target_id and (wo.hostname or wo.ip)]
    assert not untagged, (
        f"{len(untagged)} observations identify an endpoint but got no "
        f"target_id, e.g. hostname={untagged[0].hostname!r} ip={untagged[0].ip!r}"
    )


IM_PLATFORM_BY_FIXTURE_TOKEN = {
    "_telegram_": "telegram",
    "_signal_": "signal",
    "_whatsapp_": "whatsapp",
    "_facebookmessenger_": "facebook_messenger",
}


def _im_fixture_uids():
    from ._fixtures import SAMPLE_MEASUREMENTS

    for uid in SAMPLE_MEASUREMENTS:
        for token, platform in IM_PLATFORM_BY_FIXTURE_TOKEN.items():
            if token in uid:
                yield uid, platform


@pytest.mark.parametrize(
    "measurement_uid,platform", list(_im_fixture_uids()), ids=lambda v: str(v)
)
def test_every_im_endpoint_resolves_to_a_target(
    netinfodb, measurements, measurement_uid, platform
):
    """
    Drift canary across every IM fixture, not just the representative ones.

    The platforms rename endpoints — Signal moved chat from
    textsecure-service.whispersystems.org to chat.signal.org and directory from
    api.directory.signal.org to cdsi.signal.org, and both eras are in the
    archive. An unrecognised hostname silently produces an untagged observation
    that then drops out of any target-keyed analysis, so fail loudly here
    instead and add the hostname to oonipipeline/targets.py.
    """
    msmt = load_measurement(msmt_path=measurements[measurement_uid])
    web_obs = measurement_to_observations(msmt=msmt, netinfodb=netinfodb)[0]

    unresolved = sorted(
        {
            endpoint
            for wo in web_obs
            if not wo.target_id
            for endpoint in [wo.hostname or wo.ip]
            # OONI's PII scrubbing substitutes the literal string "scrubbed"
            # for an address it redacted, so these rows carry no endpoint
            # identity to resolve. Not a missing mapping.
            if endpoint and endpoint != "scrubbed"
        }
    )
    assert not unresolved, (
        f"{platform} fixture {measurement_uid} has endpoints with no target "
        f"mapping: {unresolved}"
    )


# --- probe_id extraction ----------------------------------------------------


def _load_with(measurement_uid, measurements, **overrides):
    import orjson

    raw = orjson.loads(measurements[measurement_uid].read_bytes())
    raw.update(overrides)
    return load_measurement(msmt=raw)


def test_probe_id_is_extracted_onto_observations(netinfodb, measurements):
    """
    probe_id is a pseudonymous identifier issued via anonymous credentials,
    carried as a top-level key on the measurement. It lets consumers count
    distinct probes rather than using uniq(report_id) as a proxy.
    """
    uid = "20220608132401.787399_AM_webconnectivity_2285fc373f62729e"
    msmt = _load_with(uid, measurements, probe_id="anoncred-v1-9f2c4a7b")
    assert msmt.probe_id == "anoncred-v1-9f2c4a7b"

    web_obs, ctrl_obs = measurement_to_observations(msmt=msmt, netinfodb=netinfodb)
    assert web_obs
    for o in web_obs:
        assert o.probe_meta.probe_id == "anoncred-v1-9f2c4a7b"


def test_probe_id_absent_normalises_to_empty_string(netinfodb, measurements):
    """
    Every measurement collected before the scheme shipped omits the key. It must
    normalise to "" rather than None, so that "unknown probe" is a single value
    and the ClickHouse column stays non-nullable.
    """
    uid = "20220608132401.787399_AM_webconnectivity_2285fc373f62729e"
    msmt = load_measurement(msmt_path=measurements[uid])
    assert msmt.probe_id is None

    web_obs, _ = measurement_to_observations(msmt=msmt, netinfodb=netinfodb)
    assert web_obs
    for o in web_obs:
        assert o.probe_meta.probe_id == ""


def test_probe_id_extracted_for_non_web_nettests(netinfodb, measurements):
    """The field is on BaseMeasurement, so every nettest inherits it."""
    uid = "20210926222047.205897_UZ_signal_95fab4a2e669573f"
    msmt = _load_with(uid, measurements, probe_id="anoncred-v1-deadbeef")
    web_obs = measurement_to_observations(msmt=msmt, netinfodb=netinfodb)[0]
    assert web_obs
    assert {o.probe_meta.probe_id for o in web_obs} == {"anoncred-v1-deadbeef"}
