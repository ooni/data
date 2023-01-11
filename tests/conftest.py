import os
from pathlib import Path
from datetime import date
from click.testing import CliRunner

import pytest

import orjson

from oonidata.fingerprintdb import FingerprintDB
from oonidata.netinfo import NetinfoDB
from oonidata.dataclient import sync_measurements
from oonidata.apiclient import get_measurement_dict, get_raw_measurement

from .explorer_urls import EXPLORER_URLS, get_report_id_input

FIXTURE_PATH = Path(os.path.dirname(os.path.realpath(__file__))) / "data"
DATA_DIR = FIXTURE_PATH / "datadir"

SAMPLE_MEASUREMENTS = [
    (
        "20220107222458.184469_IL_webconnectivity_d32af5597d7eeccc",
        "20220107T222039Z_webconnectivity_IL_42925_n1_18Kwpmtx9nYVVoeM",
        "https://ooni.org/",
    ),
    (
        "20220607115854.978538_BR_webconnectivity_d47c958eb0986d1b",
        "20220607T115805Z_webconnectivity_BR_270374_n1_69vdpoRbUpU1Lwjz",
        "https://ooni.org/",
    ),
    (
        "20220608132401.787399_AM_webconnectivity_2285fc373f62729e",
        "20220608T131504Z_webconnectivity_AM_49800_n1_AqEZWsh35AuSmwMv",
        "http://hahr.am",
    ),
    (
        "20220608155654.044764_AM_webconnectivity_ccb727b4812234a5",
        "20220608T154458Z_webconnectivity_AM_49800_n1_Xz3UTlXhINnvPC0o",
        "https://aysor.am",
    ),
    (
        "20220608122138.241075_IR_webconnectivity_c4240e52c7ca025f",
        "20220608T122003Z_webconnectivity_IR_58224_n1_AcrDNmCaHeCbDoNj",
        "https://www.youtube.com/",
    ),
    (
        "20220608121828.356206_RU_webconnectivity_80e3fa60eb2cd026",
        "20220608T120927Z_webconnectivity_RU_41668_n1_wuoaKW00hbGU12Yw",
        "http://proxy.org/",
    ),
    (
        "20220627131742.081225_GB_webconnectivity_e1e2cf4db492b748",
        "20220627T131610Z_webconnectivity_GB_5089_n1_hPwPFmWSlBooLToC",
        "https://ooni.org/",
    ),
    (
        "20220627030703.592775_IR_webconnectivity_80e199b3c572f8d3",
        "20220626T215355Z_webconnectivity_IR_206065_n1_aoeFoexkL6onyiqN",
        "https://thepiratebay.org/",
    ),
    (
        "20220627134426.194308_DE_webconnectivity_15675b61ec62e268",
        "20220627T134105Z_webconnectivity_DE_3209_n1_OxtDrquootq2Ud5G",
        "https://thepiratebay.org/",
    ),
    (
        "20220627125833.737451_FR_webconnectivity_bca9ad9d3371919a",
        "20220627T125710Z_webconnectivity_FR_5410_n1_KMkIWk9q4gZRq9gS",
        "https://thepiratebay.org/",
    ),
    (
        "20220625234824.235023_HU_webconnectivity_3435a5df0e743d39",
        "20220625T234722Z_webconnectivity_HU_20845_n1_Kg7ARyGpKG58zIZU",
        "https://thepiratebay.org/",
    ),
    (
        "20220924222854.036406_IR_webconnectivity_7aedefe4aaac824c",
        "20220924T215758Z_webconnectivity_IR_206065_n1_2CRoWBNJkWc7VyAs",
        "https://doh.dns.apple.com/dns-query?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB",
    ),
    (
        "20221020235950.432819_NL_signal_27b05458f186a906",
        "20221020T235949Z_signal_NL_13127_n1_3OMvDeaFEYRUpmMQ",
        None,
    ),
    (
        "20221016235944.266268_GB_signal_1265ff650ee17b44",
        "20221016T235943Z_signal_GB_2856_n1_sFk2dryEB6FQDSqM",
        None,
    ),
    (
        "20210926222047.205897_UZ_signal_95fab4a2e669573f",
        "20210926T222024Z_signal_UZ_201767_n1_DRRr4WJQ5hKHYhs2",
        None,
    ),
    (
        "20221018174612.488229_IR_signal_f8640b28061bec06",
        "20221018T174538Z_signal_IR_44244_n1_aCmeIoeeYLKBkyxo",
        None,
    ),
    (
        "20221013000000.517636_US_dnscheck_bfd6d991e70afa0e",
        "20221012T235950Z_dnscheck_US_10396_n1_EhBJEeRzCdMRTLDH",
        "dot://dns.quad9.net/",
    ),
    (
        "20221114002335.786418_BR_webconnectivity_6b203219ec4ded0e",
        "20221114T002124Z_webconnectivity_BR_27699_n1_knqvcofoEIxHMpzj",
        "https://cdt.org/",
    ),
]


@pytest.fixture
def datadir():
    return DATA_DIR


@pytest.fixture
def fingerprintdb(datadir):
    return FingerprintDB(
        datadir=datadir,
        download=True,
    )


@pytest.fixture
def netinfodb():
    return NetinfoDB(
        datadir=DATA_DIR,
        download=True,
    )


@pytest.fixture
def raw_measurements():
    output_dir = FIXTURE_PATH / "raw_measurements"
    if (output_dir / "signal" / "2022-10-01").exists():
        return output_dir
    sync_measurements(
        output_dir=output_dir,
        probe_cc=["IT"],
        test_name=["web_connectivity", "signal"],
        start_day=date(2022, 10, 1),
        end_day=date(2022, 10, 2),
    )
    return output_dir


@pytest.fixture
def measurements():
    measurement_dir = FIXTURE_PATH / "measurements"
    measurement_dir.mkdir(parents=True, exist_ok=True)

    sampled_measurements = {}
    for msmt_uid, report_id, input_ in SAMPLE_MEASUREMENTS:
        sampled_measurements[msmt_uid] = measurement_dir / f"{msmt_uid}.json"
        if sampled_measurements[msmt_uid].exists():
            continue
        msmt = get_measurement_dict(report_id=report_id, input=input_)
        with sampled_measurements[msmt_uid].open("wb") as out_file:
            out_file.write(orjson.dumps(msmt))
    return sampled_measurements


@pytest.fixture
def explorer_urls():
    sampled_measurements = {}

    measurement_dir = FIXTURE_PATH / "measurements" / "explorer_urls"
    measurement_dir.mkdir(parents=True, exist_ok=True)
    for key, explorer_url in EXPLORER_URLS.items():
        report_id, input_ = get_report_id_input(explorer_url)
        sampled_measurements[key] = measurement_dir / f"{key}.json"

        msmt = get_measurement_dict(report_id=report_id, input=input_)
        with sampled_measurements[key].open("wb") as out_file:
            out_file.write(orjson.dumps(msmt))
    return sampled_measurements


@pytest.fixture
def cli_runner():
    return CliRunner()
