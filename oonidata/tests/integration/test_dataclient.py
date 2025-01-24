from datetime import date, datetime

from oonidata.dataclient import (
    date_interval,
    get_file_entries_hourly,
    iter_file_entries,
    get_v2_prefixes,
    iter_measurements,
)
from oonidata.dataclient import (
    get_file_entries,
    get_can_prefixes,
    Prefix,
    MC_BUCKET_NAME,
)


def test_iter_file_entries_new_jsonl():
    fe_list = list(
        iter_file_entries(
            Prefix(
                prefix="jsonl/webconnectivity/IT/20201020/00/",
                bucket_name=MC_BUCKET_NAME,
            )
        )
    )
    assert len(fe_list) == 41
    for fe in fe_list:
        assert fe.testname == "webconnectivity"
        assert fe.probe_cc == "IT"
        assert fe.size > 0
        assert fe.bucket_name == MC_BUCKET_NAME
        assert fe.timestamp == datetime(2020, 10, 20, 0, 0)
        assert fe.ext == "jsonl.gz"


def test_iter_file_entries_old_format():
    fe_list = list(
        iter_file_entries(
            Prefix(
                prefix="raw/20211020/00/IT/webconnectivity/", bucket_name=MC_BUCKET_NAME
            )
        )
    )
    assert len(fe_list) == 6
    for fe in fe_list:
        assert fe.testname == "webconnectivity"
        assert fe.probe_cc == "IT"
        assert fe.size > 0
        assert fe.bucket_name == MC_BUCKET_NAME
        assert fe.timestamp == datetime(2021, 10, 20, 0, 0)


def test_get_v2_prefixes():
    prefixes = list(get_v2_prefixes(set(), set(), date(2020, 1, 1), date(2020, 1, 2)))
    # assert len(prefixes) == 2516
    assert len(prefixes) == 2905


def test_get_file_entries():
    fe_list = get_file_entries(
        probe_cc=None,
        test_name=None,
        start_day=date(2021, 1, 1),
        end_day=date(2021, 1, 2),
        from_cans=False,
    )
    # assert len(fe_list) == 1125
    assert len(fe_list) == 3320


def test_get_file_entries_for_cc():
    from oonidata.dataclient import ProgressStatus

    def progress_callback(p):
        assert p.total_prefixes == 10
        assert (
            p.progress_status == ProgressStatus.LISTING_BEGIN
            or p.progress_status == ProgressStatus.LISTING
        )

    fe_list = get_file_entries(
        probe_cc="IT",
        test_name="webconnectivity",
        start_day=date(2022, 8, 1),
        end_day=date(2022, 8, 11),
        from_cans=True,
        progress_callback=progress_callback,
    )
    # assert len(fe_list) == 1125
    assert len(fe_list) == 454


def test_get_file_entries_by_hour():
    from oonidata.dataclient import ProgressStatus

    def progress_callback(p):
        assert p.total_prefixes == 1
        assert (
            p.progress_status == ProgressStatus.LISTING_BEGIN
            or p.progress_status == ProgressStatus.LISTING
        )

    fe_list = get_file_entries_hourly(
        probe_cc="IT",
        test_name="webconnectivity",
        start_hour=datetime(2022, 8, 1, 11),
        end_hour=datetime(2022, 8, 1, 12),
        from_cans=True,
        progress_callback=progress_callback,
    )
    assert len(fe_list) == 4


def test_get_can_prefixes():
    # print(get_can_prefixes(set(), set(), date(2019, 6, 2), date(2020, 10, 21)))
    # print(get_can_prefixes(set(), set(), date(2020, 6, 2), date(2020, 10, 21)))
    start_day = date(2020, 6, 1)
    end_day = date(2020, 6, 11)
    prefixes = get_can_prefixes(start_day, end_day)
    assert len(set([p.prefix.split("/")[-1] for p in prefixes])) == len(
        prefixes
    ), "Duplicate prefixes"
    assert len(prefixes) == len(
        list(date_interval(start_day, end_day))
    ), "Inconsistent prefix length"

    start_day = date(2020, 10, 12)
    end_day = date(2020, 10, 22)
    prefixes = get_can_prefixes(start_day, end_day)

    assert len(set([p.prefix.split("/")[-1] for p in prefixes])) == len(
        prefixes
    ), "Duplicate prefixes"
    assert len(prefixes) == len(
        list(date_interval(start_day, end_day))
    ), "Inconsistent prefix length"

    start_day = date(2019, 1, 1)
    end_day = date(2020, 10, 22)
    prefixes = get_can_prefixes(start_day, end_day)

    assert len(set([p.prefix.split("/")[-1] for p in prefixes])) == len(
        prefixes
    ), "Duplicate prefixes"
    assert len(prefixes) == len(
        list(date_interval(start_day, end_day))
    ), "Inconsistent prefix length"


def test_iter_measurements(caplog):
    import logging

    caplog.set_level(logging.DEBUG, logger="oonidata.dataclient")
    msmt_count_cans = 0
    report_id_cans = []
    msmt_count_jsonl = 0
    report_id_jsonl = []
    for msmt in iter_measurements(
        start_day=date(2018, 1, 1),
        end_day=date(2018, 1, 2),
        probe_cc=["IT"],
        test_name=["whatsapp"],
        from_cans=True,
        progress_callback=lambda x: print(x),
    ):
        msmt_count_cans += 1
        report_id_cans.append(msmt["report_id"])
        assert msmt["measurement_uid"] is not None

    for msmt in iter_measurements(
        start_day=date(2018, 1, 1),
        end_day=date(2018, 1, 2),
        probe_cc=["IT"],
        test_name=["whatsapp"],
        from_cans=False,
        progress_callback=lambda x: print(x),
    ):
        report_id_jsonl.append(msmt["report_id"])
        msmt_count_jsonl += 1

    assert set(report_id_jsonl) == set(report_id_cans)
    # TODO: these are disabled due to: https://github.com/ooni/backend/issues/613
    # We ought to probably come up with a workaround in the meantime
    # assert msmt_count_jsonl == msmt_count_cans
    # assert report_id_jsonl == report_id_cans

    count = 0
    for _ in iter_measurements(
        start_day=date(2022, 10, 20),
        end_day=date(2022, 10, 21),
        probe_cc=["BA"],
        test_name=["web_connectivity"],
        from_cans=True,
        progress_callback=lambda x: print(x),
    ):
        count += 1
    assert count == 200
