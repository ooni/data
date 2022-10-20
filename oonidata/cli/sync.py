from collections import defaultdict
from functools import partial
import gzip
import logging
import multiprocessing
from typing import List

import orjson
from tqdm.contrib.logging import tqdm_logging_redirect
from oonidata.dataclient import FileEntry, get_file_entries, iter_measurements
from oonidata.datautils import trim_measurement


log = logging.getLogger("oonidata")
logging.basicConfig(level=logging.INFO)


def make_filename(args, fe):
    flags = ""
    if args.max_string_size:
        flags = f"_max{args.max_string_size}"
    ts = fe.timestamp.strftime("%Y%m%d%H")
    filename = f"{ts}_{fe.probe_cc}_{fe.testname}{flags}.jsonl.gz"
    return filename


def download_file_entry_list(fe_list: List[FileEntry], args):
    """
    Download a list of file entries to the output dir.

    It assumes that the list of file entries in the list are all pertinent to
    the same testname, probe_cc, hour tuple
    """
    total_fe_size = 0
    output_dir = (
        args.output_dir
        / fe_list[0].testname
        / fe_list[0].timestamp.strftime("%Y-%m-%d")
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    output_path = output_dir / make_filename(args, fe_list[0])

    with gzip.open(output_path.with_suffix(".tmp"), "wb") as out_file:
        for fe in fe_list:
            assert fe.testname == fe_list[0].testname
            assert fe.timestamp == fe_list[0].timestamp
            assert fe.probe_cc == fe_list[0].probe_cc
            total_fe_size += fe.size

        for msmt_dict in iter_measurements(
            start_day=args.start_day,
            end_day=args.end_day,
            probe_cc=args.probe_cc,
            test_name=args.test_name,
            file_entries=fe_list,
        ):
            if args.max_string_size:
                msmt_dict = trim_measurement(msmt_dict, args.max_string_size)
            out_file.write(orjson.dumps(msmt_dict))
            out_file.write(b"\n")

    output_path.with_suffix(".tmp").rename(output_path)
    return total_fe_size


def run_sync(args):
    log.info(
        f"Downloading measurement in s3 for {args.start_day} - {args.end_day} probe_cc:"
        f" {args.probe_cc}"
    )
    testnames = set()
    if args.test_name is not None:
        testnames = set(list(map(lambda x: x.lower().replace("_", ""), args.test_name)))

    ccs = set()
    if args.probe_cc is not None:
        ccs = set(list(map(lambda x: x.upper(), args.probe_cc)))

    with tqdm_logging_redirect(unit_scale=True) as pbar:

        def cb_list_fe(p):
            if p.current_prefix_idx == 0:
                pbar.total = p.total_prefixes
                pbar.update(0)
                pbar.set_description("starting prefix listing")
                return
            pbar.update(1)
            pbar.set_description(
                f"listed {p.total_file_entries} files in {p.current_prefix_idx}/{p.total_prefixes} prefixes"
            )

        log.info("Listing file entries...")
        all_file_entries = get_file_entries(
            start_day=args.start_day,
            end_day=args.end_day,
            ccs=ccs,
            testnames=testnames,
            from_cans=True,
            progress_callback=cb_list_fe,
        )

        total_fe_size = 0
        to_download_fe = defaultdict(list)
        for fe in all_file_entries:
            if (
                args.output_dir
                / fe.testname
                / fe.timestamp.strftime("%Y%-m-%d")
                / make_filename(args, fe)
            ).exists():
                continue

            ts = fe.timestamp.strftime("%Y%m%d%H")
            # We group based on this key, so each process is writing to the same file.
            # Each raw folder can have multiple files on a given hour
            key = f"{ts}-{fe.testname}-{fe.probe_cc}"
            to_download_fe[key].append(fe)
            total_fe_size += fe.size

        pbar.unit = "B"
        pbar.reset(total=total_fe_size)
        pbar.set_description("downloading files")
        download_count = 0
        with multiprocessing.Pool() as pool:
            for fe_size in pool.imap_unordered(
                partial(
                    download_file_entry_list,
                    args=args,
                ),
                to_download_fe.values(),
            ):
                download_count += 1
                pbar.update(fe_size)
                pbar.set_description(
                    f"downloaded {download_count}/{len(to_download_fe)}"
                )
