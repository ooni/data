import logging
import multiprocessing
from oonidata.dataclient import date_interval
from oonidata.db.connections import CSVConnection, ClickhouseConnection
from oonidata.fingerprintdb import FingerprintDB
from oonidata.netinfo import NetinfoDB
from oonidata.processing import (
    process_day,
)


log = logging.getLogger("oonidata.processing")


def worker(day_queue, args):
    fingerprintdb = FingerprintDB(datadir=args.data_dir, download=False)
    netinfodb = NetinfoDB(datadir=args.data_dir, download=False)

    if args.clickhouse:
        db = ClickhouseConnection(args.clickhouse)
    elif args.csv_dir:
        db = CSVConnection(args.csv_dir)
    else:
        raise Exception("Missing --csv-dir or --clickhouse")

    while True:
        day = day_queue.get(block=True)
        if day == None:
            break
        process_day(
            db,
            fingerprintdb,
            netinfodb,
            day,
            test_name=args.test_name,
            probe_cc=args.probe_cc,
            start_at_idx=args.start_at_idx,
            fast_fail=args.fast_fail,
        )

    db.close()


def run_process(args):
    # This triggers the download of the required files
    FingerprintDB(datadir=args.data_dir, download=True)
    NetinfoDB(datadir=args.data_dir, download=True)

    if args.csv_dir:
        log.info(
            "When generating CSV outputs we currently only support parallelism of 1"
        )
        args.parallelism = 1

    day_queue = multiprocessing.Queue()
    pool = multiprocessing.Pool(
        processes=args.parallelism, initializer=worker, initargs=(day_queue, args)
    )
    for day in date_interval(args.start_day, args.end_day):
        day_queue.put(day)

    for _ in range(args.parallelism):
        day_queue.put(None)

    day_queue.close()
    day_queue.join_thread()

    pool.close()
    pool.join()
