import io
import time
import gzip
from oonidata.dataclient import FileEntry, create_s3_client
from oonidata.dataformat import WebConnectivity, WebConnectivityTestKeys
from datetime import date


ITER_COUNT = 10

import json
import ujson
import orjson
import dacite.core


def dacite_from_dict_ujson(raw_msmt):
    data = ujson.loads(raw_msmt)
    dacite.core.from_dict(data_class=WebConnectivity, data=data)


def mashumoro_from_json(raw_msmt):
    msmt = orjson.loads(raw_msmt)
    WebConnectivity.from_dict(msmt)


def pydantic_from_json(raw_msmt):
    msmt = orjson.loads(raw_msmt)
    WebConnectivity.parse_obj(msmt)


def dacite_from_dict_orjson(raw_msmt):
    data = orjson.loads(raw_msmt)
    dacite.core.from_dict(data_class=WebConnectivity, data=data)


benchmarks = {
    "json": json.loads,
    "ujson": ujson.loads,
    "orjson": orjson.loads,
    "mashumoro_from_orjson": mashumoro_from_json,
    # "pydantic_from_json": pydantic_from_json,
    # "dacite_ujson": dacite_from_dict_ujson,
    # "dacite_orjson": dacite_from_dict_orjson,
}


def bench_func(raw_msmt_list, func):
    iters = 0
    errs = 0
    t0 = time.monotonic()
    for _ in range(ITER_COUNT):
        for raw_msmt in raw_msmt_list:
            try:
                func(raw_msmt)
            except Exception as exc:
                print(exc)
                errs += 1
            iters += 1

    return time.monotonic() - t0, iters, errs


def main():
    s3 = create_s3_client()
    fe = FileEntry(
        day=date(2022, 8, 1),
        country_code="IT",
        test_name="webconnectivity",
        filename="2022080100_IT_webconnectivity.n0.0.jsonl.gz",
        size=3834672,
        ext="jsonl.gz",
        s3path="raw/20220801/00/IT/webconnectivity/2022080100_IT_webconnectivity.n0.0.jsonl.gz",
        bucket_name="ooni-data-eu-fra",
    )
    out_file = io.BytesIO()
    s3.download_fileobj(fe.bucket_name, fe.s3path, out_file)
    raw_msmt_list = list(
        filter(lambda x: x != b"", gzip.decompress(out_file.getvalue()).split(b"\n"))
    )

    with open("sample-file.jsonl", "wb") as sample_file:
        sample_file.write(gzip.decompress(out_file.getvalue()))

    for b_name, func in benchmarks.items():
        runtime, iters, errs = bench_func(raw_msmt_list, func)
        print(f"# {b_name}")
        print(f"  runtime: {runtime}")
        print(f"  iters/s: {iters/runtime}")
        print(f"  iters: {iters}")
        print(f"  errs: {errs}")


main()
