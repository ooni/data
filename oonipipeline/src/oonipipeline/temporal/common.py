import logging

from typing import (
    Callable,
    Dict,
    List,
    Optional,
    Tuple,
)

log = logging.getLogger("oonidata.processing")

TS_FORMAT = "%Y-%m-%d %H:%M:%S"

def make_db_rows(
    dc_list: List,
    column_names: List[str],
    bucket_date: Optional[str] = None,
    custom_remap: Optional[Dict[str, Callable]] = None,
) -> Tuple[str, List[str]]:
    # TODO(art): this function is quite sketchy
    assert len(dc_list) > 0

    def maybe_remap(k, value):
        if custom_remap and k in custom_remap:
            return custom_remap[k](value)
        return value

    table_name = dc_list[0].__table_name__
    rows = []
    for d in dc_list:
        if bucket_date:
            d.bucket_date = bucket_date
        assert table_name == d.__table_name__, "inconsistent group of observations"
        rows.append(tuple(maybe_remap(k, getattr(d, k)) for k in column_names))

    return table_name, rows
