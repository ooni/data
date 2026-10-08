from datetime import datetime, timezone


# docker-compose.yml loads measurements from these countries only
DATASET_PROBE_CC = {"IT", "IR"}


def parse_ts(ts: str) -> datetime:
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def assert_in_window(ts: str, params: dict):
    since = parse_ts(params["since"])
    until = parse_ts(params["until"])
    assert since <= parse_ts(ts) <= until, (ts, params)
