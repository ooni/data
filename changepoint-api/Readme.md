# changepoint-api

Minimal FastAPI wrapper around `oonipipeline.analysis.detectorV2`. See `API.md` for the API spec.

Run (from this directory; needs [uv](https://docs.astral.sh/uv/)):

```
PYTHONPATH=../oonipipeline/src uv run app.py
```

Env vars: `CLICKHOUSE_URL` (default `clickhouse://localhost:9000/ooni`), `HOST` (default
`127.0.0.1`), `PORT` (default `8000`). To run it elsewhere, copy `app.py` and point `PYTHONPATH` at
any checkout of `oonipipeline/src`.
