# OONI Changepoint API

HTTP API that detects when a website started or stopped being blocked in a country, using OONI
measurement data. Each changepoint is a moment when a CUSUM detector decided that a network moved
from OK to blocked (`BLOCK`), or from blocked back to `OK`, at one network layer.

Base URL: `http://127.0.0.1:8000` (the machine-readable schema is at `/openapi.json`).

## GET /changepoints

Returns changepoints for one domain in one country over a date range (all times UTC).

### Query parameters

| name | type | required | default | meaning |
|---|---|---|---|---|
| `probe_cc` | string | yes | | Two-letter ISO country code, e.g. `IR`, `RU`. |
| `domain` | string | yes | | Hostname without scheme or path, e.g. `twitter.com`. Must match exactly: `twitter.com` and `x.com` are different domains. |
| `start_date` | date `YYYY-MM-DD` | yes | | First day to report changepoints for. |
| `end_date` | date `YYYY-MM-DD` | no | `start_date` | Last day (inclusive). Omit it to query a single day. |
| `layers` | `dns` \| `tcp` \| `tls`, repeatable | no | all three | Which layers to run on, e.g. `layers=dns&layers=tls`. |
| `warmup_days` | int 0–365 | no | 30 | Days of history before `start_date` replayed to learn the starting state. No changepoints are reported from the warmup. |
| `p0` | float 0–1 | no | 0.05 | Expected blocked fraction when a network is OK. |
| `p1` | float 0–1 | no | 0.50 | Expected blocked fraction when a network is blocking. Must be > `p0`. |
| `h` | float > 0 | no | 30 | Detection threshold. Higher means fewer, more confident changepoints. |
| `gap_halflife` | float > 0 | no | 24 | Hours of missing data after which the accumulated evidence is halved. |
| `use_decay` | bool | no | true | Whether to apply the `gap_halflife` decay. |

Normally only `probe_cc`, `domain`, `start_date` and `end_date` should be set; leave the
detector parameters at their defaults unless asked otherwise.

### Response 200

```json
{
  "query": { "probe_cc": "RU", "domain": "twitter.com", "start_date": "2026-09-01", "end_date": "2026-09-30", "...": "echo of all parameters used" },
  "changepoints": [
    {
      "layer": "tls",
      "domain": "twitter.com",
      "probe_cc": "RU",
      "probe_asn": 56377,
      "resolver_asn": 56377,
      "ts_hour": "2026-09-09T14:00:00+00:00",
      "state": "BLOCK",
      "s_pos": 32.24,
      "s_neg": 0,
      "h": 30.0
    }
  ],
  "series": [
    {
      "probe_asn": 56377,
      "resolver_asn": 56377,
      "n_measurements": 412,
      "final_state": { "dns": "OK", "tcp": "OK", "tls": "OK" }
    }
  ]
}
```

- `changepoints`: sorted by `ts_hour`. Empty when nothing changed in the range.
  - `state`: the state entered at `ts_hour`: `BLOCK` (blocking started) or `OK` (blocking ended).
  - `layer`: where blocking was seen. `dns` = DNS tampering, `tcp` = connection blocked,
    `tls` = TLS handshake interfered with (e.g. SNI filtering).
  - `probe_asn`: the network (ISP) of the measuring probe. `resolver_asn`: the network of the DNS
    resolver the probe used. Each (`probe_asn`, `resolver_asn`) pair is detected separately.
  - `s_pos` / `s_neg`: accumulated evidence for blocking / for unblocking when the threshold `h`
    was crossed. Further above `h` means stronger evidence.
- `series`: one entry per (`probe_asn`, `resolver_asn`) seen in the range plus warmup.
  - `final_state`: per-layer state at the end of the range: `OK`, `BLOCK`, or `UNK` (not enough
    data to decide). Use it to answer "is X blocked right now / at the end of the range", since a
    block that began before `start_date` produces no changepoint inside the range.
  - `n_measurements`: measurements inside the range (warmup excluded). Low counts mean weak evidence.

### Errors

- `400` `{"detail": "..."}`: `end_date` before `start_date`, or `p1 <= p0`.
- `422`: missing or malformed parameter (FastAPI validation error).

### Examples

```
GET /changepoints?probe_cc=RU&domain=twitter.com&start_date=2026-09-01&end_date=2026-09-30
GET /changepoints?probe_cc=IR&domain=www.instagram.com&start_date=2026-10-01
GET /changepoints?probe_cc=TZ&domain=x.com&start_date=2026-06-01&end_date=2026-06-30&layers=dns&layers=tls
```

### Notes for interpreting results

- An empty `changepoints` list with no `series` means there were no OONI measurements for that
  domain and country. That does not mean the site is accessible.
- Ranges of months on a popular domain can take tens of seconds.
- To give a person a chart to check a changepoint against, link to OONI Explorer (same format as `detector.get_explorer_url`):
  `https://explorer.ooni.org/chart/mat?domain=<domain>&probe_cc=<cc>&probe_asn=<asn>&since=<YYYY-MM-DD>&until=<YYYY-MM-DD>&axis_x=measurement_start_day`
