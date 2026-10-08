# OONI Changepoint API

HTTP API that detects when a website started or stopped being blocked in a country, using OONI
measurement data. Each changepoint is a moment when a CUSUM detector decided that a network moved
from OK to blocked (`BLOCK`), or from blocked back to `OK`, at one network layer.

A second endpoint, `/rule_counts`, shows the raw evidence behind a changepoint: which scoring rules
fired for each measurement of one network.

`/stored_changepoints` lists changepoints already found by the scheduled detector run (stored in
ClickHouse), across all domains and countries. It is fast and is the way to answer "what new
blocking was detected recently?" without knowing the domain in advance.

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

## GET /rule_counts

For one network (`probe_cc`, `probe_asn`, `resolver_asn`) and one domain, counts how many
measurements were assigned each rule, per hour and per layer. Every measurement is scored at each
layer by a rule (e.g. `country_consistent_blockpage` for DNS, `failure_ctrl_ok_reset` for TLS), and
the rule names say *how* the site was blocked or why it was considered OK. Use it to explain or
double check a changepoint: take `probe_asn` and `resolver_asn` from a `/changepoints` result and
query the days around its `ts_hour`.

### Query parameters

| name | type | required | default | meaning |
|---|---|---|---|---|
| `probe_cc` | string | yes | | Two-letter ISO country code. |
| `probe_asn` | int | yes | | Network of the probe, number only (`56377`, not `AS56377`). |
| `resolver_asn` | int | yes | | Network of the DNS resolver, number only. |
| `domain` | string | yes | | Hostname, exact match as in `/changepoints`. |
| `start_date` | date `YYYY-MM-DD` | yes | | First day (UTC). |
| `end_date` | date `YYYY-MM-DD` | no | `start_date` | Last day, inclusive. |

### Response 200

```json
{
  "query": { "probe_cc": "RU", "probe_asn": 56377, "resolver_asn": 56377, "domain": "twitter.com", "start_date": "2026-09-09", "end_date": "2026-09-10" },
  "totals": [
    { "layer": "dns", "rule_id": "country_consistent_blockpage", "class": "blocked", "count": 32 },
    { "layer": "tcp", "rule_id": "connect_ok", "class": "ok", "count": 32 },
    { "layer": "tls", "rule_id": "certificate_valid", "class": "ok", "count": 15 },
    { "layer": "tls", "rule_id": "failure_ctrl_ok_reset", "class": "blocked", "count": 17 }
  ],
  "hourly": [
    { "ts_hour": "2026-09-09T00:00:00+00:00", "layer": "dns", "rule_id": "country_consistent_blockpage", "class": "blocked", "count": 1 }
  ]
}
```

- `totals`: counts per (`layer`, `rule_id`) summed over the whole range, sorted by layer then
  rule. Start here; `hourly` can be long.
- `hourly`: the same counts broken down by `ts_hour` (start of the hour, UTC), sorted by hour,
  layer and rule. Hours with no measurements are absent.
- `rule_id`: the rule that scored the layer for that measurement. Its name describes what was seen.
- `class`: how the changepoint detector counts the rule:
  - `blocked`: evidence of blocking (counted towards both `k` and `n`).
  - `ok`: evidence the layer worked (counted towards `n` only).
  - `discarded`: ignored by the detector, e.g. the layer was not reached, the result is not
    trustworthy, or the site looked down rather than blocked, or the rule id is a legacy one.
- Within one layer and hour, the blocked share the detector sees is
  `blocked / (blocked + ok)`; it compares this against `p0` and `p1`.

### Errors

- `400`: `end_date` before `start_date`.
- `422`: missing or malformed parameter.

Empty `totals` and `hourly` mean no measurements for that exact combination; check the
`series` of `/changepoints` for the `probe_asn`/`resolver_asn` pairs that have data.

### Example

```
GET /rule_counts?probe_cc=RU&probe_asn=56377&resolver_asn=56377&domain=twitter.com&start_date=2026-09-09&end_date=2026-09-10
```

## POST /changepoint_labels

Stores a person's verdict on a changepoint from `event_detector_v2_changepoints`: the ground truth
of whether that network (`probe_cc`, `probe_asn`, `resolver_asn`) was blocking the domain around the
changepoint. A changepoint can be labelled more than once; every label is kept, and the most recent
`created_at` is the current one.

### Request body (JSON)

| name | type | required | default | meaning |
|---|---|---|---|---|
| `changepoint_id` | uuid | yes | | `uuid` of the changepoint in `event_detector_v2_changepoints`. |
| `author` | string, non-empty | yes | | Name of the person labelling. |
| `verdict` | `blocked` \| `ok` \| `undecided` | yes | | The network's actual state. |
| `notes` | string | no | `""` | Free-form text. |
| `last_ok_time` | datetime | no | null | Last time the domain was seen accessible before the block. |
| `first_block_time` | datetime | no | null | First time the domain was seen blocked. |
| `last_block_time` | datetime | no | null | Last time the domain was seen blocked. |
| `first_ok_time` | datetime | no | null | First time the domain was seen accessible after the block. |

Datetimes are ISO 8601, e.g. `2026-09-01T09:00:00Z`. Ones without a timezone are taken as UTC.

### Response 201

The stored label, with the server-generated `id` and `created_at`:

```json
{
  "id": "e3b28905-2e25-49d2-8d63-5cdfad3d729c",
  "created_at": "2026-10-08T16:32:08.134796+00:00",
  "changepoint_id": "26660500-5ea1-47f7-a7bf-36aa18c46197",
  "author": "luis",
  "verdict": "blocked",
  "notes": "confirmed",
  "last_ok_time": null,
  "first_block_time": "2026-09-01T09:00:00+00:00",
  "last_block_time": null,
  "first_ok_time": null
}
```

### Errors

- `404` `{"detail": "changepoint_id not found"}`: no changepoint with that uuid.
- `422`: missing or malformed field, e.g. a `verdict` other than `blocked`, `ok` or `undecided`.

### Example

```
POST /changepoint_labels
{"changepoint_id": "26660500-5ea1-47f7-a7bf-36aa18c46197", "author": "luis", "verdict": "blocked", "first_block_time": "2026-09-01T09:00:00Z"}
```

## GET /stored_changepoints

Lists changepoints the hourly detector job has already stored in the
`event_detector_v2_changepoints` table, newest first. Every filter is optional; with none it
returns the most recent changepoints anywhere.

Use `/stored_changepoints` to discover events (which countries, domains and networks changed).
Use `/changepoints` to recompute a specific domain and country over any range or with different
detector parameters.

### Query parameters

| name | type | default | meaning |
|---|---|---|---|
| `probe_cc` | string | | Two-letter country code (case insensitive). |
| `domain` | string | | Exact hostname. |
| `probe_asn` | int | | Probe network, number only. |
| `resolver_asn` | int | | Resolver network, number only. |
| `layer` | `dns` \| `tcp` \| `tls` | | Only this layer. |
| `state` | `BLOCK` \| `OK` | | `BLOCK` for blocking that started, `OK` for blocking that ended. |
| `start_date` | date `YYYY-MM-DD` | | Only changepoints with `ts_hour` on or after this day (UTC). |
| `end_date` | date `YYYY-MM-DD` | | Only changepoints with `ts_hour` on or before this day, inclusive. |
| `limit` | int 1–1000 | 100 | Maximum number of rows to return. |
| `offset` | int ≥ 0 | 0 | Rows to skip, for paging. |

### Response 200

```json
{
  "query": { "probe_cc": "RU", "state": "BLOCK", "start_date": null, "end_date": null, "limit": 100, "offset": 0 },
  "changepoints": [
    {
      "uuid": "ef9f7f66-af02-4a66-82f2-e570a5586c56",
      "domain": "pixelfed.social",
      "probe_cc": "RU",
      "probe_asn": 8402,
      "resolver_asn": 8402,
      "layer": "tcp",
      "ts_hour": "2026-10-03T11:00:00+00:00",
      "s_neg": 0.0,
      "s_pos": 31.71,
      "h": 30.0,
      "state": "BLOCK",
      "run_parameters": { "p0": 0.05, "p1": 0.5, "h_threshold": 30, "gap_halflife": 24, "use_decay": true, "warmup_days": 30 },
      "created_at": "2026-10-08T16:53:46.712000+00:00"
    }
  ]
}
```

- Fields mean the same as in `/changepoints`. Sorted by `ts_hour` newest first, then by domain,
  country, networks and layer.
- `uuid`: unique id of the stored row.
- `run_parameters`: the detector settings the job used (`h_threshold` is `h`). To reproduce a
  row with `/changepoints`, pass these values and a range that covers `ts_hour`.
- `created_at`: when the job wrote the row, which can be well after `ts_hour`.
- `query` echoes only the filters that were set.
- Fewer rows than `limit` means there are no more results. Otherwise request the next page with
  `offset` increased by `limit`.

### Errors

- `422`: malformed parameter, e.g. a `state` other than `BLOCK` or `OK`.

### Examples

```
GET /stored_changepoints?start_date=2026-10-01
GET /stored_changepoints?probe_cc=RU&state=BLOCK&limit=50
GET /stored_changepoints?domain=twitter.com&layer=tls&start_date=2026-10-01&end_date=2026-10-07
```
