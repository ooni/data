## OONI Data

OONI Data is a collection of tooling for downloading, analyzing and interpreting
OONI network measurement data.

Most users will likely be interested in using this as a CLI tool for downloading
measurements.

If that is your goal, getting started is easy, run:
```
pip install oonidata
```

You will then be able to download measurements via:
```
oonidata sync --probe-cc IT --start-day 2022-10-01 --end-day 2022-10-02 --output-dir measurements/
```

This will download all OONI measurements for Italy into the directory
`./measurements` that were uploaded between 2022-10-01 and 2022-10-02.

If you are interested in learning more about the design of the analysis tooling,
please read on.

## Developer setup

This project makes use of [poetry](https://python-poetry.org/) for dependency
management. Follow [their
instructions](https://python-poetry.org/docs/#installation) on how to set it up.

Once you have done that you should be able to run:
```
poetry install
poetry run python -m oonidata --help
```
## Architecture overview

The analysis engine is made up of several components:
* Observation generation
* Response body archving
* Ground truth generation
* Experiment result generation

Below we explain each step of this process in detail

At a high level the pipeline looks like this:
```mermaid
graph
    M{{Measurement}} --> OGEN[[make_observations]]
    OGEN --> |many| O{{Observations}}
    NDB[(NetInfoDB)] --> OGEN
    OGEN --> RB{{ResponseBodies}}
    RB --> BA[(BodyArchive)]
    FDB[(FingerprintDB)] --> FPH
    FPH --> BA
    RB --> FPH[[fingerprint_hunter]]
    O --> ODB[(ObservationTables)]

    ODB --> MKGT[[make_ground_truths]]
    MKGT --> GTDB[(GroundTruthDB)]
    GTDB --> MKER
    BA --> MKER
    ODB --> MKER[[make_experiment_results]]
    MKER --> |one| ER{{ExperimentResult}}
```

### Observation generation

The goal of the Observation generation stage is to take raw OONI measurements
as input data and produce as output observations.

An observation is a timestamped statement about some network condition that was
observed by a particular vantage point. For example, an observation could be
"the TLS handshake to 8.8.4.4:443 with SNI equal to dns.google failed with
a connection reset by peer error".

What these observations mean for the
target in question (e.g., is there blocking or is the target down?) is something
that is to be determined when looking at data in aggregate and is the
responsibility of the Verdict generation stage.

During this stage we are also going to enrich observations with metadata about
IP addresses (using the IPInfoDB).

Each each measurement ends up producing observations that are all of the same
type and are written to the same DB table.

This has the benefit that we don't need to lookup the observations we care about
in several disparate tables, but can do it all in the same one, which is
incredibly fast.

A side effect is that we end up with tables are can be a bit sparse (several
columns are NULL).

The tricky part, in the case of complex tests like web_connectivity, is to
figure out which individual sub measurements fit into the same observation row.
For example we would like to have the TCP connect result to appear in the same
row as the DNS query that lead to it with the TLS handshake towards that IP,
port combination.

You can run the observation generation with a clickhouse backend like so:
```
poetry run python -m oonidata mkobs --clickhouse clickhouse://localhost/ --data-dir tests/data/datadir/ --start-day 2022-08-01 --end-day 2022-10-01 --create-tables --parallelism 20
```

Here is the list of supported observations so far:
* [x] WebObservation, which has information about DNS, TCP, TLS and HTTP(s)
* [x] WebControlObservation, has the control measurements run by web connectivity (is used to generate ground truths)
* [ ] CircumventionToolObservation, still needs to be designed and implemented
  (ideally we would use the same for OpenVPN, Psiphon, VanillaTor)

### Response body archving

It is optionally possible to also create WAR archives of HTTP response bodies
when running the observation generation.

This is enabled by passing the extra command line argument `--archives-dir`.

Whenever a response body is detected in a measurement it is sent to the
archiving queue which takes the response body, looks up in the database if it
has seen it already (so we don't store exact duplicate bodies).
If we haven't archived it yet, we write the body to a WAR file and record it's
sha1 hash together with the filename where we wrote it to into a database.

These WAR archives can then be mined asynchronously for blockpages using the
fingerprint hunter command:
```
oonidata fphunt --data-dir tests/data/datadir/ --archives-dir warchives/ --parallelism 20
```

When a blockpage matching the fingerprint is detected, the relevant database row
for that fingerprint is updated with the ID of the fingerprint which was
detected.

### Ground Truth generation

In order to establish if something is being blocked or not, we need some ground truth for comparison.

The goal of the ground truth generation task is to build a ground truth
database, which contains all the ground truths for every target that has been
tested in a particular day.

Currently it's implemented using the WebControlObservations, but in the future
we could just use other WebObservation.

Each ground truth database is actually just a sqlite3 database. For a given day
it's approximately 150MB in size and we load them in memory when we are running
the analysis workflow.

### ExperimentResult generation

An experiment result is the interpretation of one or more observations with a
determination of whether the target is `BLOCKED`, `DOWN` or `OK`.

For each of these states a confidence indicator is given which is an estimate of the
likelyhood of that result to be accurate.

For each of the 3 states, it's possible also specify a `blocking_detail`, which
gives more information as to why the block might be occurring.

It's important to note that for a given measurement, multiple experiment results
can be generated, because a target might be blocked in multiple ways or be OK in
some regards, but not in orders.

This is best explained through a concrete example. Let's say a censor is
blocking https://facebook.com/ with the following logic:
* any DNS query for facebook.com get's as answer "127.0.0.1"
* any TCP connect request to 157.240.231.35 gets a RST
* any TLS handshake with SNI facebook.com gets a RST

In this scenario, assuming the probe has discovered other IPs for facebook.com
through other means (ex. through the test helper or DoH as web_connectivity 0.5
does), we would like to emit the following experiment results:
* BLOCKED, `dns.bogon`, `facebook.com`
* BLOCKED, `tcp.rst`, `157.240.231.35:80`
* BLOCKED, `tcp.rst`, `157.240.231.35:443`
* OK, `tcp.ok`, `157.240.231.100:80`
* OK, `tcp.ok`, `157.240.231.100:443`
* BLOCKED, `tls.rst`, `157.240.231.35:443`
* BLOCKED, `tls.rst`, `157.240.231.100:443`

This way we are fully characterising the block in all the methods through which
it is implemented.

### Current pipeline

This section documents the current [ooni/pipeline](https://github.com/ooni/pipeline)
design.

```mermaid
graph LR

    Probes --> ProbeServices
    ProbeServices --> Fastpath
    Fastpath --> S3MiniCans
    Fastpath --> S3JSONL
    Fastpath --> FastpathClickhouse
    S3JSONL --> API
    FastpathClickhouse --> API
    API --> Explorer
```

```mermaid
classDiagram
    direction RL
    class CommonMeta{
        measurement_uid
        report_id
        input
        domain
        probe_cc
        probe_asn
        test_name
        test_start_time
        measurement_start_time
        platform
        software_name
        software_version
    }

    class Measurement{
        +Dict test_keys
    }

    class Fastpath{
        anomaly
        confirmed
        msm_failure
        blocking_general
        +Dict scores
    }
    Fastpath "1" --> "1" Measurement
    Measurement *-- CommonMeta
    Fastpath *-- CommonMeta
```
