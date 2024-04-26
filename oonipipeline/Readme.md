# OONI Pipeline v5

This it the fifth major iteration of the OONI Data Pipeline.

For historical context, these are the major revisions:
* `v0` - The "pipeline" is basically just writing the RAW json files into a public `www` directory. Used until ~2013
* `v1` - OONI Pipeline based on custom CLI scripts using mongodb as a backend. Used until ~2015.
* `v2` - OONI Pipeline based on [luigi](https://luigi.readthedocs.io/en/stable/). Used until ~2017.
* `v3` - OONI Pipeline based on [airflow](https://airflow.apache.org/). Used until ~2020.
* `v4` - OONI Pipeline basedon custom script and systemd units (aka fastpath). Currently in use in production.
* `v5` - Next generation OONI Pipeline. What this readme is relevant to. Expected to become in production by Q4 2024.

## Setup

In order to run the pipeline you should setup the following dependencies:
* [Temporal for python](https://learn.temporal.io/getting_started/python/dev_environment/)
* [Clickhouse](https://clickhouse.com/docs/en/install)
* [hatch](https://hatch.pypa.io/1.9/install/)


### Quick start

Start temporal dev server:
```
temporal server start-dev
```

Start clickhouse server:
```
mkdir -p _clickhouse-data
cd _clickhouse-data
clickhouse server
```

You can then start the desired workflow, for example to create signal observations for the US:
```
hatch run oonipipeline mkobs --probe-cc US --test-name signal --start-day 2024-01-01 --end-day 2024-01-02
```

Monitor the workflow executing by accessing: http://localhost:8233/

If you would like to also collect OpenTelemetry traces, you can set it up like so:
```
docker run -d --name jaeger \
  -e COLLECTOR_OTLP_ENABLED=true \
  -p 16686:16686 \
  -p 4317:4317 \
  -p 4318:4318 \
  jaegertracing/all-in-one:latest
```

They are then visible at the following address: http://localhost:16686/search
