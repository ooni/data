# OONI Pipeline v5

This it the fifth major iteration of the OONI Data Pipeline.

For historical context, these are the major revisions:

- `v0` - The "pipeline" is basically just writing the RAW json files into a public `www` directory. Used until ~2013
- `v1` - OONI Pipeline based on custom CLI scripts using mongodb as a backend. Used until ~2015.
- `v2` - OONI Pipeline based on [luigi](https://luigi.readthedocs.io/en/stable/). Used until ~2017.
- `v3` - OONI Pipeline based on [airflow](https://airflow.apache.org/). Used until ~2020.
- `v4` - OONI Pipeline basedon custom script and systemd units (aka fastpath). Currently in use in production.
- `v5` - Next generation OONI Pipeline. What this readme is relevant to. Expected to become in production by Q4 2024.

## Setup

In order to run the pipeline you should setup the following dependencies:

- [Temporal for python](https://learn.temporal.io/getting_started/python/dev_environment/)
- [Clickhouse](https://clickhouse.com/docs/en/install)
- [hatch](https://hatch.pypa.io/1.9/install/)

### Quick start

```
git clone https://github.com/ooni/data
```

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
hatch run oonipipeline mkobs --probe-cc US --test-name signal --start-day 2024-01-01 --end-day 2024-01-02 --create-tables
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

### Production usage

By default we use thread based parallelism, but in production you really want
to have multiple workers processes which have inside of them multiple threads.

You should also be using the production temporal server with an elasticsearch
backend as opposed to the dev server.

To start all the server side components, we have a handy docker-compose.yml
that sets everything up.

It can be started by running from this directory:

```
docker compose up
```

The important services you can access are the following:

- Temporal UI: http://localhost:8080
- Superset UI: http://localhost:8083 (u: `admin`, p: `oonity`)
- OpenTelemetry UI: http://localhost:8088

We don't include a clickhouse instance inside of the docker-compose file by
design. The reason for that is that it's recommended you set that up separately
and not inside of docker.

To start the worker processes:

```
hatch run oonipipeline startworkers
```

Then you can trigger the workflow by passing the `--no-start-workers` flag:

```
hatch run oonipipeline mkobs --probe-cc US --start-day 2024-01-01 --end-day 2024-01-20 --no-start-workers --create-tables
```

#### Superset

Superset is a neat data viz platform.

In order to set it up to speak to your clickhouse instance, assuming it's
listening on localhost of the host container, you should:

1. Click Settings -> Data - Database connections
2. Click + Database
3. In the Supported Databases drop down pick "Clickhouse Connect"
4. Enter as Host `host.docker.internal` and port `8123`

Note: `host.docker.internal` only works reliably on windows, macOS and very
recent linux+docker versions. In linux the needed configuration is a bit more
complex and requires discovering the gateway IP of the host container,
adjusting the clickhouse setup to bind to that IP and setting up correct nft or
similar firewall rules.

5. Click connect
6. Go to datasets and click + Dataset
7. Add all the tables from the `clickhouse` database in the `default` schema.
   Recommended tables to add are `obs_web` and `measurement_experiment_result`.
8. You are now able to start building dashboards

For more information on superset usage and setup refer to [their
documentation](https://superset.apache.org/docs/).
