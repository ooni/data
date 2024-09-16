There are different ways to access OONI data, wether that is via: [OONI
Explorer](https://explorer.ooni.org/), the [OONI API](https://api.ooni.io/) or
clickhouse table dumps.

The [OONI API](https://api.ooni.io/) is meant for developers and researchers and allows [searching for
measurement metadata](https://api.ooni.io/apidocs/#/default/get_api_v1_measurements), [fetching single measurements](https://api.ooni.io/apidocs/#/default/get_api_v1_measurement_meta), and [generating statistics](https://api.ooni.io/apidocs/#/default/get_api_v1_aggregation).

**Hovever the OONI API, is not designed for large data transfers (i.e. extracting tens of thousands of measurements or many GB of data) and implements rate limiting API.**
If you are interested in a dump of the clickhouse tables, please [reach out to us](https://ooni.org/about/) instead of scraping our API.

Researchers can access the raw measurement data from an S3 bucket. The
specifications of the OONI data formats can be found in
[ooni/spec](https://github.com/ooni/spec).

## Accessing raw measurement data

"Raw measurement data" refers to data structures uploaded by OONI Probes (run by volunteers worldwide) to the
processing pipeline.

Thanks to the [Amazon Open Data program](https://aws.amazon.com/government-education/open-data/), the whole OONI dataset
can be fetched from the [`ooni-data-eu-fra` Amazon S3 bucket](https://ooni-data-eu-fra.s3.eu-central-1.amazonaws.com/).

A single chunk of data is called "a measurement" and its uncompressed size can vary between 1KB to 1MB, roughly.

Probes usually upload multiple measurements on each execution. Measurements are stored temporarily and then batched together, compressed and uploaded to the S3 bucket once every hour. To ensure transparency, incoming measurements go through basic content validation and the API returns success or error;
once a measurement is accepted it will be published on S3.

OONI measurements are also processed by the fastpath and made immediately available on OONI Explorer. See the "receive_measurement" function in the probe_services.py file in the API codebase for details.

The commands which follow will be using the [aws s3 cli
tool](https://aws.amazon.com/cli/). See [their documentation on how to install
it](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html).

Since [OONI data is part of the AWS Open Data
program](https://registry.opendata.aws/ooni/), you don't have to pay for access
and you can use the `--no-sign-request` flag to access it for free.

## File paths in the S3 bucket in JSONL format

Contains a JSON document for each measurement, separated by newline and compressed, for easy processing.
The path structure allows to easily select, identify and download data based on the researcher's needs.

In the path template:
- `cc` is an uppercase [2 letter country code](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2)
- `testname` is a test name where underscores are removed
- `timestamp` is a `YYYYMMDD` timestamp
- `name` is a unique filename

### Compressed JSONL from measurements starting from 2020-10-20

The path structure is: `s3://ooni-data-eu-fra/raw/<timestamp>/<hour>/<cc>/<testname>/<ts2>_<cc>_<testname>.<host_id>.<counter>.jsonl.gz`

Example: `s3://ooni-data-eu-fra/raw/20210817/15/US/webconnectivity/2021081715_US_webconnectivity.n0.0.jsonl.gz`

Note: The path will be updated in the future to live under `/jsonl/`

Listing JSONL files:
```
aws s3 --no-sign-request ls \
    s3://ooni-data-eu-fra/raw/20210817/15/US/webconnectivity/
```

#### Downloading entire dates

If you would like to download the raw measurements for a particular country,
you can use the `aws s3 sync` command.

For example to download all JSONL measurements from Italy on the 1st of February 2024, you can run:
```
aws s3 --no-sign-request sync \
    s3://ooni-data-eu-fra/raw/20240201/ ./ \
    --exclude "*" --include "*/IT/*.jsonl.gz"
```

**Note**: the difference in paths compared to older data

### Compressed JSONL from measurements before 2020-10-21

The path structure is: `s3://ooni-data-eu-fra/jsonl/<testname>/<cc>/<timestamp>/00/<name>.jsonl.gz`

Example: `s3://ooni-data-eu-fra/jsonl/webconnectivity/IT/20200921/00/20200921_IT_webconnectivity.l.0.jsonl.gz`

Listing JSONL files:
```
aws s3 --no-sign-request ls s3://ooni-data-eu-fra/jsonl/
aws s3 --no-sign-request ls \
    s3://ooni-data-eu-fra/jsonl/webconnectivity/US/20201021/00/
```

#### Downloading entire dates

If you would like to download the raw measurements for a particular country,
you can use the `aws s3 sync` command.

For example to download webconnectivity measurements from Italy on the 1st of February 2024, you can run:
```
aws s3 --no-sign-request sync \
    s3://ooni-data-eu-fra/jsonl/webconnectivity/IT/20200201/ ./ \
    --exclude "*" \
    --include "*"
```

**Note**: the difference in paths compared to newer data

## Raw "postcans" from measurements starting from 2020-10-20

A "postcan" is tarball containing measurements as they are uploaded by the probes, optionally compressed.
Each HTTP POST is stored in the tarball as `<timestamp>_<cc>_<testname>/<timestamp>_<cc>_<testname>_<hash>.post`

Example: `s3://ooni-data-eu-fra/raw/20210817/11/GB/webconnectivity/2021081711_GB_webconnectivity.n0.0.tar.gz`

Listing postcan files:
```
aws s3 --no-sign-request ls s3://ooni-data-eu-fra/raw/20210817/
aws s3 --no-sign-request ls \
    s3://ooni-data-eu-fra/raw/20210817/11/GB/webconnectivity/
```
