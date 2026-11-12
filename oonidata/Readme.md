# OONI Data

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
oonidata sync --probe-cc IT --start-day 2026-11-01 --end-day 2026-11-02 --output-dir measurements/
```

This will download all OONI measurements for Italy into the directory
`./measurements` that were uploaded between 2026-11-01 and 2026-11-02.
