## Upgrading oonipipeline version on clickhouse cluster

Login to `clickhouse1.prod.ooni.io`, then run:

```
cd /opt/miniconda && sudo -u miniconda /opt/miniconda/bin/pip install -e 'git+https://github.com/ooni/data@v5-rc1#egg=oonipipeline&subdirectory=oonipipeline'
```

## Run commands

```
sudo -u airflow CONFIG_FILE=/etc/ooni/pipeline/oonipipeline-config.toml /opt/miniconda/bin/python -m oonipipeline.main check-duplicates --start-at 2025-01-01 --end-at 2025-02-01
```

## Backfilling event detector

The event detector runs in an online mode, so you need to first pause the airflow task before you start the backfilling process.
If you don't stop it, the cusums table will be updated while you are backfilling, the rows will be deduplicated with new ones from the airflow task and it will not take the previous values from the backfill task.

You may also want to clear the detected events table before backfilling, so as to avoid a conflict in the detected events.

Here is the complete command to clear the changepoints and cusums tables before backfilling:
```
sudo -u airflow CONFIG_FILE=/etc/ooni/pipeline/oonipipeline-config.toml /opt/miniconda/bin/python -m oonipipeline.main event-detector --clear-changepoints --truncate-cusums --start-at 2025-01-01 --end-at 2026-01-01
```
