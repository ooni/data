## Upgrading oonipipeline version on clickhouse cluster

Run the ansible command:
```
./play -i inventory -l data1.htz-fsn.prod.ooni.nu deploy-airflow.yml -t oonipipeline --diff
```

## Run commands

```
sudo -u airflow CONFIG_FILE=/etc/ooni/pipeline/oonipipeline-config.toml /opt/miniconda/bin/python -m oonipipeline.main check-duplicates --start-at 2025-01-01 --end-at 2025-02-01
```

## Backfilling event detector

The event detector runs in an online mode, so you need to first pause the airflow task before you start the backfilling process.
If you don't stop it, the cusums table will be updated while you are backfilling, the rows will be deduplicated with new ones from the airflow task and it will not take the previous values from the backfill task.
You can stop the execution of the event detector by going into
`Admin->Variables` in airflow and setting the variable `enable_event_detector`
to `false`.

You may also want to clear the detected events table before backfilling, so as to avoid a conflict in the detected events.

Here is the complete command to clear the changepoints and cusums tables before backfilling:
```
sudo -u airflow CONFIG_FILE=/etc/ooni/pipeline/oonipipeline-config.toml /opt/miniconda/bin/python -m oonipipeline.main event-detector --clear-changepoints --truncate-cusums --start-at 2025-01-01 --end-at 2026-01-01
```

## Backfilling the analysis

If you make updates to the rules and need to re-run them, you should clear the
task state inside of airflowas follows:

```
airflow tasks clear hourly_batch_measurement_processing --task-regex make_analysis --start-date 2026-08-16 --end-date 2026-08-22 --yes
```

You can then monitor progress easier in airflow or with the following query (be
sure to replace the date ranges below):

```
WITH
    toDateTime('2026-08-16 00:00:00') AS range_start,
    toDateTime('2026-08-22 00:00:00') AS range_end
SELECT
    count()                                      AS windows_done,
    dateDiff('hour', range_start, range_end)     AS windows_total,
    round(100 * windows_done / windows_total, 1) AS pct,
    argMax(window_start, finished_at)            AS current_window,
    max(window_start)                            AS furthest_window,
    max(finished_at)                             AS last_activity,
    round(avg(ms) / 1000, 1)                     AS avg_secs,
    formatReadableTimeDelta((windows_total - windows_done) * avg(ms) / 1000) AS eta
FROM (
    -- One row per distinct window, keeping its most recent completion.
    SELECT
        parseDateTimeBestEffortOrNull(
            extract(query, 'measurement_start_time > \'([^\']+)\'')) AS window_start,
        max(event_time)                       AS finished_at,
        argMax(query_duration_ms, event_time) AS ms
    FROM system.query_log
    WHERE type = 'QueryFinish'
      AND is_initial_query
      AND event_time > now() - INTERVAL 36 HOUR
      AND query LIKE '%INSERT INTO analysis_web_measurement%'
    GROUP BY window_start
    HAVING window_start >= range_start AND window_start < range_end
) Format Vertical
```

Once this is done, you will also have to run an OPTIMIZE query to clear all
duplicate entries:
```
OPTIMIZE TABLE ON CLUSTER oonidata_cluster PARTITION '202608';
```

Before this merge is complete, queries to the tables might return duplicates,
which is why it's important to pause any consumer of the data (eg. event
detector) while this is happening.
