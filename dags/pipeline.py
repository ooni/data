import pathlib
import datetime
from typing import List

from airflow import DAG
from airflow.operators.python import PythonVirtualenvOperator
from airflow.models import Variable, Param


def run_make_observations(
    probe_cc: List[str],
    test_name: List[str],
    clickhouse_url: str,
    data_dir: str,
    bucket_date: str,
):
    from oonipipeline.tasks.observations import (
        MakeObservationsParams,
        make_observations,
    )

    params = MakeObservationsParams(
        probe_cc=probe_cc,
        test_name=test_name,
        clickhouse=clickhouse_url,
        fast_fail=False,
        data_dir=data_dir,
        bucket_date=bucket_date,
    )
    make_observations(params)


def run_make_analysis(
    clickhouse_url: str,
    probe_cc: List[str],
    test_name: List[str],
    timestamp: str,
):
    from oonipipeline.tasks.analysis import (
        MakeAnalysisParams,
        make_analysis,
    )

    params = MakeAnalysisParams(
        probe_cc=probe_cc,
        test_name=test_name,
        timestamp=timestamp,
        clickhouse_url=clickhouse_url,
    )
    make_analysis(params)


REQUIREMENTS = [str((pathlib.Path(__file__).parent.parent / "oonipipeline").absolute())]

with DAG(
    dag_id="batch_measurement_processing",
    default_args={
        "retries": 3,
        "retry_delay": datetime.timedelta(minutes=10),
    },
    params={
        "probe_cc": Param(default=[], type=["null", "array"]),
        "test_name": Param(default=[], type=["null", "array"]),
    },
    start_date=datetime.datetime(2012, 12, 4),
    # We offset the schedule by 30 minutes so that we give time for the uploader
    # to finish
    schedule="30 0 * * *",
    catchup=False,
    max_active_tasks=2,
    max_active_runs=2,
) as dag_full:
    # YYYY-MM-DD
    start_day = "{{ ds }}"
    op_make_observations = PythonVirtualenvOperator(
        task_id="make_observations",
        python_callable=run_make_observations,
        op_kwargs={
            "probe_cc": dag_full.params["probe_cc"],
            "test_name": dag_full.params["test_name"],
            "clickhouse_url": Variable.get("clickhouse_url", default_var=""),
            "data_dir": Variable.get("data_dir", default_var=""),
            "bucket_date": start_day,
        },
        requirements=REQUIREMENTS,
        system_site_packages=False,
    )

    op_make_analysis = PythonVirtualenvOperator(
        task_id="make_analysis",
        python_callable=run_make_analysis,
        op_kwargs={
            "probe_cc": dag_full.params["probe_cc"],
            "test_name": dag_full.params["test_name"],
            "clickhouse_url": Variable.get("clickhouse_url", default_var=""),
            "day": start_day,
        },
        requirements=REQUIREMENTS,
        system_site_packages=False,
    )

    op_make_observations >> op_make_analysis

with DAG(
    dag_id="hourly_batch_measurement_processing",
    default_args={
        "retries": 3,
        "retry_delay": datetime.timedelta(minutes=5),
    },
    params={
        "probe_cc": Param(default=[], type=["null", "array"]),
        "test_name": Param(default=[], type=["null", "array"]),
    },
    start_date=datetime.datetime(2012, 12, 4),
    # We offset the schedule by 30 minutes so that we give time for the uploader
    # to finish
    schedule="30 * * * *",
    catchup=False,
    max_active_tasks=2,
    max_active_runs=2,
) as dag_full:
    # YYYY-MM-DDTHH
    start_hour = "{{ ts }}"[:13]
    op_make_observations_hourly = PythonVirtualenvOperator(
        task_id="make_observations_hourly",
        python_callable=run_make_observations,
        op_kwargs={
            "probe_cc": dag_full.params["probe_cc"],
            "test_name": dag_full.params["test_name"],
            "clickhouse_url": Variable.get("clickhouse_url", default_var=""),
            "data_dir": Variable.get("data_dir", default_var=""),
            "bucket_date": start_hour,
        },
        requirements=REQUIREMENTS,
        system_site_packages=False,
    )

    op_make_analysis_hourly = PythonVirtualenvOperator(
        task_id="make_analysis",
        python_callable=run_make_analysis,
        op_kwargs={
            "probe_cc": dag_full.params["probe_cc"],
            "test_name": dag_full.params["test_name"],
            "clickhouse_url": Variable.get("clickhouse_url", default_var=""),
            "timestamp": start_hour,
        },
        requirements=REQUIREMENTS,
        system_site_packages=False,
    )

    op_make_observations_hourly >> op_make_analysis_hourly
