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
    probe_cc: List[str],
    test_name: List[str],
    day: str,
):
    from oonipipeline.tasks.analysis import (
        MakeAnalysisParams,
        make_analysis_in_a_day,
    )

    params = MakeAnalysisParams(probe_cc=probe_cc, test_name=test_name, day=day)
    make_analysis_in_a_day(params)


REQUIREMENTS = [str((pathlib.Path(__file__).parent.parent / "oonipipeline").absolute())]

with DAG(
    dag_id="batch_measurement_processing",
    default_args={
        "depends_on_past": True,
        "retries": 3,
        "retry_delay": datetime.timedelta(minutes=30),
    },
    params={
        "probe_cc": Param(default=[], type=["null", "array"]),
        "test_name": Param(default=[], type=["null", "array"]),
    },
    start_date=datetime.datetime(2012, 12, 4),
    schedule="@daily",
    catchup=False,
) as dag:
    start_day = "{{ ds }}"
    op_make_observations = PythonVirtualenvOperator(
        task_id="make_observations",
        python_callable=run_make_observations,
        op_kwargs={
            "probe_cc": dag.params["probe_cc"],
            "test_name": dag.params["test_name"],
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
            "probe_cc": dag.params["probe_cc"],
            "test_name": dag.params["test_name"],
            "day": start_day,
        },
        requirements=REQUIREMENTS,
        system_site_packages=False,
    )

    op_make_observations >> op_make_analysis
