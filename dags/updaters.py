import pathlib
import datetime
from typing import List

from airflow import DAG
from airflow.operators.python import PythonVirtualenvOperator
from airflow.models import Variable, Param


def run_update_citizenlab_test_lists(clickhouse_url: str):
    from oonipipeline.tasks.updaters.citizenlab_test_lists_updater import (
        update_citizenlab_test_lists,
    )

    update_citizenlab_test_lists(clickhouse_url=clickhouse_url)

def run_update_fingerprints(clickhouse_url: str):
    from oonipipeline.tasks.updaters.fingerprints_updater import update_fingerprints

    update_fingerprints(clickhouse_url=clickhouse_url)

def run_update_asnmeta(clickhouse_url: str):
    from oonipipeline.tasks.updaters.asnmeta_updater import update_asnmeta

    update_asnmeta(clickhouse_url=clickhouse_url)

REQUIREMENTS = [str((pathlib.Path(__file__).parent.parent / "oonipipeline").absolute())]

with DAG(
    dag_id="weekly_updaters",
    default_args={
        "retries": 3,
        "retry_delay": datetime.timedelta(minutes=10),
    },
    schedule="@weekly",
    start_date=datetime.datetime(2025, 1, 1),
    catchup=False,
    max_active_tasks=2,
    max_active_runs=2,
) as dag_full:
    PythonVirtualenvOperator(
        task_id="update_asnmeta",
        python_callable=run_update_asnmeta,
        op_kwargs={
            "clickhouse_url": Variable.get("clickhouse_url", default_var=""),
        },
        requirements=REQUIREMENTS,
        system_site_packages=False,
    )

with DAG(
    dag_id="hourly_updaters",
    default_args={
        "retries": 3,
        "retry_delay": datetime.timedelta(minutes=10),
    },
    schedule="@hourly",
    start_date=datetime.datetime(2025, 1, 1),
    catchup=False,
    max_active_tasks=2,
    max_active_runs=2,
) as dag_full:
    PythonVirtualenvOperator(
        task_id="update_fingerprints",
        python_callable=run_update_fingerprints,
        op_kwargs={
            "clickhouse_url": Variable.get("clickhouse_url", default_var=""),
        },
        requirements=REQUIREMENTS,
        system_site_packages=False,
    )

with DAG(
    dag_id="halfhour_updaters",
    default_args={
        "retries": 3,
        "retry_delay": datetime.timedelta(minutes=10),
    },
    schedule="00/30 * * * *",
    start_date=datetime.datetime(2025, 1, 1),
    catchup=False,
    max_active_tasks=2,
    max_active_runs=2,
) as dag_full:
    PythonVirtualenvOperator(
        task_id="update_test_lists",
        python_callable=run_update_citizenlab_test_lists,
        op_kwargs={
            "clickhouse_url": Variable.get("clickhouse_url", default_var=""),
        },
        requirements=REQUIREMENTS,
        system_site_packages=False,
    )
