import datetime

from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.models import Variable, Param
from oonipipeline.tasks.observations import (
    MakeObservationsParams,
    make_observations,
)
from oonipipeline.tasks.analysis import (
    MakeAnalysisParams,
    make_analysis_in_a_day,
)

with DAG(
    dag_id="batch_measurement_processing",
    params={
        "probe_cc": Param([], type="array"),
        "test_name": Param([], type="array"),
    },
    start_date=datetime.datetime(2012, 12, 4),
    schedule="@daily",
) as dag:
    start_day = "{{ ds }}"
    op_make_observations = PythonOperator(
        task_id="make_observations",
        python_callable=make_observations,
        op_args=[
            MakeObservationsParams(
                probe_cc=dag.params["probe_cc"],
                test_name=dag.params["test_name"],
                clickhouse=Variable.get("clickhouse_url", default_var=""),
                data_dir=Variable.get("data_dir", default_var=""),
                fast_fail=False,
                bucket_date=start_day,
            )
        ],
    )

    op_make_analysis = PythonOperator(
        task_id="make_analysis",
        python_callable=make_analysis_in_a_day,
        op_args=[
            MakeAnalysisParams(
                probe_cc=dag.params["probe_cc"],
                test_name=dag.params["test_name"],
                day=start_day,
            )
        ],
    )

    op_make_observations >> op_make_analysis

    # dag.log.info(
    #     f"finished make_observations for bucket_date={start_day} in "
    #     f"{total_t.pretty} speed: {obs_res['mb_per_sec']}MB/s ({obs_res['measurement_per_sec']}msmt/s)"
    # )

    # return {
    #     "measurement_count": obs_res["measurement_count"],
    #     "size": obs_res["total_size"],
    #     "mb_per_sec": obs_res["mb_per_sec"],
    #     "bucket_date": params.bucket_date,
    #     "measurement_per_sec": obs_res["measurement_per_sec"],
    # }
