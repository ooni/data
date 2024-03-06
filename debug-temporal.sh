# >>> json.dumps(asdict(ObservationsWorkflowParams(probe_cc=["IT"], start_day="2024-01-01", end_day="2024-01-02", clickhouse="clickhouse://localhost/", data_dir="/Users/art/repos/ooni/data/tests/data/", parallelism=10, fast_fail=False, test_name=["signal"])))
#
#
INPUT_JSON="{\"probe_cc\": [\"IT\"], \"test_name\": [\"signal\"], \"start_day\": \"2024-01-01\", \"end_day\": \"2024-01-20\", \"clickhouse\": \"clickhouse://localhost/\", \"data_dir\": \"$(pwd)/tests/data/datadir/\", \"parallelism\": 10, \"fast_fail\": false, \"log_level\": 20}"

echo $INPUT_JSON
temporal workflow start \
    --task-queue oonidatapipeline-task-queue \
    --type ObservationsWorkflow \
    --namespace default \
    --input "$INPUT_JSON"

