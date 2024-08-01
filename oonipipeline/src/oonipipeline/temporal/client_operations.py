import asyncio
import pathlib
import signal
import sys
import logging
import dataclasses
from dataclasses import dataclass
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Tuple

from oonipipeline.temporal.workers import make_threaded_worker
from oonipipeline.temporal.workflows import (
    TASK_QUEUE_NAME,
    AnalysisWorkflowParams,
    ObservationsWorkflowParams,
    schedule_analysis,
    schedule_observations,
)

from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry import trace

from temporalio.client import (
    Client as TemporalClient,
    ScheduleBackfill,
    ScheduleOverlapPolicy,
    WorkflowExecution,
)
from temporalio.service import TLSConfig
from temporalio.contrib.opentelemetry import TracingInterceptor
from temporalio.runtime import (
    OpenTelemetryConfig,
    Runtime as TemporalRuntime,
    TelemetryConfig,
)
from temporalio.types import MethodAsyncSingleParam, SelfType, ParamType, ReturnType

log = logging.getLogger("oonidata.client_operations")


@dataclass
class TemporalConfig:
    temporal_address: str = "localhost:7233"
    telemetry_endpoint: Optional[str] = None
    temporal_namespace: Optional[str] = None
    temporal_tls_client_cert_path: Optional[str] = None
    temporal_tls_client_key_path: Optional[str] = None


def init_runtime_with_telemetry(endpoint: str) -> TemporalRuntime:
    provider = TracerProvider(resource=Resource.create({SERVICE_NAME: "oonipipeline"}))
    exporter = OTLPSpanExporter(
        endpoint=endpoint, insecure=endpoint.startswith("http://")
    )
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    return TemporalRuntime(
        telemetry=TelemetryConfig(metrics=OpenTelemetryConfig(url=endpoint))
    )


async def temporal_connect(
    temporal_config: TemporalConfig,
):
    runtime = None
    if temporal_config.telemetry_endpoint:
        runtime = init_runtime_with_telemetry(temporal_config.telemetry_endpoint)

    extra_kw = {}
    if temporal_config.temporal_namespace is not None:
        extra_kw["namespace"] = temporal_config.temporal_namespace

    try:
        assert (
            temporal_config.temporal_tls_client_cert_path
        ), "missing tls_client_cert_path"
        assert (
            temporal_config.temporal_tls_client_key_path
        ), "missing tls_client_key_path"
        with open(temporal_config.temporal_tls_client_cert_path, "rb") as in_file:
            client_cert = in_file.read()
        with open(temporal_config.temporal_tls_client_key_path, "rb") as in_file:
            client_private_key = in_file.read()
        tls_config = TLSConfig(
            client_cert=client_cert,
            client_private_key=client_private_key,
        )
    except AssertionError:
        tls_config = None

    if tls_config is not None:
        extra_kw["tls"] = tls_config

    log.info(
        f"connecting to {temporal_config.temporal_address} with extra_kw={extra_kw.keys()}"
    )
    client = await TemporalClient.connect(
        temporal_config.temporal_address,
        interceptors=[TracingInterceptor()],
        runtime=runtime,
        **extra_kw,
    )
    return client


@dataclass
class WorkerParams:
    temporal_address: str
    temporal_namespace: Optional[str]
    temporal_tls_client_cert_path: Optional[str]
    temporal_tls_client_key_path: Optional[str]
    telemetry_endpoint: Optional[str]
    thread_count: int
    process_idx: int = 0


async def start_threaded_worker(params: WorkerParams):
    temporal_config = TemporalConfig(
        temporal_address=params.temporal_address,
        temporal_namespace=params.temporal_namespace,
        temporal_tls_client_cert_path=params.temporal_tls_client_cert_path,
        temporal_tls_client_key_path=params.temporal_tls_client_key_path,
        telemetry_endpoint=params.telemetry_endpoint,
    )
    client = await temporal_connect(temporal_config=temporal_config)
    worker = make_threaded_worker(client, parallelism=params.thread_count)
    await worker.run()


def run_worker(params: WorkerParams):
    try:
        asyncio.run(start_threaded_worker(params))
    except KeyboardInterrupt:
        print("shutting down")


def start_workers(params: WorkerParams, process_count: int):
    def signal_handler(signal, frame):
        print("shutdown requested: Ctrl+C detected")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    process_params = [
        dataclasses.replace(params, process_idx=idx) for idx in range(process_count)
    ]
    executor = ProcessPoolExecutor(max_workers=process_count)
    try:
        futures = [executor.submit(run_worker, param) for param in process_params]
        for future in as_completed(futures):
            future.result()
    except KeyboardInterrupt:
        print("ctrl+C detected, cancelling tasks...")
        for future in futures:
            future.cancel()
        executor.shutdown(wait=True)
        print("all tasks have been cancelled and cleaned up")
    except Exception as e:
        print(f"an error occurred: {e}")
        executor.shutdown(wait=False)
        raise


async def execute_workflow_with_workers(
    workflow: MethodAsyncSingleParam[SelfType, ParamType, ReturnType],
    arg: ParamType,
    parallelism,
    workflow_id_prefix: str,
    temporal_config: TemporalConfig,
):
    log.info(f"running workflow {workflow}")
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

    client = await temporal_connect(
        temporal_config=temporal_config,
    )
    async with make_threaded_worker(client, parallelism=parallelism):
        await client.execute_workflow(
            workflow,
            arg,
            id=f"{workflow_id_prefix}-{ts}",
            task_queue=TASK_QUEUE_NAME,
        )


async def execute_workflow(
    workflow: MethodAsyncSingleParam[SelfType, ParamType, ReturnType],
    arg: ParamType,
    workflow_id_prefix: str,
    temporal_config: TemporalConfig,
):
    log.info(f"running workflow {workflow}")
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

    client = await temporal_connect(
        temporal_config=temporal_config,
    )
    await client.execute_workflow(
        workflow,
        arg,
        id=f"{workflow_id_prefix}-{ts}",
        task_queue=TASK_QUEUE_NAME,
    )


async def execute_backfill(
    schedule_id: str,
    temporal_config: TemporalConfig,
    start_at: datetime,
    end_at: datetime,
):
    log.info(f"running backfill for schedule_id={schedule_id}")

    client = await temporal_connect(temporal_config=temporal_config)
    handle = client.get_schedule_handle(schedule_id)

    await handle.backfill(
        ScheduleBackfill(
            start_at=start_at + timedelta(hours=1),
            end_at=end_at + timedelta(hours=1),
            overlap=ScheduleOverlapPolicy.ALLOW_ALL,
        ),
    )


async def create_schedules(
    obs_params: Optional[ObservationsWorkflowParams],
    analysis_params: Optional[AnalysisWorkflowParams],
    temporal_config: TemporalConfig,
    delete: bool = False,
) -> dict:
    log.info(f"creating all schedules")

    client = await temporal_connect(temporal_config=temporal_config)

    obs_schedule_id = None
    if obs_params is not None:
        obs_schedule_id = await schedule_observations(
            client=client, params=obs_params, delete=delete
        )
        log.info(f"created schedule observations schedule with ID={obs_schedule_id}")

    analysis_schedule_id = None
    if analysis_params is not None:
        analysis_schedule_id = await schedule_analysis(
            client=client, params=analysis_params, delete=delete
        )
        log.info(f"created schedule analysis schedule with ID={analysis_schedule_id}")

    return {
        "analysis_schedule_id": analysis_schedule_id,
        "observations_schedule_id": obs_schedule_id,
    }


async def get_status(
    temporal_config: TemporalConfig,
) -> Tuple[List[WorkflowExecution], List[WorkflowExecution]]:

    client = await temporal_connect(temporal_config=temporal_config)
    active_observation_workflows = []
    async for workflow in client.list_workflows('WorkflowType="ObservationsWorkflow"'):
        if workflow.status == 1:
            active_observation_workflows.append(workflow)

    if len(active_observation_workflows) == 0:
        print("No active Observations workflows")
    else:
        print("Active observations workflows")
        for workflow in active_observation_workflows:
            print(f"workflow_id={workflow.id}")
            print(f"  run_id={workflow.run_id}")
            print(f"  execution_time={workflow.execution_time}")
            print(f"  execution_time={workflow.execution_time}")

    active_analysis_workflows = []
    async for workflow in client.list_workflows('WorkflowType="AnalysisWorkflow"'):
        if workflow.status == 1:
            active_analysis_workflows.append(workflow)

    if len(active_analysis_workflows) == 0:
        print("No active Analysis workflows")
    else:
        print("Active analysis workflows")
        for workflow in active_analysis_workflows:
            print(f"workflow_id={workflow.id}")
            print(f"  run_id={workflow.run_id}")
            print(f"  execution_time={workflow.execution_time}")
            print(f"  execution_time={workflow.execution_time}")
    return active_observation_workflows, active_observation_workflows


def run_workflow(
    workflow: MethodAsyncSingleParam[SelfType, ParamType, ReturnType],
    arg: ParamType,
    start_workers: bool,
    workflow_id_prefix: str,
    temporal_config: TemporalConfig,
    parallelism: Optional[int] = None,
):
    action = execute_workflow
    kw_args = {}
    if start_workers:
        print("starting also workers")
        action = execute_workflow_with_workers
        kw_args["parallelism"] = parallelism
    try:
        asyncio.run(
            action(
                workflow=workflow,
                arg=arg,
                workflow_id_prefix=workflow_id_prefix,
                temporal_config=temporal_config,
                **kw_args,
            )
        )
    except KeyboardInterrupt:
        print("shutting down")


def run_backfill(
    temporal_config: TemporalConfig,
    schedule_id: str,
    start_at: datetime,
    end_at: datetime,
):
    try:
        asyncio.run(
            execute_backfill(
                temporal_config=temporal_config,
                schedule_id=schedule_id,
                start_at=start_at,
                end_at=end_at,
            )
        )
    except KeyboardInterrupt:
        print("shutting down")


def run_create_schedules(
    obs_params: Optional[ObservationsWorkflowParams],
    analysis_params: Optional[AnalysisWorkflowParams],
    temporal_config: TemporalConfig,
    delete: bool,
):
    try:
        asyncio.run(
            create_schedules(
                obs_params=obs_params,
                analysis_params=analysis_params,
                temporal_config=temporal_config,
                delete=delete,
            )
        )
    except KeyboardInterrupt:
        print("shutting down")


def start_event_loop(async_task):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(async_task())


def run_status(
    temporal_config: TemporalConfig,
):
    try:
        asyncio.run(
            get_status(
                temporal_config=temporal_config,
            )
        )
    except KeyboardInterrupt:
        print("shutting down")
