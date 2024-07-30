import asyncio
import signal
import sys
import logging
import dataclasses
from dataclasses import dataclass
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Optional

from oonipipeline.temporal.workers import make_threaded_worker
from oonipipeline.temporal.workflows import TASK_QUEUE_NAME

from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry import trace

from temporalio.client import Client as TemporalClient
from temporalio.contrib.opentelemetry import TracingInterceptor
from temporalio.runtime import (
    OpenTelemetryConfig,
    Runtime as TemporalRuntime,
    TelemetryConfig,
)
from temporalio.types import MethodAsyncSingleParam, SelfType, ParamType, ReturnType

log = logging.getLogger("oonidata.client_operations")


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


async def temporal_connect(telemetry_endpoint: Optional[str], temporal_address: str):
    runtime = None
    if telemetry_endpoint:
        runtime = init_runtime_with_telemetry(telemetry_endpoint)
    client = await TemporalClient.connect(
        temporal_address,
        interceptors=[TracingInterceptor()],
        runtime=runtime,
    )
    return client


@dataclass
class WorkerParams:
    temporal_address: str
    telemetry_endpoint: Optional[str]
    thread_count: int
    process_idx: int = 0


async def start_threaded_worker(params: WorkerParams):
    client = await temporal_connect(
        telemetry_endpoint=params.telemetry_endpoint,
        temporal_address=params.temporal_address,
    )
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
    telemetry_endpoint: Optional[str],
    temporal_address: str,
):
    log.info(
        f"running workflow {workflow} temporal_address={temporal_address} telemetry_address={telemetry_endpoint} parallelism={parallelism}"
    )
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    client = await temporal_connect(
        telemetry_endpoint=telemetry_endpoint, temporal_address=temporal_address
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
    parallelism,
    workflow_id_prefix: str,
    telemetry_endpoint: Optional[str],
    temporal_address: str,
):
    log.info(
        f"running workflow {workflow} temporal_address={temporal_address} telemetry_address={telemetry_endpoint} parallelism={parallelism}"
    )
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    client = await temporal_connect(
        telemetry_endpoint=telemetry_endpoint, temporal_address=temporal_address
    )
    await client.execute_workflow(
        workflow,
        arg,
        id=f"{workflow_id_prefix}-{ts}",
        task_queue=TASK_QUEUE_NAME,
    )


def run_workflow(
    workflow: MethodAsyncSingleParam[SelfType, ParamType, ReturnType],
    arg: ParamType,
    parallelism,
    start_workers: bool,
    workflow_id_prefix: str,
    telemetry_endpoint: Optional[str],
    temporal_address: str,
):
    action = execute_workflow
    if start_workers:
        print("starting also workers")
        action = execute_workflow_with_workers
    try:
        asyncio.run(
            action(
                workflow=workflow,
                arg=arg,
                parallelism=parallelism,
                workflow_id_prefix=workflow_id_prefix,
                telemetry_endpoint=telemetry_endpoint,
                temporal_address=temporal_address,
            )
        )
    except KeyboardInterrupt:
        print("shutting down")
