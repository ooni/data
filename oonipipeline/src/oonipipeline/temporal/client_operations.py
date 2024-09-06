import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Tuple

from oonipipeline.temporal.schedules import (
    ScheduleIdMap,
    schedule_all,
    schedule_backfill,
)

from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry import trace

from temporalio.client import (
    Client as TemporalClient,
    WorkflowExecution,
)
from temporalio.service import TLSConfig
from temporalio.contrib.opentelemetry import TracingInterceptor
from temporalio.runtime import (
    OpenTelemetryConfig,
    Runtime as TemporalRuntime,
    TelemetryConfig,
    PrometheusConfig,
)

log = logging.getLogger("oonidata.client_operations")


@dataclass
class TemporalConfig:
    temporal_address: str = "localhost:7233"
    telemetry_endpoint: Optional[str] = None
    prometheus_bind_address: Optional[str] = None
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


def init_runtime_with_prometheus(bind_address: str) -> TemporalRuntime:
    # Create runtime for use with Prometheus metrics
    return TemporalRuntime(
        telemetry=TelemetryConfig(metrics=PrometheusConfig(bind_address=bind_address))
    )


async def temporal_connect(
    temporal_config: TemporalConfig,
):
    runtime = None
    if temporal_config.prometheus_bind_address and temporal_config.telemetry_endpoint:
        raise RuntimeError("cannot use both prometheus and otel")

    if temporal_config.prometheus_bind_address:
        runtime = init_runtime_with_prometheus(temporal_config.prometheus_bind_address)
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


async def execute_backfill(
    probe_cc: List[str],
    test_name: List[str],
    start_at: datetime,
    end_at: datetime,
    workflow_name: str,
    temporal_config: TemporalConfig,
):
    log.info(f"creating all schedules")

    client = await temporal_connect(temporal_config=temporal_config)

    return await schedule_backfill(
        client=client,
        probe_cc=probe_cc,
        test_name=test_name,
        start_at=start_at,
        end_at=end_at,
        workflow_name=workflow_name,
    )


async def create_schedules(
    probe_cc: List[str],
    test_name: List[str],
    clickhouse_url: str,
    data_dir: str,
    temporal_config: TemporalConfig,
) -> ScheduleIdMap:
    log.info(f"creating all schedules")

    client = await temporal_connect(temporal_config=temporal_config)

    return await schedule_all(
        client=client,
        probe_cc=probe_cc,
        test_name=test_name,
        clickhouse_url=clickhouse_url,
        data_dir=data_dir,
    )


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


def run_backfill(
    temporal_config: TemporalConfig,
    probe_cc: List[str],
    test_name: List[str],
    workflow_name: str,
    start_at: datetime,
    end_at: datetime,
):
    try:
        asyncio.run(
            execute_backfill(
                temporal_config=temporal_config,
                workflow_name=workflow_name,
                probe_cc=probe_cc,
                test_name=test_name,
                start_at=start_at,
                end_at=end_at,
            )
        )
    except KeyboardInterrupt:
        print("shutting down")


def run_create_schedules(
    probe_cc: List[str],
    test_name: List[str],
    clickhouse_url: str,
    data_dir: str,
    temporal_config: TemporalConfig,
):
    try:
        asyncio.run(
            create_schedules(
                probe_cc=probe_cc,
                test_name=test_name,
                clickhouse_url=clickhouse_url,
                data_dir=data_dir,
                temporal_config=temporal_config,
            )
        )
    except KeyboardInterrupt:
        print("shutting down")


def run_reschedule(
    probe_cc: List[str],
    test_name: List[str],
    clickhouse_url: str,
    data_dir: str,
    temporal_config: TemporalConfig,
):
    try:
        asyncio.run(
            create_schedules(
                probe_cc=probe_cc,
                test_name=test_name,
                clickhouse_url=clickhouse_url,
                data_dir=data_dir,
                temporal_config=temporal_config,
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
