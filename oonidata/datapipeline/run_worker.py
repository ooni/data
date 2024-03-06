import asyncio

import concurrent.futures

from temporalio.client import Client
from temporalio.worker import Worker

from .workflows.observations import ObservationsWorkflow
from .workflows.observations import make_observation_in_day


async def async_main():
    client = await Client.connect("localhost:7233")
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as activity_executor:
        worker = Worker(
            client,
            task_queue="oonidatapipeline-task-queue",
            workflows=[ObservationsWorkflow],
            activities=[make_observation_in_day],
            activity_executor=activity_executor,
        )

        await worker.run()


def main():
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
