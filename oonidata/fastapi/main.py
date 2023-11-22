from fastapi import FastAPI

from .routers import aggregation, measurements
from .config import settings

import logging

logging.basicConfig(level=getattr(logging, settings.log_level.upper()))

app = FastAPI()
app.include_router(aggregation.router, prefix="/api/v1")
app.include_router(measurements.router, prefix="/api/v1")


@app.get("/")
async def root():
    return {"message": "Hello OONItarian!"}
