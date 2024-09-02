from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routers import aggregate_analysis, list_analysis, aggregate_observations
from .config import settings

import logging

logging.basicConfig(level=getattr(logging, settings.log_level.upper()))

app = FastAPI()
origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(aggregate_analysis.router, prefix="/api/v1")
app.include_router(list_analysis.router, prefix="/api/v1")
app.include_router(aggregate_observations.router, prefix="/api/v2")


@app.get("/")
async def root():
    return {"message": "Hello OONItarian!"}
