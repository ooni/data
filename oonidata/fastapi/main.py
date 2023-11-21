from fastapi import FastAPI

from oonidata.fastapi.routers import aggregation, measurements

app = FastAPI()
app.include_router(aggregation.router, prefix="/api/v1")
app.include_router(measurements.router, prefix="/api/v1")


@app.get("/")
async def root():
    return {"message": "Hello OONItarian!"}
