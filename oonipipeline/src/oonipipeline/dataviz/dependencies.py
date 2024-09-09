from functools import lru_cache
from typing import Annotated

from fastapi import Depends
from clickhouse_driver import Client as Clickhouse

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    clickhouse_url: str = "clickhouse://localhost"
    data_dir: str = "tests/data/datadir"


@lru_cache
def get_settings() -> Settings:
    return Settings()


def get_clickhouse_session(settings: Annotated[Settings, Depends(get_settings)]):
    db = Clickhouse.from_url(settings.clickhouse_url)
    try:
        yield db
    finally:
        db.disconnect()
