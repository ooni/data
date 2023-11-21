from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "OONI Data API"
    clickhouse_url: str = "clickhouse://localhost"


settings = Settings()
