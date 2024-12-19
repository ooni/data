import os
from typing import Optional, Tuple, Type
from pydantic import Field

from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict()

    data_dir: str = "tests/data/datadir"

    clickhouse_url: str = "clickhouse://localhost"
    clickhouse_write_batch_size: int = 200_000

    telemetry_endpoint: Optional[str] = None
    prometheus_bind_address: Optional[str] = None

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: Type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> Tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            TomlConfigSettingsSource(
                settings_cls, toml_file=os.environ.get("CONFIG_FILE", "")
            ),
        )


config = Settings()
