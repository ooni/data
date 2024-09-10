from datetime import datetime
from dataclasses import dataclass
from typing import Annotated, Any, List, Optional, Tuple
from mashumaro import DataClassDictMixin
from mashumaro.config import BaseConfig, TO_DICT_ADD_OMIT_NONE_FLAG
from typing import Protocol, runtime_checkable


class BaseModel(DataClassDictMixin):
    class Config(BaseConfig):
        # This makes it possible to call .to_dict(omit_none=True) to remove any
        # attributes of the dataclass that a None, saving up quite a bit of
        # space for unnecessary keys
        code_generation_options = [TO_DICT_ADD_OMIT_NONE_FLAG]


def table_model(table_name: str, table_index: Tuple[str, ...]):
    def decorator(cls):
        cls.__table_name__ = table_name
        cls.__table_index__ = table_index
        return cls

    return decorator


@runtime_checkable
@dataclass
class TableModelProtocol(Protocol):
    __table_name__: str
    __table_index__: Tuple[str, ...]

    probe_meta: Any
    measurement_meta: Any


@dataclass
class ProcessingMeta:
    created_at: datetime


UInt8 = Annotated[int, "UInt8"]
UInt16 = Annotated[int, "UInt16"]
UInt32 = Annotated[int, "UInt32"]

Float64 = Annotated[float, "Float64"]

ArrayString = Annotated[List[str], "Array(String)"]

OptionalDatetime64_3 = Annotated[Optional[datetime], "Nullable(DateTime64(3, 'UTC'))"]
OptionalDatetime = Annotated[Optional[datetime], "Nullable(DateTime('UTC'))"]
