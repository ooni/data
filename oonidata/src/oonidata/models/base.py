from dataclasses import dataclass
from typing import Tuple
from mashumaro import DataClassDictMixin
from mashumaro.config import BaseConfig, TO_DICT_ADD_OMIT_NONE_FLAG


class BaseModel(DataClassDictMixin):
    class Config(BaseConfig):
        # This makes it possible to call .to_dict(omit_none=True) to remove any
        # attributes of the dataclass that a None, saving up quite a bit of
        # space for unnecessary keys
        code_generation_options = [TO_DICT_ADD_OMIT_NONE_FLAG]

@dataclass
class BaseTableModel:
    __table_name__ : str
    __table_index__ : Tuple[str, ...]
    def __init_subclass__(cls, /, table_name : str, table_index : Tuple[str, ...], **kwargs):
        super().__init_subclass__(**kwargs)
        cls.__table_name__ = table_name
        cls.__table_index__ = table_index