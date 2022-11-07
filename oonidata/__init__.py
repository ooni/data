try:
    import importlib.metadata as importlib_metadata
except ModuleNotFoundError:
    import importlib_metadata  # type: ignore it's only for py <=3.8

__version__ = importlib_metadata.version(__name__)
