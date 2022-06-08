from typing import Generator, List
from oonidata.observations import Observation
from oonidata.dataformat import WebConnectivity, load_measurement


class BaseMeasurementProcessor:
    def __init__(self, raw: bytes):
        self.measurement = load_measurement(raw)

    def transform(self) -> None:
        pass

    def gen_observations(self) -> Generator[Observation]:
        pass


class WebConnectivityProcessor(BaseMeasurementProcessor):
    measurement: WebConnectivity

    def transform(self):
        self.measurement


nettest_processors = {"web_connectivity": WebConnectivityProcessor}
