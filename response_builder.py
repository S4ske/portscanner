from utils import PortInfo, Protocol, ApplicationProtocol
from datetime import timedelta


class ResponseBuilder:
    def __init__(self) -> None:
        self._response: list[str] = []

    def build_response(self, port_info: PortInfo) -> str:
        if not port_info.opened:
            raise ValueError()
        self._add_protocol(port_info.protocol)
        self._add_port(port_info.port)
        if port_info.response_time is not None:
            self._add_response_time(port_info.response_time)
        if port_info.application_protocol:
            self._add_application_protocol(port_info.application_protocol)
        result = " ".join(self._response)
        self._response = []
        return result

    def _add_protocol(self, protocol: Protocol) -> None:
        self._response.append(protocol)

    def _add_port(self, port: int) -> None:
        self._response.append(str(port))

    def _add_response_time(self, time: timedelta) -> None:
        self._response.append(str(int(time.total_seconds() * 1000)))

    def _add_application_protocol(
        self, application_protocol: ApplicationProtocol
    ) -> None:
        self._response.append(application_protocol)
