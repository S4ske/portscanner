from dataclasses import dataclass
from typing import Literal
from datetime import timedelta

Protocol = Literal["TCP", "UDP"]
ApplicationProtocol = Literal["HTTP", "ECHO", "UNKNOWN"]


@dataclass
class PortInfo:
    port: int
    protocol: Protocol
    opened: bool
    response_time: timedelta | None = None
    application_protocol: ApplicationProtocol | None = None
