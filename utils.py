from dataclasses import dataclass
from typing import Literal
from datetime import timedelta
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
logger = logging.getLogger(__name__)

Protocol = Literal["TCP", "UDP"]
ApplicationProtocol = Literal["HTTP", "DNS", "ECHO", "UNKNOWN"]


@dataclass
class PortInfo:
    port: int
    protocol: Protocol
    opened: bool
    response_time: timedelta | None = None
    application_protocol: ApplicationProtocol | None = None
