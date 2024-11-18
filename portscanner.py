from typing import Iterable, Generator
from response_builder import ResponseBuilder
from utils import Protocol, PortInfo, logger
import socket
from datetime import datetime
from protocol_guesser import guess_protocol
from struct import pack


class PortScanner:
    def __init__(
        self,
        timeout: float = 2,
        verbose: bool = False,
        guess: bool = False,
        formatted: bool = True,
    ) -> None:
        self._timeout = timeout
        self._verbose = verbose
        self._guess = guess
        self._formatted = formatted
        self._response_builder = ResponseBuilder() if formatted else None

    def scan(
        self, ip_addr: str, ports_range: list[tuple[Protocol, Iterable[int]]]
    ) -> Generator[PortInfo | str, None, None]:
        logger.info(f"Start scanning {ip_addr}")
        for protocol, ports in ports_range:
            for port in ports:
                port_info = self.check_port(ip_addr, protocol, port)
                logger.info(f"{ip_addr} {port}: opened = {port_info.opened}, "
                            f"application_protocol = {port_info.application_protocol}, "
                            f"response_time = {port_info.response_time}, protocol = {port_info.protocol}")
                if not port_info.opened:
                    continue
                yield (
                    self._response_builder.build_response(port_info)
                    if self._formatted
                    else port_info
                )

    def check_port(self, ip_addr: str, protocol: Protocol, port: int) -> PortInfo:
        if protocol == "TCP" and not self._guess:
            return self._just_check_tcp(ip_addr, port)

        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM if protocol == "TCP" else socket.SOCK_DGRAM,
        ) as sock:
            sock.settimeout(self._timeout)

            start_time = datetime.now()
            try:
                request = b"ping"
                sock.sendto(request, (ip_addr, port))
                response, _ = sock.recvfrom(1024)
                response_time = (datetime.now() - start_time) if self._verbose else None
                application_protocol = (
                    guess_protocol(request, response) if self._guess else None
                )
                return PortInfo(
                    port=port,
                    protocol=protocol,
                    opened=True,
                    response_time=response_time,
                    application_protocol=application_protocol,
                )
            except socket.timeout:
                return PortInfo(port=port, protocol=protocol, opened=False)
            except socket.error:
                return PortInfo(port=port, protocol=protocol, opened=False)

    def _just_check_tcp(self, ip_addr: str, port: int) -> PortInfo:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as sock:
            sock.settimeout(self._timeout)

            tcp_header = pack("!HHIIBBHHH", port, port, 0, 0, 5 << 4, 2, 1024, 0, 0)

            start_time = datetime.now()
            try:
                sock.sendto(tcp_header, (ip_addr, port))
                response, _ = sock.recvfrom(1024)
                response_time = (datetime.now() - start_time) if self._verbose else None

                return PortInfo(
                    port=port,
                    protocol="TCP",
                    opened=True,
                    response_time=response_time,
                )
            except socket.timeout:
                return PortInfo(port=port, protocol="TCP", opened=False)
