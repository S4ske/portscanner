from typing import Iterable, Generator
from utils import Protocol, PortInfo
import socket
from datetime import datetime
from protocol_guesser import guess_application_protocol
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.layers.inet import IP, TCP, sr1


class PortScanner:
    def __init__(
            self,
            timeout: float = 2,
            verbose: bool = False,
            guess: bool = False,
            workers_count: int = 100
    ) -> None:
        self._timeout = timeout
        self._verbose = verbose
        self._guess = guess
        self._workers_count = workers_count

    def scan(
            self, ip_addr: str, ports_range: list[tuple[Protocol, Iterable[int]]]
    ) -> Generator[PortInfo | str, None, None]:
        for protocol, ports in ports_range:
            with ThreadPoolExecutor(self._workers_count) as executor:
                futures = [executor.submit(self.scan_port, ip_addr, protocol, port) for port in ports]

                for future in as_completed(futures):
                    port_info = future.result()
                    if not port_info.opened:
                        continue

                    yield port_info

    def scan_port(self, ip_addr: str, protocol: Protocol, port: int) -> PortInfo:
        if protocol == "TCP":
            if self._guess:
                return self._scan_tcp(ip_addr, port)
            return self._scapy_scan_tcp(ip_addr, port)
        return self._scan_udp(ip_addr, port)

    def _scan_udp(self, ip_addr: str, port: int) -> PortInfo:
        with socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM,
        ) as sock:
            sock.settimeout(self._timeout)

            try:
                request = b"ping"
                start_time = datetime.now()
                sock.sendto(request, (ip_addr, port))
                response, _ = sock.recvfrom(1024)
                response_time = (datetime.now() - start_time) if self._verbose else None
                application_protocol = guess_application_protocol(b"ping", response) if self._guess else None
                return PortInfo(
                    port=port,
                    protocol="UDP",
                    opened=True,
                    response_time=response_time,
                    application_protocol=application_protocol,
                )
            except socket.timeout:
                return PortInfo(port=port, protocol="UDP", opened=False)

    def _scapy_scan_tcp(self, ip_addr: str, port: int) -> PortInfo:
        syn = IP(dst=ip_addr) / TCP(dport=port, flags="S", seq=1000)
        start_time = datetime.now()
        response = sr1(syn, timeout=self._timeout, verbose=0)
        response_time = datetime.now() - start_time if self._verbose else None

        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            return PortInfo(port=port, opened=True, protocol="TCP", response_time=response_time)
        return PortInfo(port=port, opened=False, protocol="TCP")

    def _scan_tcp(self, ip_addr: str, port: int) -> PortInfo:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self._timeout)
            try:
                connected = sock.connect_ex((ip_addr, port))
                start_time = datetime.now()
                sock.send(b"ping")
                response = sock.recv(1024)
                response_time = datetime.now() - start_time
                return PortInfo(port=port, opened=True, protocol="TCP", response_time=response_time,
                                application_protocol=guess_application_protocol(b"ping", response))
            except socket.timeout:
                return PortInfo(port=port, opened=connected == 0, protocol="TCP")
