from typer import Typer, Option, Argument, echo
from typing import Iterable
from portscanner import PortScanner
from utils import Protocol

app = Typer()


def parse_ports(
    protocols_ranges: list[str] | None,
) -> list[tuple[Protocol, Iterable[int]]]:
    if protocols_ranges is None:
        return [("TCP", range(65536)), ("UDP", range(65536))]

    protocols_ports = []

    for protocol_range in protocols_ranges:
        if "/" not in protocol_range:
            protocol = protocol_range
            if protocol not in ["udp", "tcp"]:
                raise ValueError()
            protocols_ports.append((protocol.upper(), range(65536)))
            continue

        protocol, ports_ranges = protocol_range.split("/")

        if protocol not in ["udp", "tcp"]:
            raise ValueError()

        for ports_range in ports_ranges.split(","):
            if "-" not in ports_range:
                protocols_ports.append(
                    (protocol.upper(), range(int(ports_range), int(ports_range) + 1))
                )
                continue
            left_port, right_port = ports_range.split("-")
            protocols_ports.append(
                (protocol.upper(), range(int(left_port), int(right_port) + 1))
            )

    return protocols_ports


@app.command()
def portscan(
    ip_address: str = Argument(help="Ip адрес, который необходимо просканировать"),
    scan_targets: list[str] = Argument(
        None, help="Протоколы и порты для сканирования, например, tcp/80 или udp/53-100"
    ),
    timeout: int = Option(2, "--timeout"),
    verbose: bool = Option(False, "--verbose", "-v", help="Включить подробный вывод"),
    guess: bool = Option(
        False, "--guess", "-g", help="Включить определение прикладного протокола"
    ),
) -> None:
    """
    Утилита для сканирования портов на заданном IP-адресе.
    """

    echo(f"Сканирование IP-адреса: {ip_address}")

    port_scanner = PortScanner(timeout, verbose, guess, True)

    for response_string in port_scanner.scan(ip_address, parse_ports(scan_targets)):
        echo(response_string)


if __name__ == "__main__":
    portscan("127123", ["tcp/80", "tcp/12000-12500", "udp/3000-3100,3200,3300-4000"])
