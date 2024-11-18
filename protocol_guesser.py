from utils import ApplicationProtocol


def guess_protocol(request: bytes, response: bytes) -> ApplicationProtocol:
    if response.startswith(b"HTTP/"):
        return "HTTP"

    if response == request:
        return "ECHO"

    if (
        len(response) >= 4
        and response[:2] == request[:2]
        and (response[2:4] != b"\x00\x00")
    ):
        return "DNS"

    return "UNKNOWN"
