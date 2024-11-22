from utils import ApplicationProtocol


def guess_application_protocol(request: bytes, response: bytes) -> ApplicationProtocol:
    if response.startswith(b"HTTP"):
        return "HTTP"
    if response == request:
        return "ECHO"

    return "UNKNOWN"
