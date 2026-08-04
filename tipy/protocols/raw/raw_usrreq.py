from __future__ import annotations

from tipy.lib.errno import Errno, GaiError
from tipy.lib.ip_address import IPAddress, IPFormatError

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tipy.components.core import Core
    from tipy.protocols.raw.socket import RIPSocket


def raw_bind(*, self: Core, so: RIPSocket, address: tuple[str, int]):
    try:
        if str(IPAddress(address[0])) != str(self.unicast_ip):
            so.error = Errno.EADDRNOTAVAIL
    except IPFormatError:
        so.error = GaiError.EAI_NONAME

    so.raise_exception()

    so.local_ip = IPAddress(address[0])

    # NOTE: RIP sockets does not care about port number
    so.local_port = address[1]

    so.sock_id = (
        so.local_ip.ip_address, so.proto, so.remote_ip.ip_address
    )

    self.rip.register_socket(so.sock_id, so)

def raw_connect(*, self: Core, so: RIPSocket, address: tuple[str, int]):
    try:
        so.remote_ip = IPAddress(address[0])
    except IPFormatError:
        so.error = Errno.EADDRNOTAVAIL

    so.raise_exception()

    so.remote_port = address[1]

    if so.local_ip.ip_address == "0.0.0.0":
        # just select the configured IP
        so.local_ip = self.unicast_ip
        so.sock_id = (
            so.local_ip.ip_address, so.proto, so.remote_ip.ip_address
        )
        self.rip.register_socket(so.sock_id, so)
        return

    so.sock_id = (
        so.local_ip.ip_address, so.proto, so.remote_ip.ip_address
    )

    self.rip.update_socket(
        (so.local_ip.ip_address, so.proto, '0.0.0.0'),
        so.sock_id,
        so
    )

def raw_close(*, self: Core, so: RIPSocket):
    self.rip.remove_socket(so.sock_id)


def raw_send(*, self: Core, so: RIPSocket, data: bytes) -> int:

    # sins no support yet for sendto/recvfrom calls
    # check if the socket is connected type (we use connect call)
    if so.remote_ip.ip_address != '0.0.0.0':

        self.tx_raw(
            payload=data,
            protocol=so.proto,
            src=so.local_ip,
            dst=so.remote_ip
        )
        return len(data)

    so.error = Errno.EDESTADDRREQ
    so.raise_exception()
    return 0

def raw_recv(*, self: Core, so: RIPSocket, bufsize: int) -> bytes:
    with so.cond:
        got_packet = so.cond.wait(timeout=so.timeout)
        if not got_packet:
            so.error = Errno.ETIMEDOUT
            so.raise_exception()

        packet = so.queue.popleft()
        return bytes(packet[:bufsize])






