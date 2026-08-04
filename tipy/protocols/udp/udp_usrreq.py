from __future__ import annotations

from tipy.lib.errno import Errno, GaiError
from tipy.lib.ip_address import IPAddress, IPFormatError

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tipy.components.core import Core
    from tipy.protocols.udp.socket import UDPSocket


def udp_bind(*, self: Core, so: UDPSocket, address: tuple[str, int]):
    try:
        if str(IPAddress(address[0])) != str(self.unicast_ip):
            so.error = Errno.EADDRNOTAVAIL
    except IPFormatError:
        so.error = GaiError.EAI_NONAME

    so.raise_exception()

    so.local_ip = IPAddress(address[0])

    if so.local_port in range(1, 65535):
        # Already bound, cannot bind again
        # this raise an exception when we call
        # bind call more than one time
        so.error = Errno.EINVAL
        so.raise_exception()

    so.local_port = address[1]

    if self.udp.check_bound((so.local_ip.ip_address,
                                   so.local_port)):
        so.error = Errno.EADDRINUSE
        so.raise_exception()

    so.sock_id = (
        so.local_ip.ip_address, so.local_port,
        so.remote_ip.ip_address, so.remote_port
    )
    self.udp.register_socket(so.sock_id, so)
    self.udp.register_bound_socket((so.local_ip.ip_address,
                                          so.local_port))


def udp_connect(*, self: Core, so: UDPSocket, address: tuple[str, int]):
    # Connect call in udp socket type
    # is used when you want to send data
    # using only the 'send' call, because
    # 'send' call does not accept remote port/ip args
    so.remote_ip = IPAddress(address[0])
    so.remote_port = address[1]

    if not so.local_port:
        so.local_port = self.udp.pick_ephemeral_udp_port()
        # TODO : MUST SELECT IP BASED ON THE DST IP SELECTED FROM CONNECT
        # now just select the configured IP
        so.local_ip = self.unicast_ip

        so.sock_id = (
            so.local_ip.ip_address, so.local_port,
            so.remote_ip.ip_address, so.remote_port
        )

        self.udp.register_socket(so.sock_id, so)
        return

    so.sock_id = (
        so.local_ip.ip_address, so.local_port,
        so.remote_ip.ip_address, so.remote_port
    )

    self.udp.update_socket(
        (so.local_ip.ip_address, so.local_port, '0.0.0.0', 0 ),
        so.sock_id,
        so
    )


def udp_close(*, self: Core, so: UDPSocket):
    self.udp.remove_socket((
        so.local_ip, so.local_port,
        so.remote_ip, so.remote_port
    ))


def udp_send(*, self: Core, so: UDPSocket, data: bytes):

    # sins no support yet for sendto/recvfrom calls
    # check if the socket is connected type (we use connect call)
    if so.remote_ip.ip_address != '0.0.0.0' and so.remote_port:
        # check if there is an icmp err msg
        if so.sock_id in self.udp.err_msg:
            so.error = self.udp.err_msg[so.sock_id]
            so.raise_exception()

        self.tx_udp(
            local_ip=so.local_ip,
            remote_ip=so.remote_ip,
            local_port=so.local_port,
            remote_port=so.remote_port,
            sock_opt=so.sock_opt,
            data=data
        )
        return

    so.error = Errno.EDESTADDRREQ
    so.raise_exception()

def udp_recv(*, self: Core, so: UDPSocket, bufsize: int):
    with so.cond:
        got_packet = so.cond.wait(timeout=so.timeout)
        if not got_packet:
            so.error = Errno.ETIMEDOUT
            so.raise_exception()

        packet = so.queue.popleft()
        return bytes(packet[:bufsize])






