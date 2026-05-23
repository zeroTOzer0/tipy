from __future__ import annotations

from typing import TYPE_CHECKING, Optional
if TYPE_CHECKING:
    from tipy.protocols.icmp.socket import ICMPSocket
    from tipy.protocols.udp.socket import UDPSocket
    from tipy.protocols.tcp.socket import TCPSocket
    from tipy.protocols.tcp.tcpcb import TCPCB
    from tipy.lib.packet import PacketRX
    from tipy.lib.socket_errors import (
        ConnectionRefusedError
    )

from tipy.config.config import EPHEMERAL_PORTS

class UDPTable:
    def __init__(self):
        # Tuple format: (local_ip, local_port, remote_ip, remote_port)
        self.sockets: dict[tuple, UDPSocket] = dict()

        self.bound_sockets: set[tuple[str, int]] = set()
        # when an icmp message received
        self.err_msg: dict[tuple[str, int, str, int],ConnectionRefusedError
                                                     | OSError] = dict()

        self.ephemeral_ports: set[int] = set(EPHEMERAL_PORTS)

        self.used_ports: set[int] = set()

    def register_socket(self, sock_id: tuple, socket: UDPSocket):
        self.sockets[sock_id] = socket

    def update_socket(self, old: tuple, new: tuple, socket: UDPSocket):
        self.remove_socket(old)
        self.register_socket(new, socket)

    def remove_socket(self, sock_id: tuple):
        self.sockets.pop(sock_id, None)

    def register_bound_socket(self, bnd_sock: tuple[str, int]):
        self.bound_sockets.add(bnd_sock)


    def __add_used_port(self, port: int):
        if port not in self.ephemeral_ports:
            self.used_ports.add(port)

    def pick_ephemeral_udp_port(self):
        picked_port = self.ephemeral_ports.pop()
        self.__add_used_port(picked_port)
        return picked_port

    def check_bound(self, bnd_sock: tuple[str, int]):
        return bnd_sock in self.bound_sockets

    def remove_socket(self,
                          sock_id: tuple[str, int, str, int]):
        self.sockets.pop(sock_id, None)


class TCPTable:
    def __init__(self):
        # Tuple format: (local_ip, local_port, remote_ip, remote_port)
        self.sockets: dict[tuple, TCPSocket] = dict()
        self.tcpcbs: dict[tuple, TCPCB] = dict()

        # Set of TCP control blocks that are still valid.
        # Used to ensure events run only on non-destroyed tcpcb objects.
        self.active_tcpcbs: set[TCPCB] = set()

        self.bound_sockets: set[tuple[str, int]] = set()

        self.ephemeral_ports: set[int] = set(EPHEMERAL_PORTS)

        self.used_ports: set[int] = set()


    def register_socket(self, sock_id: tuple, socket: TCPSocket):
        self.sockets[sock_id] = socket

    def update_socket(self, old: tuple, new: tuple, socket: TCPSocket):
        self.remove_socket(old)
        self.register_socket(new, socket)

    def remove_socket(self, sock_id: tuple):
        self.sockets.pop(sock_id, None)

    def register_bound_socket(self, bnd_sock: tuple[str, int]):
        self.bound_sockets.add(bnd_sock)


    def __add_used_port(self, port: int):
        if port not in self.ephemeral_ports:
            self.used_ports.add(port)

    def pick_ephemeral_tcp_port(self):
        picked_port = self.ephemeral_ports.pop()
        self.__add_used_port(picked_port)
        return picked_port

    def check_bound(self, bnd_sock: tuple[str, int]):
        return bnd_sock in self.bound_sockets

    def register_tcpcb(self, sock_id: tuple, tcpcb: TCPCB):
        self.tcpcbs[sock_id] = tcpcb
        self.active_tcpcbs.add(tcpcb)

    def remove_tcpcb(self, sock_id: tuple, tcpcb: TCPCB):
        self.tcpcbs.pop(sock_id, None)
        self.active_tcpcbs.remove(tcpcb)


class RAWV4Table:
    """ table for : AF_INET/SOCK_RAW sockets """
    # NOTE: Current socket identification is wrong for RAW sockets.
    def __init__(self):
        # Tuple format: (local ip, protocol_number, id|None)
        self.sockets: dict[tuple[str, int, int | None], ICMPSocket] = dict()

    def register_socket(self,
                        sock_id: tuple[str, int, int | None],
                        socket: ICMPSocket):
        self.sockets[sock_id] = socket

    def remove_socket(self,
                    sock_id: tuple[str, int, int | None]):

        self.sockets.pop(sock_id, None)

    def remove_socket(self,
                      sock_id: tuple[str, int, int | None]):
        self.sockets.pop(sock_id, None)
