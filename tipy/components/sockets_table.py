from __future__ import annotations

from typing import TYPE_CHECKING

from tipy.protocols.raw.socket import RIPSocket

if TYPE_CHECKING:
    from tipy.protocols.udp.socket import UDPSocket
    from tipy.protocols.tcp.socket import TCPSocket
    from tipy.protocols.tcp.tcpcb import TCPCB
    from tipy.lib.errno import Errno


from tipy.config.config import EPHEMERAL_PORTS

class UDPTable:
    def __init__(self):
        # Tuple format: (local_ip, local_port, remote_ip, remote_port)
        self.sockets: dict[tuple, UDPSocket] = dict()
        self.bound_sockets: set[tuple[str, int]] = set()
        # when an icmp message received
        self.err_msg: dict[tuple[str, int, str, int], Errno] = dict()
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

    def remove_tcpcb(self, sock_id: tuple, tcpcb: TCPCB):
        self.tcpcbs.pop(sock_id, None)

class RIPTable:
    """ table for : raw_ip (AF_INET/SOCK_RAW sockets) """
    def __init__(self):
        # Tuple format: (local ip, protocol_number, remote ip)
        self.sockets: dict[tuple[str, int, str], RIPSocket] = dict()

    def register_socket(self,
                        sock_id: tuple[str, int, str],
                        socket: RIPSocket):
        self.sockets[sock_id] = socket

    def remove_socket(self,
                    sock_id: tuple[str, int, str]):

        self.sockets.pop(sock_id, None)

    def update_socket(self, old: tuple[str, int, str],
                      new: tuple[str, int, str],
                      socket: RIPSocket):
        self.remove_socket(old)
        self.register_socket(new, socket)
