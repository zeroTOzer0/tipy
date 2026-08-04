from tipy.lib.ip_address import IPAddress
from tipy.lib.logger import log
from tipy.lib import stack

from tipy.lib.socket import (
Socket,
AF_INET,
SOCK_DGRAM
)
from tipy.lib.errno import Errno, so_error
from threading import Condition
from collections import deque

from tipy.protocols.udp.udp_usrreq import (
    udp_bind, udp_connect, udp_send, udp_recv, udp_close
)

class UDPSocket(Socket):
    def __init__(self, family: int, type_: int, proto: int):
        super().__init__()
        self.local_ip: IPAddress = IPAddress('0.0.0.0')
        self.remote_ip: IPAddress = IPAddress('0.0.0.0')
        self.local_port: int = 0
        self.remote_port: int = 0

        self.family = family
        self.type = SOCK_DGRAM
        self.proto = proto

        self.cond: Condition = Condition()
        self.queue: deque[memoryview] = deque()

        self.timeout: int | None = None

        self.sock_id: tuple = (
            self.local_ip.ip_address, self.local_port,
            self.remote_ip.ip_address, self.remote_port
        )

    def bind(self, address: tuple[str, int]):
        udp_bind(self=stack.core, so=self, address=address)

        if __debug__:
            log(
                "socket",
                f"{self} bound to {self.local_ip}:{self.local_port}",
                level="INFO"
            )

    def listen(self, backlog: int):
        self.error = Errno.EOPNOTSUPP
        self.raise_exception()


    def connect(self, address: tuple[str, int]):
        # Connect call in udp socket type
        # is used when you want to send data
        # using only the 'send' call, because
        # 'send' call does not accept remote port/ip args
        udp_connect(self=stack.core, so=self, address=address)

        if __debug__:
            log(
                "socket",
                f"{self} connected to {self.remote_ip}:{self.remote_port}",
                level="INFO"
            )

    def close(self):
        udp_close(self=stack.core, so=self)
        if __debug__:
            log(
                "socket",
                f"{self} socket closed",
                level="INFO"
            )


    def send(self, data: bytes):
        udp_send(self=stack.core, so=self, data=data)
        if __debug__:
            log(
                "socket",
                f"{self} {self.local_ip}:{self.local_port} -> {self.remote_ip}:{self.remote_port} "
                f"sent {len(data)}B",
                level="INFO"
            )

    def recv(self, bufsize: int):
        data = udp_recv(self=stack.core, so=self, bufsize=bufsize)

        if __debug__:
            log(
                "socket",
                f"{self} {self.local_ip}:{self.local_port} -> {self.remote_ip}:{self.remote_port} "
                f"recv {len(data)}B, read {len(data[:bufsize])}B",
                level="INFO"
            )

        return bytes(data)

    def settimeout(self, t: int):
        self.timeout = t

    def shutdown(self):
        ...


    def get_data(self, packet: memoryview):
        self.queue.append(packet)
        with self.cond:
            self.cond.notify()

    def raise_exception(self):
        so_error[self.error](self)

