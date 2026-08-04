from tipy.lib.errno import Errno, so_error
from tipy.lib.ip_address import IPAddress
from tipy.lib.logger import log
from tipy.lib import stack

from tipy.lib.socket import Socket
from threading import Condition
from collections import deque

from tipy.protocols.raw.raw_usrreq import (
raw_bind, raw_connect, raw_send, raw_recv, raw_close
)


class RIPSocket(Socket):
    def __init__(self, family: int, type_: int, proto: int):
        super().__init__()
        self.local_ip: IPAddress = IPAddress('0.0.0.0')
        self.remote_ip: IPAddress = IPAddress('0.0.0.0')
        self.local_port: int = 0
        self.remote_port: int = 0

        self.family = family
        self.type = type_
        self.proto: int = proto

        self.cond: Condition = Condition()
        self.queue: deque[memoryview] = deque()

        self.timeout: int | None = None

        self.sock_id: tuple[str, int, str] = (
            self.local_ip.ip_address, self.proto, self.remote_ip.ip_address
        )

    def __str__(self):
        return f"{self.family}/{self.type}/{self.proto}"

    def bind(self, address: tuple[str, int]):
        raw_bind(self=stack.core, so=self, address=address)

        if __debug__: log(
            'socket',
            f'{self} bound to {self.local_ip}',
            level='INFO'
        )

    def listen(self, backlog: int):
        pass

    def connect(self, address: tuple[str, int]):
        raw_connect(self=stack.core, so=self, address=address)
        if __debug__: log(
            "socket",
            f"{self} connect to {self.remote_ip}",
            level="INFO"
        )

    def send(self, data: bytes):
        bytes_sent = raw_send(self=stack.core, so=self, data=data)

        if __debug__:
            log(
                "socket",
                f"{self}: {self.local_ip} -> {self.remote_ip} "
                f"sent {bytes_sent}B",
                level="INFO"
            )
        return bytes_sent

    def close(self):
        raw_close(self=stack.core, so=self)

        if __debug__:
            log("socket",
                f"{self}: socket closed",
                level="INFO"
            )

    def recv(self, bufsize: int):
        data = raw_recv(self=stack.core, so=self, bufsize=bufsize)
        if __debug__:
            log(
                "socket",
                f"{self}: {self.remote_ip} -> {self.local_ip} "
                f"recv {len(data)}B, read {len(data[:bufsize])}B",
                level="INFO"
            )

        return data

    def shutdown(self):
        pass

    def settimeout(self, t):
        self.timeout = t

    def get_data(self, packet: memoryview):
        self.queue.append(packet)
        with self.cond:
            self.cond.notify()

    def raise_exception(self):
        so_error[self.error](self)
