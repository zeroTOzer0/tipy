from tipy.lib.socket import (Socket,
                             AF_INET,
                             SOCK_STREAM)

from tipy.lib import stack
from tipy.lib.ip_address import IPAddress
from tipy.lib.logger import log
from threading import Condition

from tipy.protocols.tcp.tcp_usrreq import (
    tcp_bind, tcp_connect, tcp_send, tcp_recv, tcp_close, tcp_shutdown
)


class TCPSocket(Socket):
    def __init__(self, family=AF_INET):
        # sock_opt() is inherited from Socket ABC
        super().__init__()
        self.local_ip: IPAddress = IPAddress('0.0.0.0')
        self.remote_ip: IPAddress = IPAddress('0.0.0.0')
        self.local_port: int = 0
        self.remote_port: int = 0

        self.connect_events: Condition = Condition()
        self.rcv_events: Condition = Condition()
        self.send_events: Condition = Condition()
        self.close_events: Condition = Condition()

        self.sock_id: tuple = (
            self.local_ip.ip_address, self.local_port,
            self.remote_ip.ip_address, self.remote_port
        )

        self.family = family
        self.type = SOCK_STREAM


    def bind(self, address: tuple[str, int]):
        tcp_bind(self=stack.core, so=self, address=address)
        if __debug__:
            log(
                "socket",
                f"{self} bound to {address[0]}:{address[1]}",
                level="INFO"
            )

    def listen(self, backlog: int):
        ...

    def connect(self, address: tuple[str, int]):
        tcp_connect(self=stack.core, so=self, address=address)
        if __debug__:
            log(
                "socket",
                f"{self} connect to {self.remote_ip}:{self.remote_port}",
                level="INFO"
            )



    def close(self):
        if __debug__:
            log(
                "socket",
                f"{self} socket close",
                level="INFO"
            )
        tcp_close(self=stack.core, so=self)

    def shutdown(self):
        if __debug__:
            log(
                "socket",
                f"{self} socket shutdown",
                level="INFO"
            )
        tcp_shutdown(self=stack.core, so=self)

    def send(self, data: bytes) -> int:
        if __debug__:
            log(
                "socket",
                f"{self} {self.sock_id} "
                f"copied {len(data)}B into send buffer",
                level="INFO"
            )

        return tcp_send(self=stack.core, so=self, data=data)

    def recv(self, bufsize: int):
        if __debug__:
            log(
                "socket",
                f"{self} {self.sock_id} "
                f"read {bufsize}B from receive buffer",
                level="INFO"
            )
        data = tcp_recv(self=stack.core, so=self, bufsize=bufsize)
        return  b''.join(_.tobytes() for _ in data)

    def settimeout(self, t):
        ...
