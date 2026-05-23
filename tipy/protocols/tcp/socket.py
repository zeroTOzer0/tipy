from typing import Any

from tipy.lib.socket import (Socket,
                             AF_INET,
                             SOCK_STREAM)
from tipy.lib import stack
from tipy.lib.socket_errors import gaierror

from tipy.lib.ip_address import IPAddress, IPFormatError
from tipy.lib.logger import log
from tipy.protocols.tcp.tcpcb import TCPCB
from threading import Condition


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
        try:
            if str(IPAddress(address[0])) != str(stack.core.unicast_ip):
                raise OSError('[Errno 99] Cannot assign requested address')
            self.local_ip = IPAddress(address[0])
        except IPFormatError:
            raise gaierror('[Errno -2] Name or service not known')

        if self.local_port in range(1, 65535):
            # Already bound, cannot bind again
            # this raise an exception when we call
            # bind call more than one time
            raise OSError("[Errno 22] Invalid argument")

        self.local_port = address[1]

        if stack.core.tcp.check_bound((self.local_ip.ip_address,
                                    self.local_port)):
            raise OSError("[Errno 98] Address already in use")

        self.sock_id = (
            self.local_ip.ip_address, self.local_port,
            self.remote_ip.ip_address, self.remote_port
        )
        stack.core.tcp.register_socket(self.sock_id, self)
        stack.core.tcp.register_bound_socket((self.local_ip.ip_address,
                                              self.local_port))

        if __debug__:
            log(
                "socket",
                f"{self} bound to {self.local_ip}:{self.local_port}",
                level="INFO"
            )

    def listen(self, backlog: int):
        ...

    def connect(self, address: tuple[str, int]):
        self.remote_ip = IPAddress(address[0])
        self.remote_port = address[1]

        if not self.local_port:
            self.local_port = stack.core.tcp.pick_ephemeral_tcp_port()
            # just select the configured IP
            self.local_ip : IPAddress = stack.core.unicast_ip

            self.sock_id = (
                self.local_ip.ip_address, self.local_port,
                self.remote_ip.ip_address, self.remote_port
            )

            stack.core.tcp.register_socket(self.sock_id, self)

        else:
            self.sock_id = (
                self.local_ip.ip_address, self.local_port,
                self.remote_ip.ip_address, self.remote_port
            )

            stack.core.tcp.update_socket(
                (self.local_ip.ip_address, self.local_port, '0.0.0.0', 0 ),
                self.sock_id,
                self
            )


        # create a TCPCB and register it: STATE=CLOSED
        tcpcb = TCPCB(local_ip=self.local_ip,
                      local_port=self.local_port,
                      remote_ip=self.remote_ip,
                      remote_port=self.remote_port,
                      connect_events=self.connect_events,
                      rcv_events=self.rcv_events,
                      send_events= self.send_events,
                      close_events=self.close_events,
                      sock_opt= self.sock_opt,
                      core=stack.core)

        stack.core.tcp.register_tcpcb(sock_id=self.sock_id, tcpcb=tcpcb)
        with self.connect_events:
            tcpcb.activ_open()
            self.connect_events.wait()

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
                f"{self} socket closed",
                level="INFO"
            )
        return stack.core.tcp.tcpcbs[(
            self.local_ip.ip_address, self.local_port,
            self.remote_ip.ip_address, self.remote_port
        )].tcp_close()

    def shutdown(self):
        if __debug__:
            log(
                "socket",
                f"{self} socket shutdown",
                level="INFO"
            )
        return stack.core.tcp.tcpcbs[(
            self.local_ip.ip_address, self.local_port,
            self.remote_ip.ip_address, self.remote_port
        )].tcp_shutdown()

    def send(self, data: bytes) -> int:
        if __debug__:
            log(
                "socket",
                f"{self} {self.sock_id} "
                f"copied {len(data)}B into send buffer",
                level="INFO"
            )

        return stack.core.tcp.tcpcbs[(
            self.local_ip.ip_address, self.local_port,
            self.remote_ip.ip_address, self.remote_port
        )].tcp_send(memoryview(data))

    def recv(self, bufsize: int):
        if __debug__:
            log(
                "socket",
                f"{self} {self.sock_id} "
                f"read {bufsize}B from receive buffer",
                level="INFO"
            )
        data = stack.core.tcp.tcpcbs[(
            self.local_ip.ip_address, self.local_port,
            self.remote_ip.ip_address, self.remote_port
        )].tcp_recv(bufsize=bufsize)

        return  b''.join(_.tobytes() for _ in data)

    def settimeout(self, t):
        ...
