from tipy.lib.ip_address import IPAddress, IPFormatError
from tipy.lib.logger import log
from tipy.lib import stack
from tipy.lib.socket_errors import gaierror

from tipy.lib.socket import (Socket,
                             AF_INET,
                             SOCK_DGRAM,
                             )
from threading import Condition
from collections import deque


class UDPSocket(Socket):
    def __init__(self, family=AF_INET):
        super().__init__()
        self.local_ip: IPAddress = IPAddress('0.0.0.0')
        self.remote_ip: IPAddress = IPAddress('0.0.0.0')
        self.local_port: int = 0
        self.remote_port: int = 0

        self.family = family
        self.type = SOCK_DGRAM

        self._cond: Condition = Condition()
        self._queue: deque[memoryview] = deque()

        # self.sock_opt is inherited from Socket ABC

        self._timeout: int | None = None

        self.sock_id: tuple = (
            self.local_ip.ip_address, self.local_port,
            self.remote_ip.ip_address, self.remote_port
        )

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

        if stack.core.udp.check_bound((self.local_ip.ip_address,
                                    self.local_port)):
            raise OSError("[Errno 98] Address already in use")

        self.sock_id = (
            self.local_ip.ip_address, self.local_port,
            self.remote_ip.ip_address, self.remote_port
        )
        stack.core.udp.register_socket(self.sock_id, self)
        stack.core.udp.register_bound_socket((self.local_ip.ip_address,
                                              self.local_port))

        if __debug__:
            log(
                "socket",
                f"{self} bound to {self.local_ip}:{self.local_port}",
                level="INFO"
            )

    def listen(self, backlog: int):
        raise OSError("[Errno 95] Operation not supported")


    def connect(self, address: tuple[str, int]):
        # Connect call in udp socket type
        # is used when you want to send data
        # using only the 'send' call, because
        # 'send' call does not accept remote port/ip args
        self.remote_ip = IPAddress(address[0])
        self.remote_port = address[1]

        if not self.local_port:
            self.local_port = stack.core.udp.pick_ephemeral_udp_port()
            # TODO : MUST SELECT IP BASED ON THE DST IP SELECTED FROM CONNECT
            # now just select the configured IP
            self.local_ip : IPAddress= stack.core.unicast_ip

            self.sock_id = (
                self.local_ip.ip_address, self.local_port,
                self.remote_ip.ip_address, self.remote_port
            )

            stack.core.udp.register_socket(self.sock_id, self)
            return

        self.sock_id = (
            self.local_ip.ip_address, self.local_port,
            self.remote_ip.ip_address, self.remote_port
        )

        stack.core.udp.update_socket(
            (self.local_ip.ip_address, self.local_port, '0.0.0.0', 0 ),
            self.sock_id,
            self
        )

        if __debug__:
            log(
                "socket",
                f"{self} connected to {self.remote_ip}:{self.remote_port}",
                level="INFO"
            )

    def close(self):
        stack.core.udp.remove_socket((
            self.local_ip, self.local_port,
            self.remote_ip, self.remote_port
        ))
        if __debug__:
            log(
                "socket",
                f"{self} socket closed",
                level="INFO"
            )


    def send(self, data: bytes):

        # check if the socket is connected type (we use connect call)
        if self.remote_ip.ip_address != '0.0.0.0' and self.remote_port:
            # check if there is an icmp err msg (for example port unreachable)
            if self.sock_id in stack.core.udp.err_msg:
                exp = stack.core.udp.err_msg[self.sock_id]
                raise exp

            if __debug__:
                log(
                    "socket",
                    f"{self} {self.local_ip}:{self.local_port} -> {self.remote_ip}:{self.remote_port} "
                    f"sent {len(data)}B",
                    level="INFO"
                )

            stack.core.tx_udp(
                local_ip=self.local_ip,
                remote_ip=self.remote_ip,
                local_port=self.local_port,
                remote_port=self.remote_port,
                sock_opt=self.sock_opt,
                data=data
            )

    def recv(self, bufsize: int):
        with self._cond:
            got_packet = self._cond.wait(timeout=self._timeout)
            if not got_packet:
                raise TimeoutError('timed out')

            packet = self._queue.popleft()

            if __debug__:
                log(
                    "socket",
                    f"{self} {self.local_ip}:{self.local_port} -> {self.remote_ip}:{self.remote_port} "
                    f"recv {len(packet)}B, read {len(packet[:bufsize])}B",
                    level="INFO"
                )

            return bytes(packet[:bufsize])

    def settimeout(self, t: int):
        self._timeout = t

    def shutdown(self):
        ...


    def get_data(self, packet: memoryview):
        self._queue.append(packet)
        with self._cond:
            self._cond.notify()

