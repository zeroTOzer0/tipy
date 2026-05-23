from tipy.lib.ip_address import IPAddress, IPFormatError
from tipy.lib.logger import log
from tipy.lib import stack
from tipy.lib.socket_errors import gaierror
from tipy.lib.socket import (Socket,
                             AF_INET,
                             SOCK_RAW,
                             IP_PROTO_ICMP
                             )


from threading import Semaphore, Condition
from collections import deque


class ICMPSocket(Socket):
    def __init__(self, family=AF_INET):
        super().__init__()
        # now we have only one interface
        # so just pick your own ip unicast
        self.local_ip: IPAddress = IPAddress(stack.core.unicast_ip)
        self.remote_ip: IPAddress = IPAddress('0.0.0.0')

        self.family = family
        self.type = SOCK_RAW

        self._cond: Condition = Condition()
        self._queue: deque[memoryview] = deque()

        self._timeout: int | None = None

        # Must find some mechanics to identify a secure id for
        # AF_INET/SOCK_RAW sockets
        self.sock_id: tuple = (
            self.local_ip.ip_address,
            int(IP_PROTO_ICMP),
            None #bro! use proto number like IP_PROTO_ICMP
        )



    def bind(self, address: tuple[str, int]):
        try:
            if str(IPAddress(address[0])) != str(stack.core.unicast_ip):
                raise OSError('[Errno 99] Cannot assign requested address')
            self.local_ip = IPAddress(address[0])
        except IPFormatError:
            raise gaierror('[Errno -2] Name or service not known')



        self.sock_id = (
            self.local_ip.ip_address,
            IP_PROTO_ICMP,
            None
        )

        stack.core.raw_v4.register_socket(self.sock_id)

        if __debug__: log(
            'socket',
            f'<lg<U>>{self.local_ip}/{str(IP_PROTO_ICMP)}<U></>'
            f' - Bound to socket'
        )

    def listen(self, backlog: int):
        raise OSError("[Errno 95] Operation not supported")

    def connect(self, address: tuple[str, int]):
        try:
            self.remote_ip = IPAddress(address[0])
            stack.core.raw_v4.register_socket(self.sock_id, self)
        except IPFormatError:
            raise gaierror('[Errno -2] Name or service not known')

        if __debug__: log("socket", f"<lg><U>{self}"
                                    f"</> - Connected")

    def send(self, data: bytes):
        # check if the socket is connected type (we use connect call)
        if self.remote_ip.ip_address != '0.0.0.0':
            if __debug__: log(
                "socket",
                f"<lg><U>{self}</> - Sent {len(data)} bytes of data</>",
            )

            stack.core.tx_raw(
                payload=data,
                protocol=int(IP_PROTO_ICMP),
                src=self.local_ip,
                dst=self.remote_ip,
                sock_opt=self.sock_opt

            )

    def recv(self, bufsize: int):
        with self._cond:
            got_packet = self._cond.wait(timeout=self._timeout)
            if not got_packet:
                raise TimeoutError('timed out')

            packet = self._queue.popleft()
            return bytes(packet[:bufsize])



    def shutdown(self):
        ...

    def close(self):
        stack.core.raw_v4.remove_socket(
            self.sock_id
        )
        if __debug__: log("socket", f"<lg><U>{self}</> - <r><U>Closed</>")

    def settimeout(self, t: int):
        self._timeout = t

    def get_data(self, packet: memoryview):
        self._queue.append(packet)
        with self._cond:
            self._cond.notify()


