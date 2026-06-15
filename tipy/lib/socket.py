from abc import ABC, abstractmethod

from tipy.lib.ip_address import IPAddress
from tipy.lib.logger import log
from enum import IntEnum

class AddressFamily(IntEnum):
    AF_INET = 1
    AF_INET6 = 2

    def __str__(self):
        return self.name

class SocketType(IntEnum):
    SOCK_STREAM = 1
    SOCK_DGRAM = 2
    SOCK_RAW = 3

    def __str__(self):
        return self.name

class Protocol(IntEnum):
    IP_PROTO_IP = 0
    IP_PROTO_ICMP = 1
    IP_PROTO_TCP = 6
    IP_PROTO_UDP = 17
    def __str__(self):
        return self.name

class OptionLevel(IntEnum):
    """
    use it with 'setsockopt' call
    """

    IPPROTO_IP = 1
    SOL_SOCKET = 2

    def __str__(self):
        return self.name

class OptionName(IntEnum):
    IPPROTO_TTL = 1
    IPPROTO_OPTIONS = 2

    SO_LINGER = 3

    def __str__(self):
        return self.name

# Socket Families
AF_INET = AddressFamily.AF_INET

# Socket Types
SOCK_STREAM = SocketType.SOCK_STREAM
SOCK_DGRAM = SocketType.SOCK_DGRAM
SOCK_RAW = SocketType.SOCK_RAW

# Protocol Numbers
IP_PROTO_IP = Protocol.IP_PROTO_IP
IP_PROTO_ICMP = Protocol.IP_PROTO_ICMP
IP_PROTO_TCP = Protocol.IP_PROTO_TCP
IP_PROTO_UDP = Protocol.IP_PROTO_UDP

# Socket Options Level
IPPROTO_IP = OptionLevel.IPPROTO_IP
SOL_SOCKET = OptionLevel.SOL_SOCKET

# Socket Option Name
IPPROTO_TTL = OptionName.IPPROTO_TTL
IPPROTO_OPTIONS = OptionName.IPPROTO_OPTIONS
SO_LINGER = OptionName.SO_LINGER

class Socket(ABC):
    def __init__(self):
        self.local_ip: IPAddress
        self.remote_ip: IPAddress
        self.local_port: int
        self.remote_port: int
        self.__family: AddressFamily
        self.__type: SocketType

        self.sock_opt: dict[tuple[OptionLevel, OptionName], int | bytes] = dict()

    def __str__(self):
        return f'{self.family}/{self.type}'




    @abstractmethod
    def bind(self, address: tuple[str, int]):
        """Bind call"""

    @abstractmethod
    def listen(self, backlog: int):
        """listen call"""

    @abstractmethod
    def connect(self, address: tuple[str, int]):
        """Connect call"""

    @abstractmethod
    def close(self):
        """close call"""

    @abstractmethod
    def send(self, data: bytes):
        """Send call"""

    @abstractmethod
    def recv(self, bufsize: int):
        """recv call"""

    @abstractmethod
    def shutdown(self):
        """shutdown call"""

    @abstractmethod
    def settimeout(self, t):
        """settimeout call"""

    def setsockopt(self, level: int, optname: int, value: int | bytes):
        self.sock_opt: dict = {
            (level, optname) : value
        }
        if __debug__:
            log(
                'socket',
                f'Set socket options | level={level}, optname={optname}, value={value}',
                'INFO'
            )




def socket(family: AddressFamily, type: SocketType, protocol: Protocol=0) -> Socket | None:
    from tipy.protocols.udp.socket import UDPSocket
    from tipy.protocols.icmp.socket import ICMPSocket
    from tipy.protocols.tcp.socket import TCPSocket
    if type == SOCK_DGRAM:
        return UDPSocket()

    if type == SOCK_STREAM:
        return TCPSocket()

    if type == SOCK_RAW and protocol == IP_PROTO_ICMP:
        return ICMPSocket()

    return None


