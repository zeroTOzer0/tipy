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
    IPPROTO_IP = 0
    IPPROTO_ICMP = 1
    IPPROTO_TCP = 6
    IPPROTO_UDP = 17

    def __str__(self):
        return self.name

class OptionLevel(IntEnum):
    """
    use it with 'setsockopt' call
    """
    IPPROTO_IP = 0
    SOL_SOCKET = 1

    def __str__(self):
        return self.name

class OptionName(IntEnum):
    IPPROTO_TTL = 0
    IPPROTO_OPTIONS = 1
    SO_LINGER = 2

    def __str__(self):
        return self.name

# Socket Families
AF_INET = AddressFamily.AF_INET

# Socket Types
SOCK_STREAM = SocketType.SOCK_STREAM
SOCK_DGRAM = SocketType.SOCK_DGRAM
SOCK_RAW = SocketType.SOCK_RAW

# Protocol Numbers
IPPROTO_IP = Protocol.IPPROTO_IP
IPPROTO_ICMP = Protocol.IPPROTO_ICMP
IPPROTO_TCP = Protocol.IPPROTO_TCP
IPPROTO_UDP = Protocol.IPPROTO_UDP

# Socket Options Level
# NOTE: IPPROTO_IP level is defined above at protocole number
# in : IPPROTO_IP = OptionLevel.IPPROTO_IP
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

        self.family: AddressFamily
        self.type: SocketType

        self.sock_opt: dict[tuple[OptionLevel, OptionName], int | bytes] = dict()

        self.error: int = 0

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

def socket(family: AddressFamily, type_: SocketType, protocol: int=0) -> Socket | None:
    from tipy.protocols.udp.socket import UDPSocket
    from tipy.protocols.tcp.socket import TCPSocket
    from tipy.protocols.raw.socket import RIPSocket
    if family == AF_INET:
        if type_ == SOCK_DGRAM:
            return UDPSocket(
                family=family, type_=type_, proto=protocol
            )

        if type_ == SOCK_STREAM:
            return TCPSocket(
                family=family, type_=type_, proto=protocol
            )

        if type_ == SOCK_RAW:
            return RIPSocket(
                family=AF_INET, type_=type_, proto=protocol
            )

    return None


