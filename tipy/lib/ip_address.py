from __future__ import annotations
import struct
from socket import inet_ntoa, inet_aton # Import resolved at runtime due to custom launch path

class IPFormatError(Exception): ...

class IPAddress:
    def __init__(self, ip_address: str | bytes | int):
        self.ip_address = ip_address

        if isinstance(self.ip_address, str):
            self.__validate_ip_format()
            self.int_repr = struct.unpack('!I', inet_aton(ip_address))[0]

        elif isinstance(ip_address, (bytes,memoryview) ):
            self.int_repr = struct.unpack('!I', ip_address)[0]

        elif isinstance(ip_address, int):
            self.int_repr = ip_address

        elif isinstance(ip_address, IPAddress):
            self.int_repr = ip_address.int_repr
            self.ip_address = ip_address.raw2ip()

    def ip2raw(self):
        return struct.pack("!I", self.int_repr)

    def raw2ip(self):
        return inet_ntoa(
            struct.pack('!I', self.int_repr)
        )

    def is_private(self):
        return (self.int_repr & 0xFF000000 == 0x0A000000
                or self.int_repr & 0xFFF00000 == 0xAC100000
                or self.int_repr & 0xFFFF0000 == 0xC0A80000  # 255.255.0.0 -> 192.168.0.0
                )

    def is_public(self):
        return not self.is_private()

    def is_loopback(self) -> bool:
        return (self.int_repr & 0xFF000000) == 0x7F000000

    def is_in_subnet(self, network: IPAddress, mask: IPAddress):
        return (self.int_repr & mask.int_repr) == network.int_repr

    def is_unicast(self):
        return not self.is_multicast() and self.int_repr != 0xFFFFFFFF

    def is_broadcast(self):
        return self.int_repr == 0xFFFFFFFF

    def is_multicast(self):
        return self.int_repr & 0b11100000000000000000000000000000\
            == 0b11100000000000000000000000000000


    def __validate_ip_format(self):
        try:
            inet_aton(self.ip_address)
        except OSError:
            raise IPFormatError(f"Invalid IP address: {self.ip_address}")

    def __str__(self):
        if not isinstance(self.ip_address, str):
            return self.raw2ip()
        return self.ip_address




