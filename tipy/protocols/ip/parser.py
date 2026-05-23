from __future__ import annotations

from struct import unpack_from

from functools import cached_property

from tipy.lib.csum import inet_csum
from tipy.lib.ip_address import IPAddress
from tipy.protocols.ip.ip import IP_PROTO
from tipy.lib.logger import log
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from tipy.lib.packet import PacketRX

class IPParser:
    def __init__(self, packet_rx: PacketRX):
        self._frame: memoryview = packet_rx.frame
        packet_rx.ip = self

    @cached_property
    def ver(self) -> int:
        return self._frame[0] >> 4

    @cached_property
    def ihl(self) -> int:
        return (self._frame[0] & 0xF) * 4

    @cached_property
    def tos(self):
        # Ignored
        ...

    @cached_property
    def total_len(self) -> int:
        return unpack_from('!H', self._frame, 2)[0]

    @cached_property
    def id(self) -> int:
        return unpack_from('!H', self._frame, 4)[0]

    @cached_property
    def flags_fragoff(self):
        return unpack_from('!H', self._frame, 6)[0]


    @cached_property
    def flag_df(self) -> bool:
        return bool(self.flags_fragoff & 0x4000)


    @property
    def flag_mf(self) -> bool:

        return bool(self.flags_fragoff & 0x2000)

    @property
    def offset(self) -> int:
        return self.flags_fragoff & 0x1FFF

    @cached_property
    def ttl(self) -> int:
        return self._frame[8]

    @cached_property
    def protocol(self) -> int:
        return self._frame[9]

    @cached_property
    def checksum(self) -> int:
        return unpack_from('!H', self._frame, 10)[0]

    @cached_property
    def src(self) -> str:
        return IPAddress(self._frame[12:16]).raw2ip()

    @cached_property
    def dst(self) -> str:
        return IPAddress(self._frame[16:20]).raw2ip()

    @cached_property
    def options(self):
        # Ignored
        ...

    @cached_property
    def dlen(self):
        return self.total_len - self.ihl

    @cached_property
    def data(self):
        # FIXME: USE memoryview INSTEAD OF bytes
        return bytes(self._frame[self.ihl:self.ihl + self.total_len])

    @cached_property
    def header(self):
        # FIXME: USE memoryview INSTEAD OF bytes
        return bytes(self._frame[:self.ihl])

    def __len__(self):
        return self.total_len

    def __str__(self):
        return (
            f"IPv4 {self.src} > {self.dst}, proto {self.protocol} "
            f"({IP_PROTO.get(self.protocol, '???')}) "
            f"id {self.id},"
            f"{' DF,' if self.flag_df else ''}"
            f"{' MF,' if self.flag_mf else ''}"
            f" offset {self.offset}, "
            f"hlen {self.ihl} bytes, "
            f'plen {self.dlen} bytes'
        )




