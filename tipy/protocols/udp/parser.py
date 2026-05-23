from __future__ import annotations

from struct import unpack_from
from functools import cached_property

from tipy.protocols.udp.udp import UDP_HEADER_LEN

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from tipy.lib.packet import PacketRX



class UDPParser:

    __slots__ = ('_frame', '__dict__')

    def __init__(self, packet_rx: PacketRX):
        self._frame: memoryview = packet_rx.frame
        packet_rx.udp = self


    @cached_property
    def src(self):
        return unpack_from('!H', self._frame, 0)[0]

    @cached_property
    def dst(self):
        return unpack_from('!H', self._frame, 2)[0]

    @cached_property
    def len(self):
        return unpack_from('!H', self._frame, 4)[0]

    @cached_property
    def chksum(self):
        return unpack_from('!H', self._frame, 6)[0]

    @cached_property
    def dlen(self):
        return len(self) - UDP_HEADER_LEN

    @cached_property
    def data(self):
        return self._frame[UDP_HEADER_LEN:]

    @cached_property
    def header(self):
        return self._frame[:UDP_HEADER_LEN]


    def __str__(self) -> str:
        return f"UDP {self.src} > {self.dst}, len {self.len}"

    def __len__(self):
        return len(self._frame)