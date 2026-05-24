from __future__ import annotations

from struct import unpack_from
from functools import cached_property

from tipy.lib.mac_address import MACAddress
from tipy.protocols.ether.ether import ETHER_TYPES

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from tipy.lib.packet import PacketRX

class EtherParser:

    __slots__ = ('_frame', '__dict__')

    def __init__(self, packet_rx: PacketRX):
        self._frame: memoryview = packet_rx.frame
        packet_rx.ether = self



    @cached_property
    def dst(self):
        return MACAddress(self._frame[:6])


    @cached_property
    def src(self):
        return MACAddress(self._frame[6:12])


    @cached_property
    def type(self):
        return  unpack_from('! H', self._frame[12:14])[0]


    def __str__(self):
        return (
            f"ETHER {self.src} > {self.dst}, 0x{self.type:0>4x} "
            f"({ETHER_TYPES.get(self.type, '???')})"
        )



