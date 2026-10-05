from __future__ import annotations

import struct

from tipy.lib.ethernet import MACAddress
from tipy.protocols.ether.ether import ETHER_LEN
from tipy.protocols.ether.ether import ETHER_TYPES

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from tipy.protocols.ip.builder import IPBuilder, IPFragBuilder

class EtherBuilder:
    def __init__(self,
                 *,
                 payload: IPBuilder | IPFragBuilder,
                 dst: MACAddress,
                 src: MACAddress,
                 type_: int = 0x0800,
                 ):

        self._dst = dst
        self._src = src
        self._type: int = type_
        self._payload: IPBuilder | IPFragBuilder = payload

    def build(self, frame: memoryview):
        struct.pack_into(
            '! IH IH H',
            frame,
            0,
            self._dst.mac_high,
            self._dst.mac_low,
            self._src.mac_high,
            self._src.mac_low,
            self._type
        )

        self._payload.build(frame=frame[14:])

    def __len__(self):
        return ETHER_LEN + len(self._payload)

    def __str__(self):
        return (
            f"ETHER {self._src} -> {self._dst}, 0x{self._type:0>4x} "
            f"({ETHER_TYPES.get(self._type, '???')}) "
            f"dlen {len(self._payload)}"
        )

    @property
    def tracker(self):
        return self._payload.tracker
