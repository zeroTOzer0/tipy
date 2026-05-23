from __future__ import annotations

from tipy.protocols.ether.parser import EtherParser

from tipy.lib.logger import log
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from tipy.lib.packet import PacketRX
    from tipy.components.core import Core

def rx_ether(self: Core, packet_rx: PacketRX):
    EtherParser(packet_rx=packet_rx)
    if __debug__: log(
        'ether',
        f"{packet_rx.tracker} - "
        f'{packet_rx.ether}'
    )
    # print(packet_rx.ether)
    packet_rx.frame = packet_rx.frame[14:]

    # pass to next layer
    self.ether_protocol_map.get(
        packet_rx.ether.type,
        self.ether_protocol_map[None]
    )(self, packet_rx)



