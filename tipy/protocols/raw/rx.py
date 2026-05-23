from __future__ import annotations

from tipy.protocols.raw.parser import RAWParser

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from tipy.lib.packet import PacketRX
    from tipy.components.core import Core


def rx_raw(packet_handler: Core, packet_rx: PacketRX):
    RAWParser(packet_rx)
