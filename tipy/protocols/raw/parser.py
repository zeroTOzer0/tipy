from __future__ import annotations

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from tipy.lib.packet import PacketRX

class RAWParser:
    def __init__(self, packet_rx: PacketRX) -> None:

        self._frame = packet_rx.frame
        packet_rx.raw = self

    @property
    def data(self):
        return self._frame

    def __str__(self):
        return f"RAW data : {len(self._data)}"




