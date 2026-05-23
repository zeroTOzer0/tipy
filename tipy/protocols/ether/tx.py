from __future__ import annotations
from tipy.protocols.ether.builder import EtherBuilder
from typing import TYPE_CHECKING
from tipy.lib.mac_address import MACAddress
from tipy.lib.logger import log


if TYPE_CHECKING:
    from tipy.protocols.ip.builder import IPBuilder, IPFragBuilder
    from tipy.protocols.arp.builder import ARPBuilder
    from tipy.components.core import Core


def tx_ether(
        self: Core,
        payload: IPBuilder|IPFragBuilder|ARPBuilder,
        dst: MACAddress,
        src: MACAddress,
        type: int
):

    ether_builder = EtherBuilder(
        payload=payload,
        dst=dst,
        src=src,
        type=type
    )
    if __debug__: log(
        'ether',
        f'{payload.tracker} - '
        f'{ether_builder}'
    )

    self.tx_ring.enqueue(ether_builder)




