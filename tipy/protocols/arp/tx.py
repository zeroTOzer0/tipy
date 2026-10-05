from __future__ import annotations

from tipy.lib.logger import log
from tipy.lib.inet import IPAddress
from tipy.lib.ethernet import MACAddress
from tipy.protocols.arp.builder import ARPBuilder
from tipy.protocols.arp.arp import ARP_OP_REPLY, ARP_OP_REQUEST

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tipy.components.core import Core
    from tipy.lib.tracker import Tracker

def tx_arp(self: Core,
           sha: MACAddress,
           spa: IPAddress,
           tha: MACAddress,
           tpa: IPAddress,
           op: int,
           prob: bool=False,
           tracker: Tracker | None = None
           ):

    arp_builder = ARPBuilder(
        sha=sha,
        spa=spa,
        tha=tha,
        tpa=tpa,
        op=op,
        echo_tracker=tracker
    )

    if op == ARP_OP_REQUEST:
        # if this an arp prob
        if prob:
            self.arp_cache.arp_probe_add(tpa)
            if __debug__: log(
                'arp',
                f'{arp_builder.tracker} - '
                f'{arp_builder}'
            )

        # if this is a normal arp request
        else:
            self.arp_cache.arp_wait_add(tpa)
            if __debug__: log(
                'arp',
                f'{arp_builder.tracker} - '
                f'{arp_builder}'
            )

        return self.tx_ether(
            payload=arp_builder,
            dst=MACAddress(0xFF_FF_FF_FF_FF_FF),
            src=sha,
            type_=0x0806
        )

    if op == ARP_OP_REPLY:
        if __debug__: log(
            'arp',
            f'{arp_builder.tracker} - '
            f'{arp_builder}'
        )

        return self.tx_ether(
            payload=arp_builder,
            dst=tha,
            src=sha,
            type_=0x0806
        )
    return

