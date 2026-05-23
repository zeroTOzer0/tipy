from __future__ import annotations

from tipy.lib.logger import log
from tipy.lib.ip_address import IPAddress
from tipy.lib.mac_address import MACAddress
from tipy.protocols.arp.builder import ARPBuilder

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

    # must do conditions her because arp-req need to
    # add Zeros in tha, so we can't use it in dst arg in ptx_ether

    if op == 1:
        # if this an arp prob
        if prob:
            self.arp_cache.arp_probe_add(str(tpa))
            if __debug__: log(
                'arp',
                f'{arp_builder.tracker} - '
                f'{arp_builder}'
            )

        # if this is a normal arp request
        else:
            self.arp_cache.arp_wait_add(str(tpa))
            if __debug__: log(
                'arp',
                f'{arp_builder.tracker} - '
                f'{arp_builder}'
            )

        return self.tx_ether(
            payload=arp_builder,
            dst=MACAddress(b'\xff'*6),
            src=sha,
            type=0x0806
        )

    if op == 2:
        if __debug__: log(
            'arp',
            f'{arp_builder.tracker} - '
            f'{arp_builder}'
        )

        return self.tx_ether(
            payload=arp_builder,
            dst=tha,
            src=sha,
            type=0x0806
        )
    return

