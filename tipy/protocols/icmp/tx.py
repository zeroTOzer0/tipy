from __future__ import annotations

from tipy.protocols.icmp.builder import ICMPBuilder
from tipy.lib.logger import log
from tipy.lib.ip_address import IPAddress
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from tipy.components.core import Core
    from tipy.lib.tracker import Tracker



def tx_icmp(self: Core,
            src: IPAddress,
            dst: IPAddress,
            type: int,
            code: int,
            data: bytes | None=None,
            echo_id: int|None=None,
            echo_seq: int|None=None,
            tracker: Tracker | None = None,
            ):

    icmp_builder = ICMPBuilder(
        type=type,
        code=code,
        data=data,
        echo_id=echo_id,
        echo_seq=echo_seq,
        tracker=tracker,
    )
    if __debug__: log('icmp',
                      f'{icmp_builder.tracker} - {icmp_builder}')

    return self.tx_ip(
        payload=icmp_builder,
        src=src,
        dst=dst,
        protocol=1
    )