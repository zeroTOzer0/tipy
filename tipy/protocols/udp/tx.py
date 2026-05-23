from __future__ import annotations
from tipy.lib.ip_address import IPAddress
from tipy.protocols.udp.builder import UDPBuilder
from typing import TYPE_CHECKING
from tipy.lib.logger import log


if TYPE_CHECKING:
    from tipy.components.core import Core
    from tipy.lib.tracker import Tracker

def tx_udp(self: Core,
           local_ip: IPAddress,
           remote_ip: IPAddress,
           local_port: int,
           remote_port: int,
           data: bytes,
           sock_opt: dict|None,
           tracker: Tracker | None = None
           ):

    udp_builder = UDPBuilder(
        src=local_port,
        dst=remote_port,
        data=data,
        tracker=tracker
    )

    if __debug__: log("udp",
        f'{udp_builder.tracker} - '
        f'{udp_builder}')
    self.tx_ip(
        payload=udp_builder,
        src=local_ip,
        dst=remote_ip,
        protocol=17,
        sock_opt=sock_opt
    )
