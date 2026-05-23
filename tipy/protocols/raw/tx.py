from __future__ import annotations
from typing import TYPE_CHECKING
from tipy.lib.ip_address import IPAddress

from tipy.protocols.raw.builder import RAWBuilder

if TYPE_CHECKING:
    from tipy.components.core import Core
    from tipy.lib.tracker import Tracker


def tx_raw(self: Core,
           payload: bytes,
           protocol: int,
           src: IPAddress,
           dst: IPAddress,
           sock_opt: dict|None=None,
           tracker: Tracker | None = None
           ):


    raw_builder = RAWBuilder(
        data=payload
    )

    return self.tx_ip(
        payload=raw_builder,
        protocol=protocol,
        src=src,
        dst=dst,
        sock_opt=sock_opt
    )