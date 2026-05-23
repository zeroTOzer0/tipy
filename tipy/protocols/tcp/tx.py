from __future__ import annotations

from tipy.lib.logger import log
from tipy.lib.ip_address import IPAddress
from tipy.protocols.tcp.builder import TCPBuilder, TCPOptBuilder

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tipy.components.core import Core
    from tipy.lib.tracker import Tracker
    from tipy.protocols.tcp.builder import TCPOptMSS, TCPOptNOP



def tx_tcp(
        self: Core,
        local_ip: IPAddress,
        remote_ip: IPAddress,
        local_port: int,
        remote_port: int,

        seq: int,
        ack_seq: int = 0,

        cwr: bool = False,
        ece: bool = False,
        urg: bool = False,
        ack: bool = False,
        psh: bool = False,
        rst: bool = False,
        syn: bool = False,
        fin: bool = False,

        window: int = 65535,
        urg_ptr: int = 0,

        options: list[TCPOptMSS] | None = None,
        data: memoryview = memoryview(b""),

        sock_opt=None,

        tracker: Tracker | None = None,
        ):


    tcp_builder = TCPBuilder(
        src=local_port,
        dst=remote_port,

        seq=seq,
        ack_seq=ack_seq,

        cwr=cwr,
        ece=ece,
        urg=urg,
        ack=ack,
        psh=psh,
        rst=rst,
        syn=syn,
        fin=fin,

        window=window,
        urg_ptr=urg_ptr,

        options=TCPOptBuilder(options) if options else None,
        data=data,
        tracker=tracker,
    )


    if __debug__: log("tcp",
                      f"{tcp_builder.tracker} - {tcp_builder}")

    self.tx_ip(
        payload=tcp_builder,
        src=local_ip,
        dst=remote_ip,
        protocol=6,
        sock_opt=sock_opt
    )