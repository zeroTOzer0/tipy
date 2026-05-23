from __future__ import annotations

from tipy.protocols.udp.parser import UDPParser
from tipy.lib.logger import log
from tipy.lib.ip_address import IPAddress
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tipy.components.core import Core
    from tipy.lib.packet import PacketRX

def rx_udp(self: Core, packet_rx: PacketRX):
    UDPParser(packet_rx=packet_rx)

    if __debug__: log('udp',
        f"{packet_rx.tracker} - "
        f"{packet_rx.udp}")

    sock_id: tuple = (
        packet_rx.ip.dst, packet_rx.udp.dst,
        packet_rx.ip.src, packet_rx.udp.src
    )

    if sock_id in self.udp.sockets:
        if __debug__:
            log(
                "socket",
                f"UDP socket matched: {sock_id}",
                level="DEBUG"
            )
        self.udp.sockets[sock_id].get_data(packet_rx.udp.data)

        return

    # TODO:
    # In server case, only "bind" call is used.
    # So remote ip/port could be anything (0.0.0.0:0).
    # Here, if exact sock_id is not in udp_socket table,
    # try again with wildcard sock_id:
            # sock_id_wild: tuple = (
            #     packet_rx.ip.dst, packet_rx.udp.dport,
            #     '0.0.0.0', 0
            # )
            # return



    # send type3 code3: port unreachable;
    if __debug__:
        log(
            "icmp",
            f"{packet_rx.tracker} port unreachable: "
            f"{packet_rx.ip.dst} -> {packet_rx.ip.src}",
            level="INFO"
        )
    self.tx_icmp(
        src=IPAddress(packet_rx.ip.dst),
        dst=IPAddress(packet_rx.ip.src),
        type=3,
        code=3,
        data=packet_rx.ip.header + packet_rx.ip.data[:8],
        tracker=packet_rx.tracker
    )







