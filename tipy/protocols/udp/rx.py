from __future__ import annotations

from struct import pack

from tipy.protocols.udp.parser import UDPParser
from tipy.lib.ip_address import IPAddress
from tipy.lib.csum import inet_csum
from tipy.lib.logger import log

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tipy.components.core import Core
    from tipy.lib.packet import PacketRX

def rx_udp(self: Core, packet_rx: PacketRX):
    """
    UDP RX interface.

    1. Check if the UDP header length is acceptable.
    2. Calculate the UDP checksum.
    3. Try to resolve the socket, pass data the socket, and return.
    4. Send icmp message and return if no matching socket exists.
    """
    l = len(packet_rx.frame)

    if l < 8:
        if __debug__:
            log(
                'udp',
                f'[{packet_rx.tracker}] udp header too short',
                "DEBUG"
            )
        return

    UDPParser(packet_rx=packet_rx)
    if __debug__:
        log(
            'udp',
            f"{packet_rx.tracker} - {packet_rx.udp}"
        )

    dst_ip = packet_rx.ip.dst
    src_ip = packet_rx.ip.src

    # make the phdr follows network byte order
    # then pass it with native system byte order
    phdr = memoryview(
        pack(
            '! 4s 4s B B H',
            IPAddress(src_ip).ip2raw(),
            IPAddress(dst_ip).ip2raw(),
            0,
            packet_rx.ip.protocol,
            len(packet_rx.udp)
        )
    )

    if inet_csum(data=packet_rx.frame, inited_sum=sum(phdr.cast('I'))):
        if __debug__:
            log(
                'udp',
                f'[{packet_rx.tracker}] udp bad checksum.',
                "DEBUG"
            )
        return

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
            f"{packet_rx.ip.src}:{packet_rx.udp.src}"
            f" -> {packet_rx.ip.dst}:{packet_rx.udp.dst}",
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







