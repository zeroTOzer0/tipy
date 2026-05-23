from __future__ import annotations

from tipy.lib.ip_address import IPAddress
from tipy.lib.logger import log
from tipy.protocols.tcp.parser import TCPParser
from tipy.protocols.tcp.tcp import TCPEvent, TCPEventType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tipy.components.core import Core
    from tipy.lib.packet import PacketRX

def rx_tcp(self: Core, packet_rx: PacketRX):
    TCPParser(packet_rx)
    __debug__ and log(
        'tcp',
        f'{packet_rx.tracker} - {packet_rx.tcp}'
    )

    sock_id: tuple = (
        packet_rx.ip.dst, packet_rx.tcp.dst,
        packet_rx.ip.src, packet_rx.tcp.src
    )

    if sock_id in self.tcp.sockets:
        tcpcb = self.tcp.tcpcbs.get(sock_id)
        self.tcp_events_schedule.schedule_event(
            TCPEvent(
                type_=TCPEventType.RX_SEGMENT,
                tcpcb=tcpcb,
                packet_rx=packet_rx,
            )
        )
        return



    if packet_rx.tcp.syn and not packet_rx.tcp.ack:
        log(
            "tcp",
            f'receive SYN from [{packet_rx.tracker}] on closed port, send RST',
            "INFO"
        )

        self.tx_tcp(
            local_ip=IPAddress(packet_rx.ip.dst), local_port=packet_rx.tcp.dst,
            remote_ip=IPAddress(packet_rx.ip.src), remote_port=packet_rx.tcp.src,
            seq=0, ack_seq=packet_rx.tcp.seq+1,
            rst=True, ack=packet_rx.tcp.seq+1,
            window=0
        )

