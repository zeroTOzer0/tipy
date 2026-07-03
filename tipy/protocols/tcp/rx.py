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
    if __debug__:
        log(
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



    # Generate RST for a non-existent connection.
    # if ACK is set, then: SEQ = SEG.ACK.
    # Otherwise: SEQ = 0, ACK = SEG.SEQ + SEG.LEN.
    # [RFC 9293: 3.5.2. Reset Generation]

    if __debug__:
        log(
            "tcp",
            f"received segment [{packet_rx.tracker}] for a closed connection; sending RST",
            "INFO"
        )
    if packet_rx.tcp.ack:

        self.tx_tcp(
            local_ip=IPAddress(packet_rx.ip.dst), local_port=packet_rx.tcp.dst,
            remote_ip=IPAddress(packet_rx.ip.src), remote_port=packet_rx.tcp.src,
            seq=packet_rx.tcp.ack_seq, ack_seq=0,
            rst=True,
            window=0
        )
        return

    ack_seq = (packet_rx.tcp.seq
               + packet_rx.tcp.dlen
               + packet_rx.tcp.syn
               + packet_rx.tcp.fin) & 0xFF_FF_FF_FF
    self.tx_tcp(
        local_ip=IPAddress(packet_rx.ip.dst), local_port=packet_rx.tcp.dst,
        remote_ip=IPAddress(packet_rx.ip.src), remote_port=packet_rx.tcp.src,
        seq=0, ack_seq=ack_seq,
        rst=True, ack=True,
        window=0
    )

