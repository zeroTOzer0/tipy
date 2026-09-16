from __future__ import annotations

from struct import pack

from tipy.protocols.tcp.tcp import TCPEvent, TCPEventType
from tipy.protocols.tcp.parser import TCPParser
from tipy.lib.ip_address import IPAddress
from tipy.lib.csum import inet_csum
from tipy.lib.logger import log

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tipy.components.core import Core
    from tipy.lib.packet import PacketRX


def rx_tcp(self: Core, packet_rx: PacketRX):
    """
    TCP RX interface

    1. Check if the TCP header length is acceptable.
    2. Calculate the TCP checksum.
    3. Try to resolve the socket, schedule an RX event, and return.
    4. Send RST and return if no matching socket exists.
    """
    l = len(packet_rx.frame)

    if l < 20:
        if __debug__:
            log(
                'tcp',
                f'[{packet_rx.tracker}] tcp header too short',
                "DEBUG"
            )
        return

    TCPParser(packet_rx)
    if __debug__:
        log(
        'tcp',
        f'{packet_rx.tracker} - {packet_rx.tcp}'
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
                l
            )
        )

    if inet_csum(data=packet_rx.frame, inited_sum=sum(phdr.cast('I'))):
        if __debug__:
            log(
                'tcp',
                f'[{packet_rx.tracker}] tcp bad checksum.',
                "DEBUG"
            )
        return

    sock_id: tuple = (
        dst_ip, packet_rx.tcp.dst,
        src_ip, packet_rx.tcp.src
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

