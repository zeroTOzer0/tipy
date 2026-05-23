from __future__ import annotations

from tipy.protocols.icmp.icmp import (
    DESTINATION_UNREACHABLE,
    PORT_UNREACHABLE,
    PROTOCOL_UNREACHABLE,

    ECHO_REQUEST,
    ECHO_REPLY,
    ECHO_REQ_REP # Code=0

)

from tipy.protocols.icmp.parser import ICMPParser
from tipy.lib.logger import log
from tipy.lib.ip_address import IPAddress
from tipy.lib.socket_errors import ConnectionRefusedError
import struct

from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from tipy.components.core import Core
    from tipy.lib.packet import PacketRX


IP_PROTO_UDP = 17
IP_PROTO_TCP = 6


def _h_icmp_dest_unreach_port(self: Core, packet_rx: PacketRX):
    """
    handle : ICMP Type 3 (Destination Unreachable), Code 3 (Port Unreachable).
    """
    frame = packet_rx.icmp.err_data
    ip_ihl: int = (frame[0] & 0xF) * 4
    src_ip = IPAddress(frame[12:16]).raw2ip()
    dst_ip = IPAddress(frame[16:20]).raw2ip()
    protocol = frame[9]
    sock_id: tuple[str, int, str, int] = (
        src_ip,  # local host
        struct.unpack('! H', frame[ip_ihl:ip_ihl + 2])[0],  # local port
        dst_ip,  # remote host
        struct.unpack('! H', frame[ip_ihl + 2:ip_ihl + 4])[0],  # remote port
    )

    if protocol == IP_PROTO_UDP:

        if sock_id in self.udp.sockets:
            self.udp.err_msg[sock_id] = ConnectionRefusedError('[Errno 111] Connection refused')
            if __debug__: log("icmp", f"port unreachable, socket ID -> {sock_id}")

    # TODO: handle TCP also

    if __debug__:
        log(
            "icmp",
            f"destination unreachable (port): {sock_id}",
            level="WARN"
        )



def _h_icmp_dest_unreach_proto(self: Core, packet_rx: PacketRX):
    """
    handle : ICMP Type 3 (Destination Unreachable), Code 2 (Protocol Unreachable)
    """
    frame = packet_rx.icmp.err_data
    ip_ihl: int = (frame[0] & 0xF) * 4
    src_ip = IPAddress(frame[12:16]).raw2ip()
    dst_ip = IPAddress(frame[16:20]).raw2ip()
    protocol = frame[9]
    sock_id: tuple[str, int, str, int] = (
        src_ip,  # local host
        struct.unpack('! H', frame[ip_ihl:ip_ihl + 2])[0],  # local port
        dst_ip,  # remote host
        struct.unpack('! H', frame[ip_ihl + 2:ip_ihl + 4])[0],  # remote port
    )

    if protocol == IP_PROTO_UDP:

        if sock_id in self.udp.sockets:
            self.udp.err_msg[sock_id] = OSError('[Errno 92] Protocol not available')
            if __debug__: log("icmp", f"protocol unreachable, socket ID -> {sock_id}")

    # TODO: handle TCP also

    if __debug__:
        log(
            "icmp",
            f"destination unreachable (protocol): {src_ip} -> {dst_ip}, proto={protocol}",
            level="WARN"
        )

def _h_icmp_echo_req(self: Core, packet_rx: PacketRX):
    """
    handle : ICMP Type 8 (echo request), Code 0
    """
    if __debug__:
        log(
            "icmp",
            f"[{packet_rx.tracker}] echo request from {packet_rx.ip.src}",
            level="INFO"
        )

    self.tx_icmp(
        src=IPAddress(packet_rx.ip.dst),
        dst=IPAddress(packet_rx.ip.src),
        type=ECHO_REPLY,
        code=ECHO_REQ_REP,
        data=packet_rx.icmp.echo_data,
        echo_id=packet_rx.icmp.echo_id,
        echo_seq=packet_rx.icmp.echo_seq,
        tracker=packet_rx.tracker

    )

def _h_icmp_echo_rep(self: Core, packet_rx: PacketRX):
    """
    handle : ICMP Type 0 (echo reply), Code 0
    """
    if __debug__:
        log(
            "icmp",
            f"[{packet_rx.tracker}] echo reply received from {packet_rx.ip.src}",
            level="INFO"
        )

    in_raw_sock_id = (
        packet_rx.ip.dst,
        packet_rx.ip.protocol,
        None
    )
    if in_raw_sock_id in self.raw_v4.sockets:
        self.raw_v4.sockets[in_raw_sock_id]\
        .get_data(packet_rx.icmp.packet)




icmp_map: dict[tuple[int, int], Callable[[Core, PacketRX], None]] = {

    (DESTINATION_UNREACHABLE, PORT_UNREACHABLE) : _h_icmp_dest_unreach_port,

    (DESTINATION_UNREACHABLE, PROTOCOL_UNREACHABLE) :_h_icmp_dest_unreach_proto,

    (ECHO_REQUEST, 0) : _h_icmp_echo_req,

    (ECHO_REPLY, 0) : _h_icmp_echo_rep

}

def rx_icmp(self: Core, packet_rx: PacketRX):
    ICMPParser(packet_rx)
    if __debug__: log('icmp', f"{packet_rx.tracker} - "
        f'{packet_rx.icmp}')


    handle_icmp = icmp_map.get(
        (packet_rx.icmp.type, packet_rx.icmp.code), None
    )
    if handle_icmp:
        handle_icmp(self, packet_rx)
    else:
        if __debug__: log('icmp',
                          f"Unsupported ICMP type={packet_rx.icmp.type} "
                          f"code={packet_rx.icmp.code} "
                          )



