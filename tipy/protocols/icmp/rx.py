from __future__ import annotations

from struct import unpack_from

from tipy.protocols.icmp.parser import ICMPParser
from tipy.lib.csum import inet_csum
from tipy.lib.errno import Errno
from tipy.lib.logger import log
from tipy.protocols.icmp.icmp import (
    DESTINATION_UNREACHABLE,
    PORT_UNREACHABLE,
    PROTOCOL_UNREACHABLE,

    ECHO_REQUEST,
    ECHO_REPLY,
    ECHO_REQ_REP,  # Code=0
)

from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from tipy.components.core import Core
    from tipy.lib.packet import PacketRX
    from tipy.lib.inet import IPAddress


IP_PROTO_UDP = 17
IP_PROTO_TCP = 6

def _h_icmp_dest_unreach_port(self: Core, packet_rx: PacketRX):
    """
    handle : ICMP Type 3 (Destination Unreachable), Code 3 (Port Unreachable).
    """
    frame = packet_rx.icmp.err_data
    ip_ihl: int = (frame[0] & 0xF) * 4
    src_ip = IPAddress(unpack_from("!I", frame[12:16])[0])
    dst_ip = IPAddress(unpack_from("!I", frame[16:20])[0])
    protocol = frame[9]
    sock_id: tuple[int, int, int, int] = (
        src_ip.ip,  # local host
        unpack_from('! H', frame[ip_ihl:ip_ihl + 2])[0],  # local port
        dst_ip.ip,  # remote host
        unpack_from('! H', frame[ip_ihl + 2:ip_ihl + 4])[0] # remote port
    )

    if protocol == IP_PROTO_UDP:

        if sock_id in self.udp.sockets:
            self.udp.err_msg[sock_id] = Errno.ECONNREFUSED
            if __debug__:
                log("icmp", f"port unreachable, socket ID -> {sock_id}")

    # TODO: handle TCP also

    if __debug__:
        log(
            "icmp",
            f"destination unreachable (port): {sock_id}",
            level="INFO"
        )

def _h_icmp_dest_unreach_proto(self: Core, packet_rx: PacketRX):
    """
    handle : ICMP Type 3 (Destination Unreachable), Code 2 (Protocol Unreachable)
    """
    frame = packet_rx.icmp.err_data
    ip_ihl: int = (frame[0] & 0xF) * 4
    src_ip = IPAddress(unpack_from("!I", frame[12:16])[0])
    dst_ip = IPAddress(unpack_from("!I", frame[16:20])[0])
    protocol = frame[9]
    sock_id: tuple[int, int, int, int] = (
        src_ip.ip,  # local host
        unpack_from('! H', frame[ip_ihl:ip_ihl + 2])[0],  # local port
        dst_ip.ip,  # remote host
        unpack_from('! H', frame[ip_ihl + 2:ip_ihl + 4])[0]  # remote port
    )

    if protocol == IP_PROTO_UDP:

        if sock_id in self.udp.sockets:
            self.udp.err_msg[sock_id] = Errno.ENOPROTOOPT
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
        src=packet_rx.ip.dst,
        dst=packet_rx.ip.src,
        type_=ECHO_REPLY,
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

    rip_sock_id = (
        packet_rx.ip.dst.ip,
        packet_rx.ip.protocol,
        packet_rx.ip.src.ip
    )
    if rip_sock_id in self.rip.sockets:
        self.rip.sockets[rip_sock_id].get_data(packet_rx.frame)

    #TODO: try the sock_id with zeros as the last item in the tuple

icmp_map: dict[tuple[int, int], Callable[[Core, PacketRX], None]] = {

    (DESTINATION_UNREACHABLE, PORT_UNREACHABLE) : _h_icmp_dest_unreach_port,

    (DESTINATION_UNREACHABLE, PROTOCOL_UNREACHABLE) :_h_icmp_dest_unreach_proto,

    (ECHO_REQUEST, 0) : _h_icmp_echo_req,

    (ECHO_REPLY, 0) : _h_icmp_echo_rep

}

def rx_icmp(self: Core, packet_rx: PacketRX):
    """
    ICMP RX interface.

    1. Check if the ICMP header length is acceptable.
    2. Calculate the ICMP checksum.
    3. Dispatch the ICMP type/code to the corresponding handler.
    """
    l = len(packet_rx.frame)

    if l < 8:
        if __debug__:
            log(
                'icmp',
                f'[{packet_rx.tracker}] icmp header too short',
                "DEBUG"
            )
        return

    ICMPParser(packet_rx)
    if __debug__:
        log('icmp',
            f"{packet_rx.tracker} - {packet_rx.icmp}")

    if inet_csum(data=packet_rx.frame):
        if __debug__:
            log(
                'icmp',
                f'[{packet_rx.tracker}] icmp bad checksum.',
                "DEBUG"
            )
        return

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



