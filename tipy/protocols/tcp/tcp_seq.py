from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tipy.lib.packet import PacketRX

def seq_lt(a: int, b: int) -> bool:
    """
    True if 'a' is before 'b' in TCP sequence space.
    """
    #define SEQ_LT(a, b) (int)(a-b) < 0
    return (a - b) & 0xFF_FF_FF_FF > 0x7F_FF_FF_FF

def seq_leq(a: int, b: int) -> bool:
    """
    True if 'a' is before or equal 'b' in TCP sequence space.
    """
    #define SEQ_LEQ(a, b) (int)(a-b) <= 0
    return a == b or seq_lt(a, b)

def seq_gt(a: int, b: int) -> bool:
    """
    True if 'a' is after 'b' in TCP sequence space.
    """
    #define SEQ_GT(a, b) (int)(a-b) > 0
    return a != b and (a - b) & 0xFF_FF_FF_FF < 0x80_00_00_00

def seq_geq(a: int, b: int) -> bool:
    """
    True if 'a' is after or equal 'b' in TCP sequence space.
    """
    #define SEQ_GEQ(a, b) (int)(a-b) >= 0
    return a == b or seq_gt(a, b)

def seq_diff(a: int, b: int) -> int:
    """
    Return (a - b) in TCP sequence space.
    """
    return (a - b) & 0xFF_FF_FF_FF

def last_seq(packet_rx: PacketRX):
    """
    returns the last seq in this segment.
    """
    return (
            packet_rx.tcp.syn +
            packet_rx.tcp.fin +
            packet_rx.tcp.seq +
            packet_rx.tcp.dlen
    ) - bool(packet_rx.tcp.syn or packet_rx.tcp.fin or packet_rx.tcp.dlen)