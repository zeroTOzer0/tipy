from __future__ import annotations

from enum import IntEnum
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from tipy.lib.packet import PacketRX
    from tipy.protocols.tcp.tcpcb import TCPCB


TCP_DOFF = 5
TCP_EOL_LEN = 1
TCP_NOP_LEN = 1
TCP_MSS_LEN = 4


TCP_EOL_KIND = 0
TCP_NOP_KIND = 1
TCP_MSS_KIND = 2

class STATES(IntEnum):
    LISTEN        =      0
    SYN_SENT      =      1
    SYN_RECV      =      2
    ESTAB         =      3
    FIN_WAIT_1    =      4
    FIN_WAIT_2    =      5
    CLOSE_WAIT    =      6
    CLOSING       =      7
    LAST_ACK      =      8
    TIME_WAIT     =      9
    CLOSED        =      10

    def __str__(self):
        return self.name

class TCPEventType(IntEnum):
    RX_SEGMENT  = 1  # prx_tcp
    CONNECT     = 2  # connect call
    SEND        = 3  # send call
    RTX         = 4  # schedule timer for the retransmission

    def __str__(self):
        return self.name

class TCPEvent:
    def __init__(self,
                 type_: TCPEventType,
                 tcpcb: TCPCB,
                 packet_rx: PacketRX|None=None,
                 ):
        self.type = type_
        self.tcpcb = tcpcb
        self.packet_rx = packet_rx

    def __str__(self):
        return (
            f"TCP Event, type: {self.type}, "
            f"{f"packet_rx: {self.packet_rx.tracker}" if self.packet_rx else ""}"
        )

NON_RECEIVABLE_STATES: set[int] = {STATES.CLOSE_WAIT,
                                   STATES.LAST_ACK,
                                   STATES.CLOSED,
                                   STATES.CLOSING,
                                   STATES.TIME_WAIT}

RECEIVABLE_STATES: set[int] = {STATES.ESTAB,
                               STATES.FIN_WAIT_1,
                               STATES.FIN_WAIT_2}