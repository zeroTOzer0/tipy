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
    CLOSED        =      1
    LISTEN        =      2
    SYN_SENT      =      3
    SYN_RECV      =      4
    ESTAB         =      5
    FIN_WAIT_1    =      6
    FIN_WAIT_2    =      7
    CLOSE_WAIT    =      8
    CLOSING       =      9
    LAST_ACK      =      10
    TIME_WAIT     =      11

    def __str__(self):
        return self.name

class TCPEventType(IntEnum):
    RX_SEGMENT  = 1  # prx_tcp
    CONNECT     = 2  # connect call
    SEND        = 3  # send call
    TIMER       = 4  # schedule timer for the rex

    def __str__(self):
        return self.name

class TCPEvent:
    def __init__(self,
                 type_: TCPEventType,
                 tcpcb: TCPCB,
                 packet_rx: PacketRX|None=None,
                 data: memoryview|None=None,
                 call: Callable|None = None):

        self.call = call
        self.type = type_
        self.tcpcb = tcpcb
        self.packet_rx = packet_rx
        self.data = data

    def __str__(self):
        return (
            f"TCP Event, type: {self.type}, "
            f"{f"packet_rx: {self.packet_rx.tracker}" if self.packet_rx else ""}, "
            f"{f"dlen: {self.data}" if self.data else ""}"
        )

NON_RECEIVABLE_STATES: set[int] = {STATES.CLOSE_WAIT,
                                   STATES.LAST_ACK,
                                   STATES.CLOSED,
                                   STATES.CLOSING,
                                   STATES.TIME_WAIT}

RECEIVABLE_STATES: set[int] = {STATES.ESTAB,
                               STATES.FIN_WAIT_1,
                               STATES.FIN_WAIT_2}