from __future__ import annotations

from random import randint
from threading import RLock

from tipy.lib.buffer import RingBuffer
from tipy.protocols.tcp.tcp import STATES
from tipy.lib.ip_address import IPAddress


from typing import TYPE_CHECKING, Any
if TYPE_CHECKING:
    from tipy.components.timer import TimerTask
    from tipy.components.core import Core
    from threading import Condition


# TODO: Extract the buffers length and rcv_wnd from sock_opt
DEFAULT_RECV_BUFF    =   0xFFFF
DEFAULT_SEND_BUFF    =   0xFFFF

DEFAULT_RCV_WND      =   0xFFFF


def remove_tcpcb(tcpcb: TCPCB):
    """delete the tcpcb"""
    tcpcb.core.tcp.remove_socket(sock_id=tcpcb.socket_id)
    tcpcb.core.tcp.remove_tcpcb(sock_id=tcpcb.socket_id, tcpcb=tcpcb)

class TCPCB:
    """
    TCP Control Block (TCPCB)

    Concurrency model:
    - The event loop is the primary owner of the connection state.
    - A limited set of fields is shared with external threads.
    - Access to shared state is protected via `_tcpcb_lock`.

    See: docs/tcpcb_concurrency.md for full details.
    """

    __slots__ = (
        # core and core components
        "core",

        # addresses and ports
        "lip",
        "lp",
        "rip",
        "rp",
        "socket_id",

        # events
        "connect_events",
        "listen_events",
        "send_events",
        "recv_events",
        "close_events",
        "shutdown_wr_events",

        # lock
        "tcpcb_lock",

        # buffers and offsets
        "rcv_buf",
        "snd_buf",
        "rcv_w_buf_offset",
        "rcv_r_buf_offset",
        "snd_w_buf_offset",
        "snd_r_buf_offset",
        "snd_r_temp_buf_offset",

        # tcp segment helpers
        "tcp_data_start",
        "tcp_data_len",

        # state variables
        "snd_una",
        "snd_nxt",
        "snd_wnd",
        "snd_max",
        "snd_wl1",
        "snd_wl2",
        "rcv_nxt",
        "rcv_wnd",
        "rcv_adv",

        # sequence numbers
        "iss",
        "irs",

        # remote options
        "remote_mss",

        # helper flags
        "ack_now",
        "sent_fin",

        # timers
        "rtx_timer",
        "time_wait_timer",

        # application requests
        "close_requested",
        "shutdown_requested",

        # socket options
        "sock_opt",

        # state
        "state",
        "prev_state",
    )

    def __init__(self,
                 local_ip: IPAddress,
                 local_port: int,
                 remote_ip: IPAddress,
                 remote_port: int,
                 connect_events: Condition,
                 rcv_events: Condition,
                 send_events: Condition,
                 close_events: Condition,
                 sock_opt: dict[tuple, Any],
                 core: Core):

        self.core = core

        self.lip: IPAddress = local_ip
        self.lp: int = local_port

        self.rip: IPAddress = remote_ip
        self.rp: int = remote_port

        self.socket_id: tuple = (self.lip.ip_address,
                                  self.lp,
                                  self.rip.ip_address,
                                  self.rp)

        self.sock_opt: dict[tuple, Any] = sock_opt

        self.connect_events: Condition = connect_events
        self.listen_events: Condition
        self.send_events: Condition = send_events
        self.recv_events: Condition = rcv_events
        self.close_events: Condition = close_events
        self.shutdown_wr_events: Condition

        # tcpcb lock (rcv_wnd, rcv_adv, *_requested, state)
        self.tcpcb_lock: RLock = RLock()

        self.rcv_buf: RingBuffer = RingBuffer(size=DEFAULT_RECV_BUFF)
        self.snd_buf: RingBuffer = RingBuffer(size=DEFAULT_SEND_BUFF)

        self.rcv_w_buf_offset: int = 0 # rcv_buf write offset
        self.rcv_r_buf_offset: int = 0 # rcv_buf read offset

        self.snd_w_buf_offset: int = 0 # snd_buf write offset
        self.snd_r_buf_offset: int = 0 # snd_buf read offset

        # temporary read offset, used to virtually indicate the read offset
        # untile the TCB make sure that the sending data is acked
        # this offset must be used by the _drain_allowed_snd_buf() function
        self.snd_r_temp_buf_offset: int = 0

        # Define the offset and length of acceptable data within the segment.
        # Used when a segment partially overlaps the RCV.WND in order way
        # (e.g. starts before RCV.NXT but extends into the window).
        self.tcp_data_start: int = 0
        self.tcp_data_len: int = 0

        # state variables
        self.snd_una: int = 0
        self.snd_nxt: int = 0
        self.snd_wnd: int = 0
        self.snd_max: int = 0 # (max_seq_sent - 1), always advance

        self.snd_wl1: int = 0
        self.snd_wl2: int = 0

        self.rcv_nxt: int = 0
        self.rcv_wnd: int = DEFAULT_RCV_WND
        self.rcv_adv: int = 0

        self.iss: int = randint(0, 0xFF_FF_FF_FF)
        self.irs: int = 0

        self.remote_mss: int = 0

        # helper
        # ACKNOW: an ack must generated
        self.ack_now: bool = False
        # SENTFIN: we already send FIN
        self.sent_fin: bool = False

        # tcp connection timers
        self.rtx_timer: TimerTask | None = None
        self.time_wait_timer: TimerTask | None = None

        # Application requested connection close/shutdown.
        self.close_requested: bool = False
        self.shutdown_requested: bool = False

        self.state = STATES.CLOSED
        self.prev_state = self.state


    def __str__(self):
        return f"({self.lip}:{self.lp}, {self.rip}:{self.rp})"
