from __future__ import annotations

from random import randint
from threading import RLock
from struct import pack

from tipy.lib.logger import log
from tipy.lib.ip_address import IPAddress
from tipy.protocols.tcp.builder import TCPOptMSS
from tipy.lib.socket import SOL_SOCKET, SO_LINGER

from tipy.protocols.tcp.tcp import (
    TCP_MSS_KIND,
    STATES,
    TCPEvent,
    TCPEventType,
    NON_RECEIVABLE_STATES,
    RECEIVABLE_STATES)

from typing import TYPE_CHECKING, Callable, Any

if TYPE_CHECKING:
    from threading import Condition
    from tipy.lib.packet import PacketRX
    from tipy.components.core import Core
    from tipy.components.timer import TimerTask


DEFAULT_RECV_BUFF    =   0xFFFF
DEFAULT_SEND_BUFF    =   0xFFFF

DEFAULT_RCV_WND      =   0xFFFF


TCP_ACCEPT_AND_HANDLE =  1
TCP_ACCEPT_BUT_BUFFER =  2
TCP_DROP              =  3

# max bytes can TCP transmit in one send routine call.
# Stop looping if the bytes transmitted exceeded TCP_MAX_TX_BYTES
# to let other TCP sockets to send its own data.
# TCPCB will automatically recall the appropriate send routine to send
# other remaining data.
TCP_MAX_TX_BYTES = 10000

# TODO: USE DYNAMIC RTO CALCULATIONS
RTX_TIMEOUT = 1.5

TIME_WAIT_TIMEOUT = 30

_SO_LINGER_ON = pack('ii', 1, 0)


def _seq_lt(a: int, b: int) -> bool:
    """
    True if 'a' is before 'b' in TCP sequence space.
    """
    #define SEQ_LT(a, b) (int)(a-b) < 0
    return (a - b) & 0xFF_FF_FF_FF > 0x7F_FF_FF_FF

def _seq_leq(a: int, b: int) -> bool:
    """
    True if 'a' is before or equal 'b' in TCP sequence space.
    """
    #define SEQ_LEQ(a, b) (int)(a-b) <= 0
    return a == b or _seq_lt(a, b)

def _seq_gt(a: int, b: int) -> bool:
    """
    True if 'a' is after 'b' in TCP sequence space.
    """
    #define SEQ_GT(a, b) (int)(a-b) > 0
    return a != b and (a - b) & 0xFF_FF_FF_FF < 0x80_00_00_00

def _seq_geq(a: int, b: int) -> bool:
    """
    True if 'a' is after or equal 'b' in TCP sequence space.
    """
    #define SEQ_GEQ(a, b) (int)(a-b) >= 0
    return a == b or _seq_gt(a, b)

def _seq_diff(a: int, b: int) -> int:
    """
    Return (a - b) in TCP sequence space.
    """
    return (a - b) & 0xFF_FF_FF_FF

def _last_seq(packet_rx: PacketRX):
    """
    returns the last seq in this segment.
    """
    return (
        packet_rx.tcp.syn +
        packet_rx.tcp.fin +
        packet_rx.tcp.seq +
        packet_rx.tcp.dlen
    ) - 1

def _write(_from: memoryview,
           from_start: int | None,
           from_end: int | None,
           into:  memoryview,
           into_start: int | None,
           into_end: int | None
    ):
    """
    copy data from buffer into another buffer
    """
    # [None:None] == [:]
    into[into_start:into_end] = _from[from_start:from_end]

def _do_segmentation(buf: list[memoryview], n: int) -> memoryview:
    """
    Consume up to `n` bytes from a buffer list (max length = 2).
    Returns a slice of data while mutating `buf` in-place to reflect
    the consumed bytes.
    """
    # NOTE: Do NOT advance sequence numbers (e.g., snd_nxt) or the remote window
    # by `n` directly.
    # When len(buf[0]) < n, fewer than `n` bytes may actually be consumed
    # from the current buffer segment. Advancing by `n` in such cases would
    # result in incorrect state updates.
    # Always advance protocol state using the length of the returned data,
    # not the requested size `n`.

    if len(buf[0]) <= n:
        data = buf[0]
        if len(buf) == 2:
            buf[0] = buf[1]
            buf.pop(1)
            return data
        buf.pop(0)
        return data

    data = buf[0][:n]
    buf[0] = buf[0][n:]
    return data


class TCPCB:
    """
    TCP Control Block (TCPCB)

    Concurrency model:
    - The event loop is the primary owner of the connection state.
    - A limited set of fields is shared with external threads.
    - Access to shared state is protected via `_tcpcb_lock`.

    See: docs/tcpcb_concurrency.md for full details.
    """

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

        self._lip: IPAddress = local_ip
        self._lp: int = local_port

        self._rip: IPAddress = remote_ip
        self._rp: int = remote_port

        self._socket_id: tuple = (self._lip.ip_address,
                                  self._lp,
                                  self._rip.ip_address,
                                  self._rp)

        self._sock_opt: dict[tuple, Any] = sock_opt

        self._connect_events: Condition = connect_events
        self._listen_events: Condition
        self._send_events: Condition = send_events
        self._recv_events: Condition = rcv_events
        self._close_events: Condition = close_events
        self._shutdown_wr_events: Condition

        # tcpcb lock (rcv_wnd, rcv_adv, *_requested, state)
        self._tcpcb_lock: RLock = RLock()

        self._rcv_buf: memoryview = memoryview(bytearray(DEFAULT_RECV_BUFF))
        self._snd_buf: memoryview = memoryview(bytearray(DEFAULT_SEND_BUFF))

        self._rcv_w_buf_offset: int = 0 # rcv_buf write offset
        self._rcv_r_buf_offset: int = 0 # rcv_buf read offset

        self._snd_w_buf_offset: int = 0 # snd_buf write offset
        self._snd_r_buf_offset: int = 0 # snd_buf read offset

        # temporary read offset, used to virtually indicate the read offset
        # untile the TCB make sure that the sending data is acked
        # this offset must be used by the _drain_allowed_snd_buf() function
        self._snd_r_temp_buf_offset: int = 0

        # Define the offset and length of acceptable data within the segment.
        # Used when a segment partially overlaps the RCV.WND in order way
        # (e.g. starts before RCV.NXT but extends into the window).
        self._tcp_data_start: int = 0
        self._tcp_data_len: int = 0

        # state variables
        self._snd_una: int = 0
        self._snd_nxt: int = 0
        self._snd_wnd: int = 0
        self._snd_max: int = 0 # (max_seq_sent - 1), always advance

        self._snd_wl1: int = 0
        self._snd_wl2: int = 0

        self._rcv_nxt: int = 0
        self._rcv_wnd: int = DEFAULT_RCV_WND
        self._rcv_adv: int = 0

        self._iss: int = randint(0, 0xFF_FF_FF_FF)
        self._irs: int = 0

        self._remote_mss: int = 0

        # helper
        self._ack_now: bool = False
        self._del_ack: bool = False

        # tcp connection timers
        self._rtx_timer: TimerTask | None = None
        self._time_wait_timer: TimerTask | None = None
        self._del_ack_timer: TimerTask | None = None
        self._persist_timer: TimerTask | None = None # FIXME: STATE NOT YET SUPPORTED

        # Application requested connection close/shutdown.
        self._close_requested: bool = False
        self._shutdown_requested: bool = False

        self._state = STATES.CLOSED
        self._prev_state = self._state

        self._tcp_rcv_states_map: dict[int, Callable] = {
            STATES.SYN_SENT   : self._tcp_rcv_syn_sent,
            STATES.ESTAB      : self._tcp_rcv_estab,
            STATES.CLOSE_WAIT : self._tcp_rcv_close_wait,
            STATES.LAST_ACK   : self._tcp_rcv_last_ack,

            STATES.FIN_WAIT_1 : self._tcp_rcv_fin_wait_1,
            STATES.FIN_WAIT_2 : self._tcp_rcv_fin_wait_2,
            STATES.CLOSING    : self._tcp_rcv_closing,
            STATES.TIME_WAIT  : self._tcp_rcv_time_wait

        }

        self._tcp_snd_states_map: dict[int, Callable] = {
            STATES.ESTAB      : self._tcp_snd_estab,
            STATES.CLOSE_WAIT : self._tcp_snd_close_wait,
            STATES.LAST_ACK   : self._tcp_snd_last_ack,

            STATES.FIN_WAIT_1: self._tcp_snd_fin_wait_1,
            STATES.FIN_WAIT_2: self._tcp_snd_fin_wait_2,
            STATES.CLOSING: self._tcp_snd_closing
        }

        # RFC 9293, Section 3.4: Sequence Numbers, page 19: receive section
        # Rows: (SEG.LEN > 0, RCV.WND > 0)
        # Cols: [0,0]=Zlen+Zwnd, [0,1]=Zlen, [1,0]=Zwnd, [1,1]=Normal
        self._h_rcv_seq_map: dict[tuple[bool, bool], Callable] = {
            (False, False )  : self._h_rcv_seq_zlen_zwnd,
            (False, True  )  : self._h_rcv_seq_zlen,
            (True,  False )  : self._h_rcv_seq_zwnd,
            (True,  True  )  : self._h_rcv_seq_normal
        }

    def __str__(self):
        return f"({self._lip}:{self._lp}, {self._rip}:{self._rp})"


    def tx(self):
        if __debug__:
            h = self._tcp_snd_states_map.get(self._state, None)

            log(
                'tcpcb',
                f'{self} TCP SND handler: "{h.__name__}"',
                level='DEBUG'
            )


        self._tcp_snd_states_map[self._state]()

    def rx(self, packet_rx: PacketRX):
        if __debug__:
            h = self._tcp_rcv_states_map.get(self._state, None)

            log(
                'tcpcb',
                f'{self} TCP RCV handler for [{packet_rx.tracker}]: "{h.__name__}"',
                level='DEBUG'
            )
        self._tcp_rcv_states_map[self._state](packet_rx)

    def retransmit(self):
        self._rollback_to_una()
        self._rtx_timer = None
        self.tx()

    def activ_open(self):
        if self._state == STATES.CLOSED:

            self.core.tx_tcp(
                local_ip=self._lip, remote_ip=self._rip,
                local_port=self._lp, remote_port=self._rp,
                seq=self._iss,
                syn=True,
                window=DEFAULT_RCV_WND,
                options=[TCPOptMSS()]
            )

            self._snd_una = self._iss
            # we sent only seg with syn flag so SEG.LEN = 1
            self._snd_nxt = (self._iss + 1) & 0xFF_FF_FF_FF
            self._snd_max = self._snd_nxt

            self._change_state(new=STATES.SYN_SENT)

    def _remove_tcpcb(self):
        """delete the tcpcb"""
        self.core.tcp.remove_socket(sock_id=self._socket_id)
        self.core.tcp.remove_tcpcb(sock_id=self._socket_id, tcpcb=self)

    def _change_state(self, new: int | None):
        if new is None:
            return

        self._prev_state = self._state
        self._state = new
        if __debug__:
            log(
                "tcpcb",
                f"{self}: state changed {self._prev_state} -> {self._state}",
                level="INFO"
            )

    def _stop_rtx_timer(self):
        if self._rtx_timer:
            self._rtx_timer.remove()
            self._rtx_timer = None

    def _stop_time_wait_timer(self):
        if self._time_wait_timer:
            self._time_wait_timer.remove()
            self._time_wait_timer = None

    def _stop_del_ack_timer(self):
        if self._del_ack_timer:
            self._del_ack_timer.remove()
            self._del_ack_timer = None

    def _stop_all_timers(self):
        self._stop_rtx_timer()
        self._stop_del_ack_timer()
        self._stop_time_wait_timer()

    def _rollback_to_una(self):
        """
        Rewind snd_r_temp_buf_offset to the last unacknowledged byte
        and reset snd_nxt to snd_una. This occurs during retransmission.
        """
        if __debug__:
            log(
                'tcpcb',
                f'rollback snd_nxt({self._snd_nxt}) to snd_una({self._snd_una}) '
                f'({_seq_diff(self._snd_nxt, self._snd_una)} unacked) on RTO',
                'DEBUG'
            )
        self._snd_r_temp_buf_offset = self._snd_r_buf_offset
        self._snd_nxt = self._snd_una

    def _start_rtx_timer(self):
        """
        start retransmission timer
        """
        if not self._rtx_timer:
            self._rtx_timer = self.core.timer.schedule_timer(
                expire_after=RTX_TIMEOUT,
                remove_at_execute=True,
                call=lambda: self.core.tcp_events_schedule.schedule_event(
                                event=TCPEvent(
                                type_=TCPEventType.RTX,
                                tcpcb=self
                                )
                            ),
                timer_name='tcp retransmission'
            )


    def _start_time_wait_timer(self):
        self._time_wait_timer = self.core.timer.schedule_timer(
            expire_after=TIME_WAIT_TIMEOUT,
            remove_at_execute=True,
            call=lambda: self._remove_tcpcb(),
            timer_name='time-wait'
        )

    def _send_ack(self, rcv_wnd):
        """
        Send an ACK-only TCP segment (no payload).
        Acknowledges received data and advertises the RCV.WND.
        """
        self.core.tx_tcp(
            local_ip=self._lip, remote_ip=self._rip,
            local_port=self._lp, remote_port=self._rp,
            seq=self._snd_nxt, ack_seq=self._rcv_nxt,
            ack=True,
            window=rcv_wnd,
        )

    def _send_fin(self, rcv_wnd):
        """
        Send a FIN+ACK segment (no payload).
        Initiates connection close while acknowledging pending data.
        """
        self.core.tx_tcp(
            local_ip=self._lip, remote_ip=self._rip,
            local_port=self._lp, remote_port=self._rp,
            seq=self._snd_nxt, ack_seq=self._rcv_nxt,
            ack=True, fin=True,
            window=rcv_wnd,
        )

    def _send_rst(self):
        """
        send RST
        """
        self.core.tx_tcp(
            local_ip=self._lip, remote_ip=self._rip,
            local_port=self._lp, remote_port=self._rp,
            seq=self._snd_nxt, ack_seq=self._rcv_nxt,
            ack=True, rst=True,
            window=0,
        )

    def _drop_with_reset(self, packet_rx: PacketRX):
        """
        Drop with RST. Challenge by seq if ACK set, else challenge by ack.
        """

        if packet_rx.tcp.ack:
            self.core.tx_tcp(
                local_ip=self._lip, remote_ip=self._rip,
                local_port=self._lp, remote_port=self._rp,
                seq=self._snd_nxt, ack_seq=0,
                rst=True,
                window=0,
            )
            return

        self.core.tx_tcp(
            local_ip=self._lip, remote_ip=self._rip,
            local_port=self._lp, remote_port=self._rp,
            seq=self._snd_nxt, ack_seq=self._rcv_nxt,
            ack=True, rst=True,
            window=0,
        )



    def _tcp_snd_loop(self,
                      *,
                      data: list[memoryview],
                      rcv_wnd: int,
                      next_state: int | None,  # next state if FIN occurs
                      shutdown_requested: bool=False,
                      close_requested: bool=False
                      ):
        """
        Send TCP data within the current send window.

        Segments `data` into chunks and transmits them while updating
        sequence numbers. Stops when all data is sent, the send window is full,
        or a TX limit is reached.

        If `shutdown_requested` or `close_requested` is set, a FIN is sent
        after the last data segment.
        """

        dlen = (
                len(data[0]) +
                (len(data[1]) if len(data) == 2 else 0)
        )

        snd_wnd = self._snd_wnd
        bytes_send_counter = 0

        if self._h_active_close_tx(close_requested=close_requested):
            return

        while dlen > 0:
            n = min(self._remote_mss, snd_wnd, dlen)
            seg_data = _do_segmentation(buf=data, n=n)
            seg_data_len = len(seg_data)
            should_fin = any((shutdown_requested, close_requested)) \
                         and not data

            self.core.tx_tcp(
                local_ip=self._lip, remote_ip=self._rip,
                local_port=self._lp, remote_port=self._rp,
                seq=self._snd_nxt, ack_seq=self._rcv_nxt,
                ack=True, psh=True, fin=should_fin,
                window=rcv_wnd,
                data=seg_data
            )

            self._snd_nxt = (self._snd_nxt + seg_data_len + should_fin) & 0xFF_FF_FF_FF
            # check if this is not a retransmission
            if _seq_gt(self._snd_nxt, self._snd_max):
                self._snd_max = self._snd_nxt

            dlen -= seg_data_len
            snd_wnd -= seg_data_len
            bytes_send_counter += seg_data_len

            # move on the temp_r_offset
            self._snd_r_temp_buf_offset = (
                    (self._snd_r_temp_buf_offset + seg_data_len) % len(self._snd_buf)
            )

            if should_fin:
                self._change_state(new=next_state)

            if snd_wnd <= 0:
                # TODO: RECHECK snd_wnd AND ENTER PERSIST STATE IF snd_wnd=0
                if __debug__:
                    log(
                        "tcpcb",
                        f"{self}: send window exhausted",
                        level="DEBUG"
                    )
                break

            if bytes_send_counter >= TCP_MAX_TX_BYTES:
                if __debug__:
                    log(
                        "tcpcb",
                        f"{self}: tx limit reached ({TCP_MAX_TX_BYTES} bytes), "
                        f"bytes_sent={bytes_send_counter}",
                        level="DEBUG"
                    )
                break

        self._start_rtx_timer()


    def _tcp_rcv_syn_sent(self,packet_rx: PacketRX):
        """
        Handle received segment when the TCP on the SYN_SENT State
        """
        # NOTE: no support yet for the Simultaneous Connection Synchronization

        if self._h_rcv_rst(packet_rx=packet_rx):
            return

        if packet_rx.tcp.fin:
            return  # FIXME

        if all((packet_rx.tcp.syn, packet_rx.tcp.ack)):

            if self._h_rcv_ack(packet_rx=packet_rx) > 0:

                self._irs = packet_rx.tcp.seq

                # Directly initialize SND.WND/WL1/WL2/RCV.NXT/RCV.ADV in SYN-SENT.
                # Using _h_rcv_wnd() here is unsafe because sequence/window state
                # is not yet synchronized and the function relies on chronologically
                # ordered SEQ/ACK checks.
                self._snd_wnd = packet_rx.tcp.window
                self._snd_wl1 = packet_rx.tcp.seq
                self._snd_wl2 = packet_rx.tcp.ack_seq

                self._rcv_nxt = (self._irs + 1) & 0xFF_FF_FF_FF
                self._rcv_adv: int = (self._rcv_nxt + self._rcv_wnd) \
                                     & 0xFF_FF_FF_FF # rcv_adv: the first seq not expected

                # extract the MSS, if no MSS options
                # exists use the default MSS: 536
                remote_mss = packet_rx.tcp.options.get(TCP_MSS_KIND, 536)
                self._remote_mss = remote_mss
                if __debug__:
                    log(
                        "tcpcb",
                        f"{self}: remote MSS = {self._remote_mss}",
                        level="INFO"
                    )

                self.core.tx_tcp(
                    local_ip=self._lip, remote_ip=self._rip,
                    local_port=self._lp, remote_port=self._rp,
                    seq=self._snd_una, ack_seq=self._rcv_nxt,
                    ack=True,
                    window=DEFAULT_RCV_WND,
                )

                self._change_state(new=STATES.ESTAB)

                with self._connect_events:
                    self._connect_events.notify()


    def _tcp_rcv_estab(self, packet_rx: PacketRX):
        """
        Handle received segment when the TCP on the ESTAB State
        """

        if packet_rx.tcp.dlen > 0\
        or packet_rx.tcp.fin:
            self._ack_now = True

        self._tcpcb_lock.acquire()
        decision = self._h_rcv_seq(packet_rx=packet_rx)
        if decision == TCP_ACCEPT_AND_HANDLE:

            if self._h_rcv_rst(packet_rx=packet_rx):
                self._tcpcb_lock.release()
                return

            # check if all our seq qre acked to stop timer
            if packet_rx.tcp.ack_seq == self._snd_nxt:
                self._stop_rtx_timer()

            seq_acked = self._h_rcv_ack(packet_rx)

            self._snd_r_buf_offset = (
                ( self._snd_r_buf_offset + (seq_acked - packet_rx.tcp.fin) )
                % len(self._snd_buf)
            ) # fin is not a payload

            self._h_rcv_wnd(packet_rx)

            self._tcpcb_lock.release()
            self._append_rcv_data(packet_rx=packet_rx)

            # enqueue_snd_data may be waiting for a signal to enqueue
            # remaining data if the given buffer is larger than available space.
            # Try to wake it up to enqueue the rest of the data, but first check
            # whether any sequence has been acknowledged; otherwise, ignore.
            if seq_acked > 0:
                with self._send_events:
                    self._send_events.notify()

            # check if the segment contains FIN and this FIN overlaps our window
            self._tcpcb_lock.acquire()
            if packet_rx.tcp.fin \
            and _seq_gt(self._rcv_adv, _last_seq(packet_rx=packet_rx)):
                self._change_state(new=STATES.CLOSE_WAIT)
                # application may block at the recv call, so notify
                # him to indicates the end of the remote's data
                with self._recv_events:
                    self._recv_events.notify()

            self._tcpcb_lock.release()

            self.core.tcp_events_schedule.schedule_event(
                event=TCPEvent(
                    type_=TCPEventType.SEND,
                    tcpcb=self
                )
            )

        elif decision == TCP_ACCEPT_BUT_BUFFER:
            # TODO: SUPPORT OOO SEGMENTS
            self._ack_now = True
            self.core.tcp_events_schedule.schedule_event(
                event=TCPEvent(
                    type_=TCPEventType.SEND,
                    tcpcb=self
                )
            )
            self._tcpcb_lock.release()
            return

        elif decision == TCP_DROP:
            self._ack_now = True
            self.core.tcp_events_schedule.schedule_event(
                event=TCPEvent(
                    type_=TCPEventType.SEND,
                    tcpcb=self
                )
            )
            self._tcpcb_lock.release()


    def _tcp_snd_estab(self):
        """
        Transmit available data and control flags when the TCP connection
        is in the ESTABLISHED state.
        """

        data = self._drain_allowed_snd_buf()

        with self._tcpcb_lock:
            shutdown_requested = self._shutdown_requested
            close_requested = self._close_requested
            rcv_wnd = self._rcv_wnd

        if not data:
            if self._h_active_close_tx(close_requested=close_requested):
                return

            if close_requested or shutdown_requested:
                if self._snd_wnd > 0:
                    # graceful connection closing
                    self._send_fin(rcv_wnd=rcv_wnd)

                    self._snd_nxt += 1
                    if _seq_gt(self._snd_nxt, self._snd_max):
                        self._snd_max += 1

                    self._change_state(new=STATES.FIN_WAIT_1)
                    self._ack_now = False
                    self._start_rtx_timer()

                    return

            if self._ack_now:
                self._send_ack(rcv_wnd=rcv_wnd)
                self._ack_now = False
                return

            return # no data, no ack should be sent. exit...

        self._tcp_snd_loop(data=data, rcv_wnd=rcv_wnd,
                           next_state=STATES.FIN_WAIT_1,
                           shutdown_requested=shutdown_requested,
                           close_requested=close_requested)


    def _tcp_rcv_close_wait(self, packet_rx: PacketRX):
        """
        Handle received segment when the TCP on the CLOSE_WAIT State
        """

        self._tcpcb_lock.acquire()
        decision = self._h_rcv_seq(packet_rx=packet_rx)
        if decision == TCP_ACCEPT_AND_HANDLE:

            if self._h_rcv_rst(packet_rx=packet_rx):
                self._tcpcb_lock.release()
                return

            seq_acked = self._h_rcv_ack(packet_rx)

            if packet_rx.tcp.ack_seq == self._snd_nxt:
                self._stop_rtx_timer()

            self._snd_r_buf_offset = (
                    (self._snd_r_buf_offset + (seq_acked - packet_rx.tcp.fin))
                    % len(self._snd_buf)
            )

            self._h_rcv_wnd(packet_rx)

            # enqueue_snd_data may be waiting for a signal.
            if seq_acked > 0:
                with self._send_events:
                    self._send_events.notify()


            self.core.tcp_events_schedule.schedule_event(
                event=TCPEvent(
                type_=TCPEventType.SEND,
                tcpcb=self
                )
            )
        self._tcpcb_lock.release()

    def _tcp_snd_close_wait(self):
        """
        Transmit available data and control flags when the TCP connection
        is in the CLOSE_WAIT state.
        """

        data = self._drain_allowed_snd_buf()

        with self._tcpcb_lock:
            shutdown_requested = self._shutdown_requested
            close_requested = self._close_requested
            rcv_wnd = self._rcv_wnd

        if not data:
            if close_requested:
                if self._h_active_close_tx(close_requested=close_requested):
                    return

            if close_requested or shutdown_requested:
                if self._snd_wnd > 0:
                    # graceful connection closing
                    self._send_fin(rcv_wnd=rcv_wnd)

                    self._snd_nxt += 1
                    if _seq_gt(self._snd_nxt, self._snd_max):
                        self._snd_max += 1

                    self._change_state(new=STATES.LAST_ACK)
                    self._ack_now = False
                    self._start_rtx_timer()

                    return

            if self._ack_now:
                self._send_ack(rcv_wnd=rcv_wnd)
                self._ack_now = False

            return # no data, exit...

        self._tcp_snd_loop(
            data=data, rcv_wnd=rcv_wnd,
            next_state=STATES.LAST_ACK,
            shutdown_requested=shutdown_requested,
            close_requested=close_requested
        )

    def _tcp_rcv_last_ack(self, packet_rx: PacketRX):
        """
        Handle received segment when the TCP on the LAST_ACK State
        """
        self._tcpcb_lock.acquire()
        decision = self._h_rcv_seq(packet_rx=packet_rx)
        if decision == TCP_ACCEPT_AND_HANDLE:

            if self._h_rcv_rst(packet_rx=packet_rx):
                self._tcpcb_lock.release()
                return

            seq_acked = self._h_rcv_ack(packet_rx)

            self._snd_r_buf_offset = (
                    (self._snd_r_buf_offset + (seq_acked - packet_rx.tcp.fin))
                    % len(self._snd_buf)
            )

            self._h_rcv_wnd(packet_rx)

            # check if all our seq including FIN are acked by the remote TCP
            if self._snd_una == self._snd_nxt:
                self._stop_rtx_timer()
                self._change_state(new=STATES.CLOSED)
                self._tcpcb_lock.release()
                self._remove_tcpcb()
                return


        # if the remote doesn't ack our data or/and FIN
        # the retransmission will resend automatically
        # so no need to schedule any send event
        self._tcpcb_lock.release()



    def _tcp_snd_last_ack(self):
        """
        Transmit available data and control flags when the TCP connection
        is in the LAST_ACK state.
        This routine executed by the retransmission
        """
        with self._tcpcb_lock:
            close_requested = self._close_requested

        data = self._drain_allowed_snd_buf()
        if not data:
            if self._h_active_close_tx(close_requested=close_requested):
                return

            # FIN should be retransmitted
            self._send_fin(rcv_wnd=self._rcv_wnd)
            self._snd_nxt += 1
            self._start_rtx_timer()
            return

        # data & FIN should be retransmitted
        self._tcp_snd_loop(
            data=data, rcv_wnd=self._rcv_wnd,
            next_state=None,
            shutdown_requested=True,
            close_requested=True
        )

    def _tcp_rcv_fin_wait_1(self, packet_rx: PacketRX):
        """
        Handle received segment when the TCP on the FIN_WAIT_1 State
        """

        # NOTE: No send scheduling here. Only immediate ACKs are sent.
        # Retransmissions are handled by the timer, which invokes
        # _tcp_snd_fin_wait_1 to resend unacknowledged data/FIN.

        if packet_rx.tcp.dlen > 0\
        or packet_rx.tcp.fin:
            self._ack_now = True

        self._tcpcb_lock.acquire()
        rcv_wnd = self._rcv_wnd
        decision = self._h_rcv_seq(packet_rx=packet_rx)
        if decision == TCP_ACCEPT_AND_HANDLE:

            if self._h_rcv_rst(packet_rx=packet_rx):
                self._tcpcb_lock.release()
                return

            if not self._h_active_close_rx(packet_rx=packet_rx):
                return

            # check if all our seq including FIN are acked by the remote TCP
            if packet_rx.tcp.ack_seq == self._snd_nxt:
                self._stop_rtx_timer()

                # check if this segment contains a FIN and
                # the FIN overlaps our window, if yes go to TIME_WAIT
                # otherwise go to FIN_WAIT_2
                if packet_rx.tcp.fin \
                and _seq_gt(self._rcv_adv, _last_seq(packet_rx=packet_rx)):
                    self._change_state(new=STATES.TIME_WAIT)
                    self._start_time_wait_timer()

                else:
                    self._change_state(new=STATES.FIN_WAIT_2)

            # our FIN not acked yet, so check if the segment
            # contains a FIN and this FIN overlaps our window
            # if yes go to CLOSING state
            elif packet_rx.tcp.fin \
            and _seq_gt(self._rcv_adv, _last_seq(packet_rx=packet_rx)):
                self._change_state(new=STATES.CLOSING)

            self._tcpcb_lock.release()
            self._append_rcv_data(packet_rx=packet_rx)

            seq_acked = self._h_rcv_ack(packet_rx)

            self._snd_r_buf_offset = (
                    (self._snd_r_buf_offset + (seq_acked - packet_rx.tcp.fin))
                    % len(self._snd_buf)
            )

            self._h_rcv_wnd(packet_rx)

            if self._ack_now:
                self._send_ack(rcv_wnd=rcv_wnd)

        elif decision == TCP_ACCEPT_BUT_BUFFER:
            self._tcpcb_lock.release()
            if self._ack_now:
                self._send_ack(rcv_wnd=rcv_wnd)

        elif decision == TCP_DROP:
            self._tcpcb_lock.release()
            if self._ack_now:
                self._send_ack(rcv_wnd=rcv_wnd)


    def _tcp_snd_fin_wait_1(self):
        """
        Transmit any unacknowledged data and control flags in FIN-WAIT-1.
        This routine is triggered only by the retransmission timer.
        """
        if self._rtx_timer:
            return

        with self._tcpcb_lock:
            rcv_wnd = self._rcv_wnd
            close_requested = self._close_requested

        data = self._drain_allowed_snd_buf()
        if not data:

            if self._h_active_close_tx(close_requested=close_requested):
                return

            if self._snd_wnd > 0:
                # FIN should be retransmitted
                self._send_fin(rcv_wnd=rcv_wnd)

                self._snd_nxt += 1
                self._start_rtx_timer()

                return

        # data & FIN should be retransmitted
        self._tcp_snd_loop(
            data=data, rcv_wnd=rcv_wnd,
            next_state=None,
            shutdown_requested=True,
            close_requested=True
        )

    def _tcp_rcv_fin_wait_2(self, packet_rx: PacketRX):
        """
        Handle received segment when TCP is in FIN_WAIT_2 state.
        """
        # NOTE: FIN_WAIT_2 is receive-only; only ACKs are sent.
        # No data transmission/retransmission path exists, so
        # _tcp_snd_fin_wait_2 function is not needed.

        self._tcpcb_lock.acquire()
        rcv_wnd = self._rcv_wnd
        decision = self._h_rcv_seq(packet_rx=packet_rx)
        if decision == TCP_ACCEPT_AND_HANDLE:

            if self._h_rcv_rst(packet_rx=packet_rx):
                self._tcpcb_lock.release()
                return

            if not self._h_active_close_rx(packet_rx=packet_rx):
                return

            # FIN_WAIT_2: ACK/SND.WND handled for protocol compliance (no further sending)
            _ = self._h_rcv_ack(packet_rx=packet_rx)
            self._h_rcv_wnd(packet_rx=packet_rx)

            # check if this segment contains FIN and this FIN
            # overlaps our window. if yes go to TIME_WAIT state
            if packet_rx.tcp.fin\
            and _seq_gt(self._rcv_adv, _last_seq(packet_rx=packet_rx)):
                self._change_state(new=STATES.TIME_WAIT)
                self._start_time_wait_timer()

            self._tcpcb_lock.release()
            self._append_rcv_data(packet_rx=packet_rx)
            self._send_ack(rcv_wnd=rcv_wnd)

        elif decision == TCP_ACCEPT_BUT_BUFFER:
            self._tcpcb_lock.release()
            self._send_ack(rcv_wnd=rcv_wnd)

        elif decision == TCP_DROP:
            self._tcpcb_lock.release()
            self._send_ack(rcv_wnd=rcv_wnd)

    def _tcp_snd_fin_wait_2(self):
        with self._tcpcb_lock:
            close_requested = self._close_requested
        self._h_active_close_tx(close_requested=close_requested)


    def _tcp_rcv_closing(self, packet_rx: PacketRX):
        """
        Handle received segment when the TCP on the CLOSING State
        """

        self._tcpcb_lock.acquire()
        decision = self._h_rcv_seq(packet_rx=packet_rx)
        if decision == TCP_ACCEPT_AND_HANDLE:

            if self._h_rcv_rst(packet_rx=packet_rx):
                self._tcpcb_lock.release()
                return

            if not self._h_active_close_rx(packet_rx=packet_rx):
                return

            seq_acked = self._h_rcv_ack(packet_rx)
            self._h_rcv_wnd(packet_rx)

            self._snd_r_buf_offset = (
                    (self._snd_r_buf_offset + (seq_acked - packet_rx.tcp.fin))
                    % len(self._snd_buf)
            )  # fin is not a payload

            # check if our FIN is acked so that we can
            # go to TIME_WAIT state
            if self._snd_una == self._snd_nxt:
                self._stop_rtx_timer()
                self._change_state(new=STATES.TIME_WAIT)
                self._start_time_wait_timer()
                return

            self._tcpcb_lock.release()
            self.core.tcp_events_schedule.schedule_event(
                event=TCPEvent(
                    type_=TCPEventType.SEND,
                    tcpcb=self
                )
            )

        elif decision == TCP_ACCEPT_BUT_BUFFER:
            self._tcpcb_lock.release()
            self.core.tcp_events_schedule.schedule_event(
                event=TCPEvent(
                    type_=TCPEventType.SEND,
                    tcpcb=self
                )
            )

        elif decision == TCP_DROP:
            self._tcpcb_lock.release()
            self.core.tcp_events_schedule.schedule_event(
                event=TCPEvent(
                    type_=TCPEventType.SEND,
                    tcpcb=self
                )
            )

    def _tcp_snd_closing(self):
        """
        Transmit any unacknowledged data and control flags in FIN-WAIT-1.
        This routine is triggered only by the retransmission timer.
        """

        with self._tcpcb_lock:
            close_requested = self._close_requested

        data = self._drain_allowed_snd_buf()
        if not data:
            if self._h_active_close_tx(close_requested=close_requested):
                return

            if self._snd_wnd > 0:
                # FIN should be retransmitted
                self._send_fin(rcv_wnd=self._rcv_wnd)

                self._snd_nxt += 1
                self._start_rtx_timer()

                return
        # data & FIN should be retransmitted
        self._tcp_snd_loop(
            data=data, rcv_wnd=self._rcv_wnd,
            next_state=None,
            shutdown_requested=True,
            close_requested=True
        )

    def _tcp_rcv_time_wait(self, packet_rx: PacketRX):
        """
        Handle received segment when the TCP on the TIME_WAIT State
        """
        if packet_rx.tcp.fin\
        or packet_rx.tcp.dlen:
            self._send_ack(rcv_wnd=self._rcv_wnd)

        self._stop_time_wait_timer()
        self._start_time_wait_timer()


    def _h_rcv_ack(self, packet_rx: PacketRX) -> int:
        """
        Handle incoming ack info.
        Verify that SND.UNA < SEG.ACK <= SND.NXT
        Affect the SND.UNA variable
        Returns number of sequence numbers acked
        """

        # The following two conditions separate the formula:
        # SND.UNA < SEG.ACK =< SND.NXT into two parts
        # The first condition is : SND.UNA < SEG.ACK
        # The second condition is : SEG.ACK =< SND.NXT
        if _seq_leq(packet_rx.tcp.ack_seq, self._snd_una)\
        or _seq_gt(packet_rx.tcp.ack_seq, self._snd_nxt):
            if __debug__:

                if _seq_leq(packet_rx.tcp.ack_seq, self._snd_una):
                    msg = (
                        f"{self}: old ACK (ignored), ACK={packet_rx.tcp.ack_seq} "
                        f"< SND.UNA={self._snd_una}"
                    )
                    log(
                        "tcpcb",
                        msg,
                        level="DEBUG"
                    )

                elif _seq_gt(packet_rx.tcp.ack_seq, self._snd_nxt):
                    msg = (f"{self}: invalid ACK, ACK={packet_rx.tcp.ack_seq} "
                           f"> SND.NXT={self._snd_una}")

                    log("tcpcb", msg, level="WARN")

            return 0

        old_snd_una = self._snd_una
        if __debug__:
            acked_bytes = _seq_diff(packet_rx.tcp.ack_seq, old_snd_una)

            log(
                "tcpcb",
                (
                    f"{self}: ACK accepted "
                    f"(UNA={old_snd_una} < ACK={packet_rx.tcp.ack_seq} <= SND.NXT={self._snd_nxt}), "
                    f"acked_bytes={acked_bytes}"
                ),
                level="INFO"
            )

        self._snd_una = packet_rx.tcp.ack_seq
        return _seq_diff(packet_rx.tcp.ack_seq, old_snd_una)

    def _h_rcv_wnd(self, packet_rx: PacketRX) -> bool:
        """
        Handle incoming window info
        Verify if SEG.SEQ > SND.WL1 or (SEG.SEQ == SND.WL1 and SEG.ACK > SND.WL2)
        (Affect the SND.WND/SND.WL1/SND.WL2 variables)
        """
        # The following condition check the formula:
        # SEG.SEQ > SND.WL1 or SEG.SEQ == SND.WL1 and SEG.ACK > SND.WL2

        if _seq_lt(self._snd_wl1, packet_rx.tcp.seq) \
        or packet_rx.tcp.seq == self._snd_wl1 \
        and _seq_lt(self._snd_wl2, packet_rx.tcp.ack_seq):
            self._snd_wl1 = packet_rx.tcp.seq
            self._snd_wl2 = packet_rx.tcp.ack_seq
            self._snd_wnd = packet_rx.tcp.window
            if __debug__:
                log(
                    "tcpcb",
                    f"{self}: SND.WND updated (WL1={self._snd_wl1}, "
                    f"WL2={self._snd_wl2}, WND={self._snd_wnd})",
                    level="INFO"
                )
            return True
        return False


    def _h_rcv_seq_zlen_zwnd(self, packet_rx: PacketRX) -> int:
        """
        SEG.LEN = 0 & RCV.WND = 0
        Only acceptable if SEG.SEQ == RCV.NXT.
        Returns TCP_ACCEPT_AND_HANDLE if segment is acceptable
        TCP_DROP otherwise.
        """

        if __debug__:
            seq = packet_rx.tcp.seq
            accept = (seq == self._rcv_nxt)
            action = "ACCEPT" if accept else "DROP"

            log(
                "tcpcb",
                f"{self}: zero-len + zero-window "
                f"(SEQ={seq}, RCV.NXT={self._rcv_nxt}) -> {action}",
                level="DEBUG"
            )

        if packet_rx.tcp.seq == self._rcv_nxt:
            return TCP_ACCEPT_AND_HANDLE

        return TCP_DROP

    def _h_rcv_seq_zlen(self, packet_rx: PacketRX) -> int:
        """
        SEG.LEN = 0 & RCV.WND > 0
        Acceptable if SEG.SEQ lies within the RCV.WND.
        Returns TCP_ACCEPT_AND_HANDLE if segment is acceptable,
        TCP_DROP otherwise.
        """

        if __debug__:
            seq = packet_rx.tcp.seq

            in_window = (
                    _seq_leq(self._rcv_nxt, seq)
                    and _seq_lt(seq, self._rcv_adv)
            )

            action = "ACCEPT" if in_window else "DROP"

            log(
                "tcpcb",
                f"{self}: zero-length segment "
                f"(SEQ={seq}, RCV.NXT={self._rcv_nxt}, RCV.MAX={self._rcv_adv}) "
                f"-> {action}",
                level="DEBUG"
            )

        if _seq_leq(self._rcv_nxt, packet_rx.tcp.seq)\
        and _seq_lt(packet_rx.tcp.seq, self._rcv_adv):
            return TCP_ACCEPT_AND_HANDLE

        return TCP_DROP


    def _h_rcv_seq_zwnd(self, packet_rx: PacketRX) -> int:
        """
        SEG.LEN > 0 & RCV.WND = 0
        NEVER acceptable. Receiver just drop.
        Returns TCP_DROP unconditionally.
        """

        if __debug__:
            length = packet_rx.tcp.dlen + packet_rx.tcp.fin + packet_rx.tcp.syn
            log(
                "tcpcb",
                f"{self}: zero-window drop "
                f"(SEQ={packet_rx.tcp.seq}, LEN={length}, RCV.NXT={self._rcv_nxt})",
                level="INFO"
            )

        return TCP_DROP

    def _h_rcv_seq_normal(self, packet_rx: PacketRX) -> int:
        """
        Verify that the segment overlaps the RCV.WND:
        RCV.NXT <= SEG.SEQ <= RCV.NXT + RCV.WND
        or
        RCV.NXT <= SEG.SEQ + SEG.LEN - 1 <= RCV.NXT + RCV.WND
        Update RCV.NXT when applicable and compute the offset and
        length of the acceptable data within the segment
        (_tcp_data_start and _tcp_data_len).
        Returns TCP_ACCEPT_AND_HANDLE for acceptable in-order data.
        Returns TCP_ACCEPT_AND_BUFFER for acceptable out-of-order segments.
        TCP_DROP otherwise.
        """
        # NOTE: returned TCP_ACCEPT_BUT_BUFFER means ooo but not yet supported

        # check if this is an in-order segment
        if _seq_leq(packet_rx.tcp.seq, self._rcv_nxt) \
        and _seq_leq(self._rcv_nxt, _last_seq(packet_rx)):

            old_rcv_nxt = self._rcv_nxt

            new_rcv_nxt = (
                (_last_seq(packet_rx) + 1) & 0xFF_FF_FF_FF
                if _seq_lt(_last_seq(packet_rx), self._rcv_adv)
                else self._rcv_adv
            )
            # calculate the start & end of the acceptable segment's data
            self._tcp_data_start = _seq_diff(old_rcv_nxt, packet_rx.tcp.seq)
            self._tcp_data_len = _seq_diff(new_rcv_nxt, old_rcv_nxt)

            # if the segment contain FIN flags
            # trim it from the calculation of
            # the acceptable data length
            self._tcp_data_len -= packet_rx.tcp.fin

            self._rcv_nxt = new_rcv_nxt

            if __debug__:
                seq = packet_rx.tcp.seq
                last_seq = _last_seq(packet_rx)

                log(
                    "tcpcb",
                    (
                        f"{self}: in-order segment "
                        f"(SEQ={seq}, RCV.NXT={old_rcv_nxt}, LAST_SEQ={last_seq}), "
                        f"data_range=[{self._tcp_data_start}:{self._tcp_data_len}]"
                    ),
                    level="DEBUG"
                )

            return TCP_ACCEPT_AND_HANDLE

        # check if this is an ooo segment
        if not _seq_leq(packet_rx.tcp.seq, self._rcv_nxt) \
        and _seq_lt(packet_rx.tcp.seq, self._rcv_adv):
            if __debug__:
                seq = packet_rx.tcp.seq

                log(
                    "tcpcb",
                    f"{self}: out-of-order segment "
                    f"(RCV.NXT={self._rcv_nxt}, SEQ={seq}, RCV.ADV={self._rcv_adv})",
                    level="DEBUG"
                )
            return TCP_ACCEPT_BUT_BUFFER

        return TCP_DROP

    def _h_rcv_seq(self, packet_rx: PacketRX) -> int:
        """
        Dispatch segment acceptance per RFC 9293 Table.
        """
        has_data = bool(packet_rx.tcp.dlen +
                        packet_rx.tcp.syn  +
                        packet_rx.tcp.fin)
        return self._h_rcv_seq_map[(has_data, bool(self._rcv_wnd))](packet_rx)


    def _h_rcv_rst(self, packet_rx: PacketRX) -> bool:
        """
        handle rcv RST. return False if no RST presents
        otherwise go to CLOSED state and delete TCPCB
        """
        if not packet_rx.tcp.rst:
            return False

        if __debug__:
            log(
                'tcpcb',
                f'{self} rcv RST',
                level='ERROR'
            )

        self._change_state(new=STATES.CLOSED)
        self._stop_all_timers()
        self._remove_tcpcb()
        return True

    def _h_active_close_tx(self, close_requested: bool) -> bool:
        """
        Handle tx path when an active close invoked.
        Returns True if connection aborted (RST sent), False if normal closure can proceed.
        """

        if close_requested\
        and self._sock_opt.get((SOL_SOCKET, SO_LINGER), None) == _SO_LINGER_ON:
            self._stop_all_timers()
            self._send_rst()
            self._change_state(new=STATES.CLOSED)
            self._remove_tcpcb()
            return True

        return False


    def _h_active_close_rx(self, packet_rx: PacketRX) -> bool:
        """
        Handle rx segments when an active close invoked.
        Returns True if graceful closure can continue.
        False if RST was sent and connection aborted.
        """

        if self._close_requested:
            if packet_rx.tcp.dlen:
                self._stop_all_timers()
                self._drop_with_reset(packet_rx=packet_rx)
                self._change_state(new=STATES.CLOSED)
                self._remove_tcpcb()
                return False

            return True

        if self._shutdown_requested:
            return True

        return True



    def _append_rcv_data(self, packet_rx: PacketRX):
        """
        Append incoming segment payload to the rcv_buf.
        Notifies the application (socket.recv()) when data is ready.
        """
        # Note: Release the lock before calling this routine.
        # _append_rcv_data will acquire the lock again, but
        # only briefly to read/modify the necessary variables and
        # release it while copying rcv_data into rcv_buf.

        # Note: Handles segments with data larger than local window.
        # The appropriate ACK is managed in _h_rcv_seq() which assumes
        # this function only enqueues acceptable data. This function
        # ignores portions exceeding the window (left/right) using
        # _tcp_data_start/_tcp_data_len vars.


        with self._tcpcb_lock:
            rcv_wnd = self._rcv_wnd
            rcv_w_buf_offset = self._rcv_w_buf_offset

        if rcv_wnd == 0:
            return

        if packet_rx.tcp.data:

            # Check if there is enough space in the rcv buffer
            # to store the entire acceptable TCP segment,
            # either in a contiguous block or wrapped around the buffer.
            if rcv_wnd >= self._tcp_data_len:

                # Check if the data fits contiguously from the current write offset.
                # If (write_offset + data length) <= buffer size, we can write without wrapping.
                if (rcv_w_buf_offset + (self._tcp_data_len-self._tcp_data_start)) \
                    <= len(self._rcv_buf):
                    if __debug__:
                        start = rcv_w_buf_offset
                        length = self._tcp_data_len - self._tcp_data_start
                        end = start + length

                        log(
                            "tcpcb",
                            f"{self}: copy into rcv_buf [{start}:{end}]",
                            level="DEBUG"
                        )

                    _write(
                        _from=packet_rx.tcp.data,
                        from_start=self._tcp_data_start,
                        from_end=self._tcp_data_len,
                        into=self._rcv_buf,
                        into_start=rcv_w_buf_offset,
                        into_end=rcv_w_buf_offset+(self._tcp_data_len-self._tcp_data_start)
                    )

                    with self._tcpcb_lock:
                        # Move on the write_offset
                        self._rcv_w_buf_offset = (self._rcv_w_buf_offset
                                                 + (self._tcp_data_len-self._tcp_data_start)
                                                  ) % \
                                                 len(self._rcv_buf)

                        if __debug__:
                            consumed = self._tcp_data_len
                            old_wnd = self._rcv_wnd
                            new_wnd = old_wnd - consumed

                            log(
                                "tcpcb",
                                f"{self}: rcv_wnd reduced {old_wnd} -> {new_wnd}",
                                level="INFO"
                            )

                        # reduce RCV.WND
                        self._rcv_wnd -= self._tcp_data_len

                    with self._recv_events:
                        self._recv_events.notify()

                    return

                # If (write_offset + data length) > buffer size, part of the data
                # will wrap around. so write from write_offset to end of rcv_buf,
                # then continue from the start of the buffer for the remaining bytes.
                if (rcv_w_buf_offset + (self._tcp_data_len-self._tcp_data_start)) \
                    > len(self._rcv_buf):
                    if __debug__:
                        buf_len = len(self._rcv_buf)
                        start = rcv_w_buf_offset
                        second_part = start

                        log(
                            "tcpcb",
                            f"{self}: copy into rcv_buf "
                            f"[{start}:{buf_len}] & [0:{second_part}]",
                            level="DEBUG"
                        )

                    # Write first portion
                    _write(
                        _from=packet_rx.tcp.data,
                        from_start=self._tcp_data_start,
                        from_end=len(self._rcv_buf)-rcv_w_buf_offset,
                        into=self._rcv_buf,
                        into_start=rcv_w_buf_offset,
                        into_end=None
                    )

                    # Write second portion
                    _write(
                        _from=packet_rx.tcp.data,
                        from_start=len(self._rcv_buf)-rcv_w_buf_offset,
                        from_end=self._tcp_data_len,
                        into=self._rcv_buf,
                        into_start=0,
                        into_end=self._tcp_data_len-self._tcp_data_start-\
                                 (len(self._rcv_buf)-rcv_w_buf_offset)
                    )

                    with self._tcpcb_lock:
                        # Move on the write_offset
                        self._rcv_w_buf_offset = (self._rcv_w_buf_offset
                                                  + self._tcp_data_len) % \
                                                 len(self._rcv_buf)

                        if __debug__:
                            consumed = packet_rx.tcp.dlen
                            old_wnd = self._rcv_wnd
                            new_wnd = old_wnd - consumed

                            log(
                                "tcpcb",
                                f"{self}: rcv_wnd reduced {old_wnd} -> {new_wnd} (consumed={consumed})",
                                level="INFO"
                            )

                        # reduce RCV.WND
                        self._rcv_wnd -= self._tcp_data_len

                    with self._recv_events:
                        self._recv_events.notify()

                    return

    def _drain_allowed_snd_buf(self) -> list[memoryview]:
        """
        Drain all allowed available data from the TCP send buffer (snd_buf),
        based on the remote window (SND.WND).
        If the ready data is less than the SND.WND, then drain all the buffer,
        otherwise drain only the permitted data .
        This routine is using the temp r_offset to deal with the buffer.
        Note that the maximum len of the returned list is 2
        """
        # NOTE1: sending routines only the permitted function that can call
        # this function

        # NOTE2: Since this function uses temp_r_offset, it does not advance it.
        # It only uses it to determine how much and from where data should be read.
        # Advancing temp_r_offset is the responsibility of the send routines.
        # Each time they send a segment, they advance temp_r_offset by the number of bytes transmitted
        # (FIN/SYN bytes are not included).

        with self._tcpcb_lock:
            snd_w_buf_offset = self._snd_w_buf_offset

        if self._snd_wnd ==  0:
            return []

        ready = ((snd_w_buf_offset - self._snd_r_temp_buf_offset)
                 % len(self._snd_buf))
        data = []

        # check if we can drain all ready data from the buffer
        if ready <= self._snd_wnd:
            # Contiguous region (no wrap-around).
            if self._snd_r_temp_buf_offset < snd_w_buf_offset:

                if __debug__:
                    start = self._snd_r_temp_buf_offset
                    end = snd_w_buf_offset

                    log(
                        "tcpcb",
                        f"{self}: drain snd_buf [{start}:{end}] (ready for send)",
                        level="DEBUG"
                    )

                data.append(self._snd_buf[self._snd_r_temp_buf_offset:snd_w_buf_offset])


            elif self._snd_r_temp_buf_offset > snd_w_buf_offset:

                if __debug__:
                    start = self._snd_r_temp_buf_offset

                    if snd_w_buf_offset != 0:
                        end_part = f"[0:{snd_w_buf_offset}]"
                        main_part = f"[{start}:]"
                        range_str = f"{main_part} & {end_part}"
                    else:
                        range_str = f"[{start}:]"

                    log(
                        "tcpcb",
                        f"{self}: drain snd_buf {range_str}",
                        level="DEBUG"
                    )

                data.append(self._snd_buf[self._snd_r_temp_buf_offset:])

                data.append(self._snd_buf[0:snd_w_buf_offset]) \
                    if snd_w_buf_offset != 0 else None

            return data


        ready = self._snd_wnd

        # check if we can just drain the allowed data in contiguously way
        if ready <= (len(self._snd_buf) - self._snd_r_temp_buf_offset):

            if __debug__:
                start = self._snd_r_temp_buf_offset
                end = start + ready

                log(
                    "tcpcb",
                    f"{self}: drain snd_buf [{start}:{end}] ({ready} bytes ready)",
                    level="DEBUG"
                )

            data.append(
                self._snd_buf[self._snd_r_temp_buf_offset
                              :self._snd_r_temp_buf_offset + ready]
            )

            return data

        # otherwise, drain from r_temp_offset until the end and
        # drain from start up to the remaining allowed bytes
        if __debug__:
            buf_len = len(self._snd_buf)
            start = self._snd_r_temp_buf_offset

            first_part = buf_len - start
            second_part = ready - first_part

            log(
                "tcpcb",
                f"{self}: drain snd_buf [{start}:{buf_len}] & [0:{second_part}] ({ready} bytes)",
                level="DEBUG"
            )
        data.append(self._snd_buf[self._snd_r_temp_buf_offset:])
        data.append(self._snd_buf[:ready - (len(self._snd_buf) - self._snd_r_temp_buf_offset)
                                  % len(self._snd_buf)])


        return data



    def tcp_recv(self, bufsize: int) -> list[memoryview]:
        """
        Dequeue up to `bufsize` bytes from the rcv buffer.
        Returns available data as one or more memoryview slices if wrapping occurs.
        Updates read offset (_rcv_r_buf_offset) and receive window (_rcv_wnd/_rcv_max).
        Limits read to available data if requested bufsize exceeds it.
        """

        if self._state in NON_RECEIVABLE_STATES:
            return []

        with self._tcpcb_lock:
            rcv_wnd = self._rcv_wnd

        with self._recv_events:
            if len(self._rcv_buf) == rcv_wnd:
                # no data in rcv_buf, wait...
                self._recv_events.wait()

        # retake a generale snapshot, because we get notified
        # by the _enqueue routine so the rcv states may be modified
        with self._tcpcb_lock:
            rcv_wnd = self._rcv_wnd
            rcv_w_buf_offset = self._rcv_w_buf_offset

        # Number of bytes to dequeue from rcv_buf.
        # If the socket's requested buffer is larger than the data available,
        # limit the read to the available data only.
        n = min(bufsize, len(self._rcv_buf)-rcv_wnd)

        if __debug__:
            available = len(self._rcv_buf)-rcv_wnd

            log(
                "tcpcb",
                f"{self}: recv request bufsize={bufsize}, available={available}",
                level="DEBUG"
            )

        old_r_offset = self._rcv_r_buf_offset

        # read contiguously
        if self._rcv_r_buf_offset < rcv_w_buf_offset:
            if __debug__:
                start = old_r_offset
                end = start + n

                if end > rcv_w_buf_offset:
                    end = rcv_w_buf_offset

                log(
                    "tcpcb",
                    f"{self}: read rcv_buf [{start}:{end}] (n={n})",
                    level="DEBUG"
                )

            if __debug__:
                old_wnd = rcv_wnd
                new_wnd = old_wnd + n

                log(
                    "tcpcb",
                    f"{self}: rcv_wnd updated {old_wnd} -> {new_wnd} (freed={n})",
                    level="INFO"
                )

            with self._tcpcb_lock:
                # extend RCV.WND
                self._rcv_wnd += n
                self._rcv_adv = (self._rcv_adv + n) & 0xFF_FF_FF_FF

            # move on the r_offset
            self._rcv_r_buf_offset = (self._rcv_r_buf_offset + n)\
                                     % len(self._rcv_buf)

            # dequeue : [r:r+n] if n < w else [r:w]
            return [
                self._rcv_buf[
                old_r_offset:min(old_r_offset + n, rcv_w_buf_offset)
                ]
            ]

        if self._rcv_r_buf_offset >= rcv_w_buf_offset:

            # w is wrapped, but we can read contiguously
            if self._rcv_r_buf_offset+n <= len(self._rcv_buf):


                if __debug__:
                    log(
                        "tcpcb",
                        f"{self}: read rcv_buf [{old_r_offset}:{old_r_offset + n}]",
                        level="DEBUG"
                    )

                if __debug__:
                    old_wnd = rcv_wnd
                    new_wnd = old_wnd + n

                    log(
                        "tcpcb",
                        f"{self}: rcv_wnd updated {old_wnd} -> {new_wnd} (freed={n})",
                        level="INFO"
                    )

                with self._tcpcb_lock:
                    # extend RCV.WND
                    self._rcv_wnd += n
                    self._rcv_adv = (self._rcv_adv + n) & 0xFF_FF_FF_FF

                # move on the r_offset
                self._rcv_r_buf_offset = (self._rcv_r_buf_offset + n) \
                                         % len(self._rcv_buf)

                # dequeue : [r: r+n]
                return [self._rcv_buf[old_r_offset:old_r_offset+n]]

            # w is wrapped, and n is exceeding the end of buffer
            # so we need to read circularly
            else:
                if __debug__:
                    old_wnd = rcv_wnd
                    new_wnd = old_wnd + n

                    log(
                        "tcpcb",
                        f"{self}: rcv_wnd increased {old_wnd} -> {new_wnd} (freed={n})",
                        level="INFO"
                    )

                with self._tcpcb_lock:
                    # extend RCV.WND
                    self._rcv_wnd += n
                    self._rcv_adv = (self._rcv_adv + n) & 0xFF_FF_FF_FF

                # move on the r_offset
                self._rcv_r_buf_offset = (self._rcv_r_buf_offset + n) \
                                         % len(self._rcv_buf)


                remainder = ((old_r_offset + n) - old_r_offset)\
                            - (len(self._rcv_buf) - old_r_offset)

                if __debug__:
                    log(
                        "tcpcb",
                        f"{self}: read rcv_buf "
                        f"[{old_r_offset}:{len(self._rcv_buf)}] & [0:{remainder}]",
                        level="DEBUG"
                    )

                # dequeue : [r:] & [:remainder]
                return [
                    self._rcv_buf[old_r_offset:],
                    self._rcv_buf[:remainder]
                ]


        return []


    def tcp_send(self, data: memoryview) -> int:
        """
        Enqueue user data into the send buffer (snd_buf).

        This routine is invoked by the blocking 'send()' path. It will not
        return until the entire input buffer has been successfully copied
        into the internal send buffer.

        The function operates in blocking mode: if the send buffer becomes
        full, the caller is put to sleep waiting for a wake-up signal from
        another execution context (e.g., the reception path processing an
        incoming ACK that advances snd.una and frees buffer space).
        """

        # Keep one byte unused to avoid the ambiguous state
        # where w == r could mean either empty or full.
        # With this invariant:
        # w == r -> empty
        # (w + 1) % len(snd_buf) == r -> full

        data_len = len(data)

        # original len used at the return statement
        # because data is modified during the function procedure
        original_len = data_len

        with self._tcpcb_lock:
            snd_r_buf_offset = self._snd_r_buf_offset
            snd_w_buf_offset = self._snd_w_buf_offset

        free_space = (
            (snd_r_buf_offset - snd_w_buf_offset - 1)
            % len(self._snd_buf)
        )

        if __debug__:
            log(
                "tcpcb",
                f"{self}: send request size={data_len}, available_space={free_space}",
                level="DEBUG"
            )

        while data_len > 0 and free_space > 0:
            # check if we can put all given buffer in snd_buf
            # either in a contiguous block or wrapped around the snd_buf.
            if data_len <= free_space:
                # check if we can put all given buffer in contiguously way
                if snd_w_buf_offset + data_len <= len(self._snd_buf)-1:

                    if __debug__:
                        start = snd_w_buf_offset
                        end = start + data_len

                        log(
                            "tcpcb",
                            f"{self}: write to snd_buf [{start}:{end}] (len={data_len})",
                            level="DEBUG"
                        )

                    _write(
                        _from=data,
                        from_start=0,
                        from_end=None,
                        into=self._snd_buf,
                        into_start=snd_w_buf_offset,
                        into_end=snd_w_buf_offset+data_len
                    )

                    with self._tcpcb_lock:
                        # Move on the w_offset
                        self._snd_w_buf_offset += data_len

                    # reduce data_len to 0 and exit loop
                    data_len = 0

                # else, we need to write in wrapped way
                # first contiguously until the end of snd_bud.
                # second from start untile the last byte.
                else:
                    if __debug__:
                        buf_len = len(self._snd_buf)
                        start = snd_w_buf_offset

                        first_part = buf_len - start
                        second_part = data_len - first_part

                        log(
                            "tcpcb",
                            f"{self}: write to snd_buf "
                            f"[{start}:{buf_len}] & [0:{second_part}]",
                            level="DEBUG"
                        )

                    # write first portion
                    _write(
                        _from=data,
                        from_start=0,
                        from_end=len(self._snd_buf)-snd_w_buf_offset,
                        into=self._snd_buf,
                        into_start=snd_w_buf_offset,
                        into_end=None,
                    )

                    # write second portion
                    _write(
                        _from=data,
                        from_start=len(self._snd_buf)-snd_w_buf_offset,
                        from_end=len(self._snd_buf)-snd_w_buf_offset + (
                            len(data) - (len(self._snd_buf) - snd_w_buf_offset)),
                        into=self._snd_buf,
                        into_start=0,
                        into_end=(len(data) -
                                  (len(self._snd_buf) - snd_w_buf_offset)),
                    )

                    with self._tcpcb_lock:
                        # Move on the w_offset
                        self._snd_w_buf_offset = ((self._snd_w_buf_offset + data_len)
                                                  % len(self._snd_buf))

                    # reduce data_len to 0 and exit loop
                    data_len = 0


            # else, data_len is greater than the free available space.
            # Write as much as possible (contiguously or wrapped)
            # into snd_buf, then try to schedule a send event.
            else:
                # Check if permitted data (based on available snd_buf) can fit contiguously
                if snd_w_buf_offset+free_space <= len(self._snd_buf)-1:

                    if __debug__:
                        start = snd_w_buf_offset
                        end = start + free_space

                        log(
                            "tcpcb",
                            f"{self}: write to snd_buf [{start}:{end}] (written={free_space})",
                            level="DEBUG"
                        )

                    _write(
                        _from=data,
                        from_start=0,
                        from_end=free_space,
                        into=self._snd_buf,
                        into_start=snd_w_buf_offset,
                        into_end=snd_w_buf_offset+free_space
                    )

                    with self._tcpcb_lock:
                        # Move on the w_offset
                        self._snd_w_buf_offset = ((self._snd_w_buf_offset + free_space)
                                                  % len(self._snd_buf))

                    # reduce data_len
                    data_len -= free_space
                    # Trim the data
                    data = data[free_space:]

                    self.core.tcp_events_schedule.schedule_event(
                        event=TCPEvent(
                            type_=TCPEventType.SEND,
                            tcpcb=self
                        )
                    )

                    with self._send_events:
                        self._send_events.wait()

                    # after awakening, recalculate the free space
                    with self._tcpcb_lock:
                        snd_r_buf_offset = self._snd_r_buf_offset
                        snd_w_buf_offset = self._snd_w_buf_offset

                    free_space = (
                                (snd_r_buf_offset-snd_w_buf_offset - 1)
                                % len(self._snd_buf)
                    )


                # else: wrapped write required.
                # First: write contiguously to buffer end.
                # Second: write from start to last free byte.
                else:
                    if __debug__:
                        buf_len = len(self._snd_buf)
                        start = snd_w_buf_offset

                        first_part = buf_len - start
                        second_part = free_space - first_part

                        log(
                            "tcpcb",
                            f"{self}: write to snd_buf "
                            f"[{start}:{buf_len}] & [0:{second_part}] (written={free_space})",
                            level="DEBUG"
                        )

                    # write first portion
                    _write(
                        _from=data,
                        from_start=0,
                        from_end=len(self._snd_buf) - snd_w_buf_offset,
                        into=self._snd_buf,
                        into_start=snd_w_buf_offset,
                        into_end=None
                    )

                    # write second portion
                    _write(
                        _from=data,
                        from_start=len(self._snd_buf) - snd_w_buf_offset,
                        from_end=len(self._snd_buf) - snd_w_buf_offset +(
                                 free_space - (len(self._snd_buf) - snd_w_buf_offset)),
                        into=self._snd_buf,
                        into_start=0,
                        into_end=(free_space -
                                  (len(self._snd_buf) - snd_w_buf_offset)
                                  )
                    )

                    with self._tcpcb_lock:
                        # Move on the w_offset
                        self._snd_w_buf_offset = ((self._snd_w_buf_offset + free_space)
                                                  % len(self._snd_buf))

                    # reduce data_len
                    data_len -= free_space
                    # Trim the data
                    data = data[free_space:]

                    self.core.tcp_events_schedule.schedule_event(
                        event=TCPEvent(
                            type_=TCPEventType.SEND,
                            tcpcb=self
                        )
                    )

                    with self._send_events:
                        self._send_events.wait()

                    # after awakening, recalculate the free space
                    with self._tcpcb_lock:
                        snd_r_buf_offset = self._snd_r_buf_offset
                        snd_w_buf_offset = self._snd_w_buf_offset

                    free_space = (
                            (snd_r_buf_offset - snd_w_buf_offset - 1)
                            % len(self._snd_buf)
                    )

        self.core.tcp_events_schedule.schedule_event(
            event=TCPEvent(
                type_=TCPEventType.SEND,
                tcpcb=self
            )
        )

        return original_len

    def tcp_shutdown(self):
        with self._tcpcb_lock:
            self._shutdown_requested = True

        self.core.tcp_events_schedule.schedule_event(
            event=TCPEvent(
            type_=TCPEventType.SEND,
            tcpcb=self
            )
        )

    def tcp_close(self):
        with self._tcpcb_lock:
            self._close_requested = True

        self.core.tcp_events_schedule.schedule_event(
            event=TCPEvent(
            type_=TCPEventType.SEND,
            tcpcb=self
            )
        )
