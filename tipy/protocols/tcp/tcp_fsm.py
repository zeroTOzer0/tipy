from __future__ import annotations

from struct import pack

from tipy.lib.logger import log
from tipy.protocols.tcp.tcp_seq import (
    seq_lt,
    seq_gt,
    seq_leq,
    seq_geq,
    seq_diff,
    last_seq
)

from tipy.protocols.tcp.tcpcb import remove_tcpcb
from tipy.lib.socket import SOL_SOCKET, SO_LINGER
from tipy.protocols.tcp.builder import TCPOptMSS
from tipy.protocols.tcp.tcp_timer import (
start_rtx_timer,
start_time_wait_timer,
stop_rtx_timer,
stop_time_wait_timer,
stop_all_timers
)
from tipy.protocols.tcp.tcp import (
STATES,
TCP_MSS_KIND,
TCPEvent,
TCPEventType
)

from typing import Callable, TYPE_CHECKING
if TYPE_CHECKING:
    from tipy.protocols.tcp.tcpcb import TCPCB
    from tipy.lib.packet import PacketRX



DEFAULT_RECV_BUFF    =   0xFFFF
DEFAULT_SEND_BUFF    =   0xFFFF

DEFAULT_RCV_WND      =   0xFFFF

_SO_LINGER_ON = pack('ii', 1, 0)

TCP_ACCEPT_AND_HANDLE =  1
TCP_ACCEPT_BUT_BUFFER =  2
TCP_DROP              =  3


# max bytes can TCP transmit in one send routine call.
# Stop looping if the bytes transmitted exceeded TCP_MAX_TX_BYTES
# to let other TCP sockets to send its own data.
# TCPCB will automatically recall the appropriate send routine to send
# other remaining data.
TCP_MAX_TX_BYTES = 10000


def _change_state(tcpcb: TCPCB, new: int | None):
    if new is None:
        return

    with tcpcb.tcpcb_lock:
        tcpcb.prev_state = tcpcb.state
        tcpcb.state = new
        if __debug__:
            log(
                "tcpcb",
                f"{tcpcb}: state changed {tcpcb.prev_state} -> {tcpcb.state}",
                level="INFO"
            )

def _send_ack(tcpcb: TCPCB):
    """
    Send an ACK-only TCP segment (no payload).
    Acknowledges received data and advertises the RCV.WND.
    """
    tcpcb.core.tx_tcp(
        local_ip=tcpcb.lip, remote_ip=tcpcb.rip,
        local_port=tcpcb.lp, remote_port=tcpcb.rp,
        seq=tcpcb.snd_nxt, ack_seq=tcpcb.rcv_nxt,
        ack=True,
        window=tcpcb.rcv_wnd,
    )

def _send_fin(tcpcb: TCPCB, next_state: STATES|None):
    """
    Send a FIN+ACK segment.

    If a FIN was already transmitted, only retransmit it when required.
    Otherwise, mark FIN as sent and transmit the closing segment.

    On initial send, the TCP state is transitioned to `next_state`.
    A retransmission timer is started when a FIN segment is sent or resent
    """

    if tcpcb.sent_fin:
        # check if this is a retransmission
        if seq_gt(tcpcb.snd_max, tcpcb.snd_nxt):
            tcpcb.core.tx_tcp(
                local_ip=tcpcb.lip, remote_ip=tcpcb.rip,
                local_port=tcpcb.lp, remote_port=tcpcb.rp,
                seq=tcpcb.snd_nxt, ack_seq=tcpcb.rcv_nxt,
                ack=True, fin=True,
                window=tcpcb.rcv_wnd,
            )

            tcpcb.snd_nxt = (
                (tcpcb.snd_nxt + 1) & 0xFF_FF_FF_FF
            )

            start_rtx_timer(tcpcb=tcpcb)

        return

    tcpcb.sent_fin = True

    tcpcb.core.tx_tcp(
        local_ip=tcpcb.lip, remote_ip=tcpcb.rip,
        local_port=tcpcb.lp, remote_port=tcpcb.rp,
        seq=tcpcb.snd_nxt, ack_seq=tcpcb.rcv_nxt,
        ack=True, fin=True,
        window=tcpcb.rcv_wnd,
    )

    tcpcb.snd_nxt = (
        (tcpcb.snd_nxt + 1) & 0xFF_FF_FF_FF
    )

    tcpcb.snd_max = tcpcb.snd_nxt

    _change_state(tcpcb=tcpcb, new=next_state)

def _send_rst(tcpcb: TCPCB):
    """
    send RST
    """
    tcpcb.core.tx_tcp(
        local_ip=tcpcb.lip, remote_ip=tcpcb.rip,
        local_port=tcpcb.lp, remote_port=tcpcb.rp,
        seq=tcpcb.snd_nxt, ack_seq=tcpcb.rcv_nxt,
        ack=True, rst=True,
        window=0,
    )

def _drop_with_reset(tcpcb: TCPCB, packet_rx: PacketRX):
    """
    Drop with RST. Challenge by seq if ACK set, else challenge by ack.
    """

    if packet_rx.tcp.ack:
        tcpcb.core.tx_tcp(
            local_ip=tcpcb.lip, remote_ip=tcpcb.rip,
            local_port=tcpcb.lp, remote_port=tcpcb.rp,
            seq=tcpcb.snd_nxt, ack_seq=0,
            rst=True,
            window=0,
        )
        return

    tcpcb.core.tx_tcp(
        local_ip=tcpcb.lip, remote_ip=tcpcb.rip,
        local_port=tcpcb.lp, remote_port=tcpcb.rp,
        seq=tcpcb.snd_nxt, ack_seq=tcpcb.rcv_nxt,
        ack=True, rst=True,
        window=0,
    )


def _h_rx_ack(tcpcb: TCPCB, packet_rx: PacketRX) -> int:
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
    if seq_leq(packet_rx.tcp.ack_seq, tcpcb.snd_una) \
    or seq_gt(packet_rx.tcp.ack_seq, tcpcb.snd_nxt):
        if __debug__:
            if seq_leq(packet_rx.tcp.ack_seq, tcpcb.snd_una):
                msg = (
                    f"{tcpcb}: old ACK (ignored), ACK={packet_rx.tcp.ack_seq} "
                    f"< SND.UNA={tcpcb.snd_una}"
                )
                log(
                    "tcpcb",
                    msg,
                    level="DEBUG"
                )

            elif seq_gt(packet_rx.tcp.ack_seq, tcpcb.snd_nxt):
                msg = (f"{tcpcb}: invalid ACK, ACK={packet_rx.tcp.ack_seq} "
                       f"> SND.NXT={tcpcb.snd_una}")

                log("tcpcb", msg, level="WARN")

        return 0

    old_snd_una = tcpcb.snd_una
    if __debug__:
        acked_bytes = seq_diff(packet_rx.tcp.ack_seq, old_snd_una)

        log(
            "tcpcb",
            (
                f"{tcpcb}: ACK accepted "
                f"(UNA={old_snd_una} < ACK={packet_rx.tcp.ack_seq} <= SND.NXT={tcpcb.snd_nxt}), "
                f"acked_bytes={acked_bytes}"
            ),
            level="INFO"
        )

    tcpcb.snd_una = packet_rx.tcp.ack_seq
    return seq_diff(packet_rx.tcp.ack_seq, old_snd_una)

def _h_rx_wnd(tcpcb: TCPCB, packet_rx: PacketRX) -> bool:
    """
    Handle incoming window info
    Verify if SEG.SEQ > SND.WL1 or (SEG.SEQ == SND.WL1 and SEG.ACK > SND.WL2)
    (Affect the SND.WND/SND.WL1/SND.WL2 variables)
    """
    # The following condition check the formula:
    # SEG.SEQ > SND.WL1 or SEG.SEQ == SND.WL1 and SEG.ACK > SND.WL2

    if seq_lt(tcpcb.snd_wl1, packet_rx.tcp.seq) \
    or packet_rx.tcp.seq == tcpcb.snd_wl1 \
    and seq_lt(tcpcb.snd_wl2, packet_rx.tcp.ack_seq):
        tcpcb.snd_wl1 = packet_rx.tcp.seq
        tcpcb.snd_wl2 = packet_rx.tcp.ack_seq
        tcpcb.snd_wnd = packet_rx.tcp.window
        if __debug__:
            log(
                "tcpcb",
                f"{tcpcb}: SND.WND updated (WL1={tcpcb.snd_wl1}, "
                f"WL2={tcpcb.snd_wl2}, WND={tcpcb.snd_wnd})",
                level="INFO"
            )
        return True
    return False

def _h_rx_seq_zlen_zwnd(tcpcb: TCPCB, packet_rx: PacketRX) -> int:
    """
    SEG.LEN = 0 & RCV.WND = 0
    Only acceptable if SEG.SEQ == RCV.NXT.
    Returns TCP_ACCEPT_AND_HANDLE if segment is acceptable
    TCP_DROP otherwise.
    """

    if __debug__:
        seq = packet_rx.tcp.seq
        accept = (seq == tcpcb.rcv_nxt)
        action = "ACCEPT" if accept else "DROP"

        log(
            "tcpcb",
            f"{tcpcb}: zero-len + zero-window "
            f"(SEQ={seq}, RCV.NXT={tcpcb.rcv_nxt}) -> {action}",
            level="DEBUG"
        )

    if packet_rx.tcp.seq == tcpcb.rcv_nxt:
        return TCP_ACCEPT_AND_HANDLE

    return TCP_DROP

def _h_rx_seq_zlen(tcpcb: TCPCB, packet_rx: PacketRX) -> int:
    """
    SEG.LEN = 0 & RCV.WND > 0
    Acceptable if SEG.SEQ lies within the RCV.WND.
    Returns TCP_ACCEPT_AND_HANDLE if segment is acceptable,
    TCP_DROP otherwise.
    """

    if __debug__:
        seq = packet_rx.tcp.seq

        in_window = (
                seq_leq(tcpcb.rcv_nxt, seq)
                and seq_lt(seq, tcpcb.rcv_adv)
        )

        action = "ACCEPT" if in_window else "DROP"

        log(
            "tcpcb",
            f"{tcpcb}: zero-length segment "
            f"(SEQ={seq}, RCV.NXT={tcpcb.rcv_nxt}, RCV.MAX={tcpcb.rcv_adv}) "
            f"-> {action}",
            level="DEBUG"
        )

    if seq_leq(tcpcb.rcv_nxt, packet_rx.tcp.seq) \
    and seq_lt(packet_rx.tcp.seq, tcpcb.rcv_adv):
        return TCP_ACCEPT_AND_HANDLE

    return TCP_DROP

def _h_rx_seq_zwnd(tcpcb: TCPCB, packet_rx: PacketRX) -> int:
    """
    SEG.LEN > 0 & RCV.WND = 0
    NEVER acceptable. Receiver just drop.
    Returns TCP_DROP unconditionally.
    """

    if __debug__:
        length = packet_rx.tcp.dlen + packet_rx.tcp.fin + packet_rx.tcp.syn
        log(
            "tcpcb",
            f"{tcpcb}: zero-window drop "
            f"(SEQ={packet_rx.tcp.seq}, LEN={length}, RCV.NXT={tcpcb.rcv_nxt})",
            level="INFO"
        )

    return TCP_DROP

def _h_rx_seq_normal(tcpcb: TCPCB, packet_rx: PacketRX) -> int:
    """
    Classify a segment as in-order, out-of-order, or invalid.
    In-order: SEG.SEQ <= RCV.NXT <= SEG.LAST
    Out-of-order: RCV.NXT < SEG.SEQ < RCV.ADV
    In-order data is trimmed to the rcv_wnd
    and RCV.NXT is advanced accordingly.
    """
    # NOTE: returned TCP_ACCEPT_BUT_BUFFER means ooo but not yet supported

    last_seq_ = last_seq(packet_rx=packet_rx)

    # In-order segment. RCV.NXT falls within the segment's
    # sequence range, so the receive stream can advance.
    if seq_leq(packet_rx.tcp.seq, tcpcb.rcv_nxt) \
    and seq_geq(last_seq_, tcpcb.rcv_nxt):

        if __debug__:
            msg = ""
            if seq_lt(packet_rx.tcp.seq, tcpcb.rcv_nxt):
                msg += f"---seq({packet_rx.tcp.seq})---rcv_nxt({tcpcb.rcv_nxt})"

            elif packet_rx.tcp.seq == tcpcb.rcv_nxt:
                msg += f"---seq({packet_rx.tcp.seq})=rcv_nxt({tcpcb.rcv_nxt})"

            if seq_gt(last_seq_, tcpcb.rcv_adv):
                msg += f"---rcv_adv({tcpcb.rcv_adv})---last_seq({last_seq_})"

            elif last_seq_ == tcpcb.rcv_adv:
                msg += f"---last_seq({last_seq_})=rcv_adv({tcpcb.rcv_adv})"

            elif seq_lt(last_seq_, tcpcb.rcv_adv):
                msg += f"---last_seq({last_seq_})---rcv_adv({tcpcb.rcv_adv})"

            log(
                "tcpcb",
                f"{msg} -> IN-ORDER SEG",
                "DEBUG"
            )

        todrop = seq_diff(tcpcb.rcv_nxt, packet_rx.tcp.seq)

        packet_rx.tcp.seq = (
                (packet_rx.tcp.seq + todrop) & 0xFF_FF_FF_FF
        )

        packet_rx.tcp.dlen -= (todrop - packet_rx.tcp.fin - packet_rx.tcp.syn)

        tcpcb.tcp_data_start = todrop
        tcpcb.tcp_data_len = min(seq_diff(tcpcb.rcv_adv, tcpcb.rcv_nxt),
                                 seq_diff(last_seq_ + 1, tcpcb.rcv_nxt))

        tcpcb.rcv_nxt = (tcpcb.rcv_nxt + tcpcb.tcp_data_len) & 0xFF_FF_FF_FF

        if packet_rx.tcp.fin\
        and seq_geq(last_seq_, tcpcb.rcv_adv):
            packet_rx.tcp.flags &= ~0x01

        return TCP_ACCEPT_AND_HANDLE

    # check for ooo
    if seq_gt(packet_rx.tcp.seq, tcpcb.rcv_nxt) \
    and seq_lt(packet_rx.tcp.seq, tcpcb.rcv_adv):
        return TCP_ACCEPT_BUT_BUFFER

    return TCP_DROP


# index 0b00 : zero len & zero wnd
# index 0b01 : zero len only
# index 0b10 : zero wnd only
# index 0b11 : normal
rcv_seq_map: list[Callable]= [
    _h_rx_seq_zlen_zwnd,
    _h_rx_seq_zwnd,
    _h_rx_seq_zlen,
    _h_rx_seq_normal
]

def _h_rx_seq(tcpcb: TCPCB, packet_rx: PacketRX) -> int:
    """
    Dispatch segment acceptance per rcv_seq_map list.
    """
    idx = (1 if packet_rx.tcp.dlen
                + packet_rx.tcp.fin
                + packet_rx.tcp.syn
           else 0)

    idx |= (2 if tcpcb.rcv_wnd else 0)
    return rcv_seq_map[idx](tcpcb, packet_rx)

def _h_rx_rst(tcpcb: TCPCB, packet_rx: PacketRX) -> bool:
    """
    handle rcv RST. return False if no RST presents
    otherwise go to CLOSED state and delete TCPCB
    """
    if not packet_rx.tcp.rst:
        return False

    if __debug__:
        log(
            'tcpcb',
            f'{tcpcb} rcv RST',
            level='ERROR'
        )

    stop_all_timers(tcpcb=tcpcb)
    _change_state(tcpcb=tcpcb, new=STATES.CLOSED)
    remove_tcpcb(tcpcb=tcpcb)
    return True

def _h_active_close_tx(tcpcb: TCPCB, close_requested: bool) -> bool:
    """
    Handle tx path when an active close invoked.
    Returns True if connection aborted (RST sent), False if normal closure can proceed.
    """

    if close_requested \
    and tcpcb.sock_opt.get((SOL_SOCKET, SO_LINGER), None) == _SO_LINGER_ON:
        stop_all_timers(tcpcb=tcpcb)
        _send_rst(tcpcb=tcpcb)
        _change_state(tcpcb=tcpcb, new=STATES.CLOSED)
        remove_tcpcb(tcpcb=tcpcb)
        return True

    return False

def _h_active_close_rx(tcpcb: TCPCB, packet_rx: PacketRX) -> bool:
    """
    Handle rx segments when an active close invoked.
    Returns False if graceful closure can continue.
    True if RST was sent and connection aborted.
    """

    with tcpcb.tcpcb_lock:
        close_req = tcpcb.close_requested
        shut_req = tcpcb.shutdown_requested

    if close_req:
        if packet_rx.tcp.dlen:
            stop_all_timers(tcpcb=tcpcb)
            _drop_with_reset(tcpcb=tcpcb, packet_rx=packet_rx)
            _change_state(tcpcb=tcpcb, new=STATES.CLOSED)
            remove_tcpcb(tcpcb=tcpcb)
            return True

        return False

    if shut_req:
        return False

    return False

def _rollback_to_una(tcpcb: TCPCB):
    """
    Rewind snd_r_temp_buf_offset to the last unacknowledged byte
    and reset snd_nxt to snd_una. This occurs during retransmission.
    """
    if __debug__:
        log(
            'tcpcb',
            f'rollback snd_nxt({tcpcb.snd_nxt}) to snd_una({tcpcb.snd_una}) '
            f'({seq_diff(tcpcb.snd_nxt, tcpcb.snd_una)} unacked)',
            'DEBUG'
        )
    tcpcb.snd_r_temp_buf_offset = tcpcb.snd_r_buf_offset
    tcpcb.snd_nxt = tcpcb.snd_una

def _compute_rcv_wnd(tcpcb: TCPCB, w_offset: int, r_offset: int) -> None:
    """
    Compute new rcv_wnd and advance rcv_adv if needed
    """

    rcv_buf_free_space = tcpcb.rcv_buf.free(
        w_offset=w_offset,
        r_offset=r_offset
    )
    # set our new local window
    tcpcb.rcv_wnd = rcv_buf_free_space

    # calculate the rcv_adv
    new_rcv_adv = (rcv_buf_free_space + tcpcb.rcv_nxt) & 0xFF_FF_FF_FF
    if seq_gt(new_rcv_adv, tcpcb.rcv_adv):
        tcpcb.rcv_adv = new_rcv_adv


def _generate_segment(buf: list[memoryview], n: int) -> memoryview:
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

def _tx_loop(*,
             tcpcb: TCPCB,
             data: list[memoryview],
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

    snd_wnd = tcpcb.snd_wnd
    bytes_send_counter = 0

    if _h_active_close_tx(tcpcb=tcpcb, close_requested=close_requested):
        return

    while dlen > 0:
        n = min(tcpcb.remote_mss, snd_wnd, dlen)
        seg_data = _generate_segment(buf=data, n=n)
        seg_data_len = len(seg_data)
        should_fin = any((shutdown_requested, close_requested)) \
                     and not data

        tcpcb.core.tx_tcp(
            local_ip=tcpcb.lip, remote_ip=tcpcb.rip,
            local_port=tcpcb.lp, remote_port=tcpcb.rp,
            seq=tcpcb.snd_nxt, ack_seq=tcpcb.rcv_nxt,
            ack=True, psh=True, fin=should_fin,
            window=tcpcb.rcv_wnd,
            data=seg_data
        )

        tcpcb.snd_nxt = (tcpcb.snd_nxt + seg_data_len + should_fin) & 0xFF_FF_FF_FF
        # check if this is not a retransmission
        if seq_gt(tcpcb.snd_nxt, tcpcb.snd_max):
            tcpcb.snd_max = tcpcb.snd_nxt

        dlen -= seg_data_len
        snd_wnd -= seg_data_len
        bytes_send_counter += seg_data_len

        # move on the temp_r_offset
        tcpcb.snd_r_temp_buf_offset = (
            (tcpcb.snd_r_temp_buf_offset + seg_data_len) % len(tcpcb.snd_buf)
        )

        if should_fin:
            tcpcb.sent_fin = should_fin
            _change_state(tcpcb=tcpcb, new=next_state)
            break

        if snd_wnd <= 0:
            # TODO: RECHECK snd_wnd AND ENTER PERSIST STATE IF snd_wnd=0
            if __debug__:
                log(
                    "tcpcb",
                    f"{tcpcb}: send window exhausted",
                    level="DEBUG"
                )
            break

        if bytes_send_counter >= TCP_MAX_TX_BYTES:
            if __debug__:
                log(
                    "tcpcb",
                    f"{tcpcb}: tx limit reached ({TCP_MAX_TX_BYTES} bytes), "
                    f"bytes_sent={bytes_send_counter}",
                    level="DEBUG"
                )
            break

    start_rtx_timer(tcpcb=tcpcb)


def _append_rcv_data(tcpcb: TCPCB, packet_rx: PacketRX) -> int:
    """
    Append incoming segment payload to the rcv_buf.
    Notifies the application (socket.recv()) when data is ready.
    """
    # NOTE: do not hold tcpcb lock when calling this function.
    # Lock is only used to snapshot rcv offsets; copy to rcv_buf happens unlocked
    # to avoid holding the lock during memory operations.

    with tcpcb.tcpcb_lock:
        rcv_w_buf_offset = tcpcb.rcv_w_buf_offset
        rcv_r_buf_offset = tcpcb.rcv_r_buf_offset

    # if delayed ack was supported, we must recalculate the local window
    _compute_rcv_wnd(tcpcb=tcpcb,
                     w_offset=rcv_w_buf_offset,
                     r_offset=rcv_r_buf_offset)

    if tcpcb.rcv_wnd == 0:
        return 0

    data = packet_rx.tcp.data

    if data:
        start = tcpcb.tcp_data_start
        dlen = tcpcb.tcp_data_len

        if __debug__:
            log(
                "tcpcb",
                f"{tcpcb}: copy into rcv_buf (packet_rx.tcp.data[{start}:{dlen}])",
                level="DEBUG"
            )

        l = tcpcb.rcv_buf.enqueue(
            w_offset=rcv_w_buf_offset,
            r_offset=rcv_r_buf_offset,
            buffer=data[start : dlen]
        )

        # reduce RCV.WND
        tcpcb.rcv_wnd -= tcpcb.tcp_data_len

        # move on the write offset
        with tcpcb.tcpcb_lock:
            tcpcb.rcv_w_buf_offset = (
                (tcpcb.rcv_w_buf_offset + l) % len(tcpcb.rcv_buf)
            )

        with tcpcb.recv_events:
            tcpcb.recv_events.notify()

        return l

    return 0


def _drain_snd_buf(tcpcb: TCPCB) -> list[memoryview]:
    with tcpcb.tcpcb_lock:
        snd_w_buf_offset = tcpcb.snd_w_buf_offset
        snd_r_buf_offset = tcpcb.snd_r_temp_buf_offset

    return tcpcb.snd_buf.dequeue(
        w_offset=snd_w_buf_offset,
        r_offset=snd_r_buf_offset,
        n=tcpcb.snd_wnd
    )


def _init_snd_seq(tcpcb: TCPCB):
    tcpcb.snd_una = tcpcb.iss
    # sins this stack does not support sending data at none-sync states
    # we advance only by 1
    tcpcb.snd_nxt = tcpcb.iss
    tcpcb.snd_max = tcpcb.snd_nxt

def _init_snd_wnd(tcpcb: TCPCB, packet_rx: PacketRX):
    tcpcb.snd_wnd = packet_rx.tcp.window
    tcpcb.snd_wl1 = packet_rx.tcp.seq
    tcpcb.snd_wl2 = packet_rx.tcp.ack_seq
    
    

def _init_rcv_seq(tcpcb: TCPCB, packet_rx: PacketRX):
    tcpcb.irs = packet_rx.tcp.seq
    tcpcb.rcv_nxt = (tcpcb.irs + 1) & 0xFF_FF_FF_FF
    tcpcb.rcv_adv = (tcpcb.rcv_nxt + tcpcb.rcv_wnd) \
                    & 0xFF_FF_FF_FF  # rcv_adv: the first seq not expected
    
        

def _activ_open(tcpcb: TCPCB):
    if tcpcb.state == STATES.CLOSED:

        tcpcb.core.tx_tcp(
            local_ip=tcpcb.lip, remote_ip=tcpcb.rip,
            local_port=tcpcb.lp, remote_port=tcpcb.rp,
            seq=tcpcb.iss,
            syn=True,
            window=DEFAULT_RCV_WND,
            options=[TCPOptMSS()]
        )
        _init_snd_seq(tcpcb=tcpcb)

        tcpcb.snd_nxt = (
                (tcpcb.snd_nxt + 1) & 0xFF_FF_FF_FF
        )
        tcpcb.snd_max = tcpcb.snd_nxt

        _change_state(tcpcb=tcpcb, new=STATES.SYN_SENT)
        start_rtx_timer(tcpcb=tcpcb)

def _rx_syn_sent(tcpcb: TCPCB, packet_rx: PacketRX):
    """
    Handle received segment when the TCP on the SYN_SENT State
    """
    if _h_rx_rst(tcpcb=tcpcb, packet_rx=packet_rx):
        return

    if packet_rx.tcp.fin:
        return  # FIXME

    if(
        packet_rx.tcp.syn and packet_rx.tcp.ack
    ):

        if _h_rx_ack(tcpcb=tcpcb, packet_rx=packet_rx) > 0:

            stop_rtx_timer(tcpcb=tcpcb)

            # l is the number of bytes enqueued into rcv_buf if data is received in this state (SYN-SENT);
            # used to control recv notification.
            l = 0

            _init_rcv_seq(tcpcb=tcpcb, packet_rx=packet_rx)
            _init_snd_wnd(tcpcb=tcpcb, packet_rx=packet_rx)

            # extract the MSS, if no MSS options
            # exists use the default MSS: 536
            remote_mss = packet_rx.tcp.options.get(TCP_MSS_KIND, 536)
            tcpcb.remote_mss = remote_mss
            if __debug__:
                log(
                    "tcpcb",
                    f"{tcpcb}: remote MSS = {tcpcb.remote_mss}",
                    level="INFO"
                )

            # If the segment contains data, buffer it into rcv_buf.
            # Since _append_rcv_data() notifies the application whenever data becomes
            # available in rcv_buf, do not use _append_rcv_data() here; enqueue it manually.
            if packet_rx.tcp.dlen > 0:
                with tcpcb.tcpcb_lock:
                    rcv_w_buf_offset = tcpcb.rcv_w_buf_offset
                    rcv_r_buf_offset = tcpcb.rcv_r_buf_offset

                l = tcpcb.rcv_buf.enqueue(
                    w_offset=rcv_w_buf_offset,
                    r_offset=rcv_r_buf_offset,
                    buffer=packet_rx.tcp.data
                )

                tcpcb.rcv_wnd -= l

                tcpcb.rcv_nxt = (tcpcb.rcv_nxt + l) & 0xFF_FF_FF_FF

                # move on the write offset
                with tcpcb.tcpcb_lock:
                    tcpcb.rcv_w_buf_offset = (
                            (tcpcb.rcv_w_buf_offset + l) % len(tcpcb.rcv_buf)
                    )

                if __debug__:
                    log("tcpcb",
                        f"{tcpcb}: pre-ESTABLISHED data received (buffered)",
                        level="INFO")

            tcpcb.core.tx_tcp(
                local_ip=tcpcb.lip, remote_ip=tcpcb.rip,
                local_port=tcpcb.lp, remote_port=tcpcb.rp,
                seq=tcpcb.snd_nxt, ack_seq=tcpcb.rcv_nxt,
                ack=True,
                window=tcpcb.rcv_wnd,
            )

            _change_state(tcpcb=tcpcb, new=STATES.ESTAB)

            with tcpcb.connect_events:
                tcpcb.connect_events.notify()

            # notify the application if we recv some data in this stage
            if l > 0:
                with tcpcb.recv_events:
                    tcpcb.recv_events.notify()
            return

    # Handle simultaneous open.
    if packet_rx.tcp.syn:
        # Retransmit our original SYN.
        _rollback_to_una(tcpcb=tcpcb)
        
        _init_rcv_seq(tcpcb=tcpcb, packet_rx=packet_rx)
        _init_snd_wnd(tcpcb=tcpcb, packet_rx=packet_rx)

        tcpcb.core.tx_tcp(
            local_ip=tcpcb.lip, remote_ip=tcpcb.rip,
            local_port=tcpcb.lp, remote_port=tcpcb.rp,
            seq=tcpcb.snd_nxt, ack_seq=tcpcb.rcv_nxt,
            syn=True, ack=True,
            window=tcpcb.rcv_wnd,
        )

        tcpcb.snd_nxt = (
            (tcpcb.snd_nxt + 1) & 0xFF_FF_FF_FF
        )

        _change_state(tcpcb=tcpcb, new=STATES.SYN_RECV)

def _tx_syn_sent(tcpcb: TCPCB):
    """ tx h for syn_sent """

    # only retransmission invokes this routine
    tcpcb.core.tx_tcp(
        local_ip=tcpcb.lip, remote_ip=tcpcb.rip,
        local_port=tcpcb.lp, remote_port=tcpcb.rp,
        seq=tcpcb.snd_nxt, ack_seq=tcpcb.rcv_nxt,
        syn=True,
        window=tcpcb.rcv_wnd,
    )

    tcpcb.snd_nxt = (
        (tcpcb.snd_nxt + 1) & 0xFF_FF_FF_FF
    )

    start_rtx_timer(tcpcb=tcpcb)

def _rx_syn_recv(tcpcb: TCPCB, packet_rx: PacketRX):
    """ rx h for syn recv"""

    # NOTE: LISTEN is not implemented yet.
    # SYN-RECV is reachable only through simultaneous open.

    if not packet_rx.tcp.ack:
        return

    if packet_rx.tcp.syn:

        if seq_lt(packet_rx.tcp.seq, tcpcb.irs):
            _drop_with_reset(tcpcb=tcpcb, packet_rx=packet_rx)
            return

        todrop = (tcpcb.rcv_nxt - packet_rx.tcp.seq)

        if todrop > 0:
            packet_rx.tcp.seq = (
                (packet_rx.tcp.seq + 1) & 0xFF_FF_FF_FF
            )

            # We already consumed the peer's SYN when entering SYN_RECV.
            # Any SYN seen here is therefore treated as a retransmitted SYN.
            packet_rx.tcp.flags &= ~0x02

        # ignore any received data
        packet_rx.tcp.dlen = 0

        # Do not drop purely due to OOO sequence or SYN mismatch.
        # As long as the segment is within the receive window and ACK is valid,
        # let sync-states handle SYN inconsistencies (e.g. via challenge ACK).
        if _h_rx_seq(tcpcb=tcpcb, packet_rx=packet_rx) == TCP_DROP:
            _send_ack(tcpcb=tcpcb)
            return

        if _h_rx_ack(tcpcb=tcpcb, packet_rx=packet_rx) > 0:

            stop_rtx_timer(tcpcb=tcpcb)

            _h_rx_wnd(tcpcb=tcpcb, packet_rx=packet_rx)
            _send_ack(tcpcb=tcpcb)
            _change_state(tcpcb=tcpcb, new=STATES.ESTAB)
            with tcpcb.connect_events:
                tcpcb.connect_events.notify()

        return


def _tx_syn_recv(tcpcb: TCPCB):
    """ tx h for syn recv state """
    tcpcb.core.tx_tcp(
        local_ip=tcpcb.lip, remote_ip=tcpcb.rip,
        local_port=tcpcb.lp, remote_port=tcpcb.rp,
        seq=tcpcb.snd_nxt, ack_seq=tcpcb.rcv_nxt,
        syn=True, ack=True,
        window=tcpcb.rcv_wnd,
    )

    tcpcb.snd_nxt = (
            (tcpcb.snd_nxt + 1) & 0xFF_FF_FF_FF
    )
    start_rtx_timer(tcpcb=tcpcb)



def _rx_estab(tcpcb: TCPCB, packet_rx: PacketRX):
    """
    Handle received segment when the TCP on the ESTAB State
    """
    if packet_rx.tcp.dlen > 0\
    or packet_rx.tcp.fin:
        tcpcb.ack_now = True

    accept_seg = _h_rx_seq(tcpcb=tcpcb, packet_rx=packet_rx)

    if accept_seg == TCP_ACCEPT_AND_HANDLE:
        if _h_rx_rst(tcpcb=tcpcb, packet_rx=packet_rx):
            return

        seq_acked = _h_rx_ack(tcpcb=tcpcb, packet_rx=packet_rx)

        # check if all our seq are acked
        if tcpcb.snd_nxt == tcpcb.snd_una:
            stop_rtx_timer(tcpcb=tcpcb)

        with tcpcb.tcpcb_lock:
            tcpcb.snd_r_buf_offset = (
                (tcpcb.snd_r_buf_offset + seq_acked - packet_rx.tcp.fin) % len(tcpcb.snd_buf)
            )

        _h_rx_wnd(tcpcb=tcpcb, packet_rx=packet_rx)

        _append_rcv_data(tcpcb=tcpcb, packet_rx=packet_rx)

        # tcp_send userreq may be waiting for
        # a signal to enqueue remaining data
        if seq_acked > 0:
            with tcpcb.send_events:
                tcpcb.send_events.notify()

        # check if the segment contains FIN
        if packet_rx.tcp.fin:
            _change_state(tcpcb=tcpcb, new=STATES.CLOSE_WAIT)
            # application may block at the tcp_recv userreq, so notify
            # him to indicates the end of the remote's data
            with tcpcb.recv_events:
                tcpcb.recv_events.notify()

        tcpcb.core.tcp_events_schedule.schedule_event(
            event=TCPEvent(
            type_=TCPEventType.SEND,
            tcpcb=tcpcb
            )
        )
        return

    if accept_seg == TCP_ACCEPT_BUT_BUFFER:
        # TODO: implement OOO
        tcpcb.core.tcp_events_schedule.schedule_event(
            event=TCPEvent(
                type_=TCPEventType.SEND,
                tcpcb=tcpcb
            )
        )
        return

    if accept_seg == TCP_DROP:
        tcpcb.core.tcp_events_schedule.schedule_event(
            event=TCPEvent(
                type_=TCPEventType.SEND,
                tcpcb=tcpcb
            )
        )
        return

def _tx_estab(tcpcb: TCPCB):
    data = _drain_snd_buf(tcpcb=tcpcb)

    with tcpcb.tcpcb_lock:
        rcv_r_buf_offset = tcpcb.rcv_r_buf_offset
        rcv_w_buf_offset = tcpcb.rcv_w_buf_offset
        shutdown_req = tcpcb.shutdown_requested
        close_req = tcpcb.close_requested

    _compute_rcv_wnd(tcpcb=tcpcb,
                     w_offset=rcv_w_buf_offset,
                     r_offset=rcv_r_buf_offset)

    if not data:
        if _h_active_close_tx(tcpcb=tcpcb, close_requested=close_req):
            return

        if close_req or shutdown_req:
            if tcpcb.snd_wnd > 0:
                # a graceful connection closing can be done
                _send_fin(tcpcb=tcpcb, next_state=STATES.FIN_WAIT_1)
                tcpcb.ack_now = False
                return

        if tcpcb.ack_now:
            _send_ack(tcpcb=tcpcb)
            tcpcb.ack_now = False
            return

        return # no data, no ack should be sent, exit.

    _tx_loop(tcpcb=tcpcb,
             data=data,
             next_state=STATES.FIN_WAIT_1,
             shutdown_requested=shutdown_req,
             close_requested=close_req)


def _rx_fin_wait_1(tcpcb: TCPCB, packet_rx: PacketRX):
    """rx h for fin-wait-1"""
    # This state is entered when the application invokes close/shutdown.
    # At this point, no further data will be queued in snd_buf, so there is
    # no need to schedule any send event. We only send ACK segments.
    # NOTE: FIN retransmissions (or the final DATA+FIN segment, if applicable)
    # are handled by the TX routine for this state.

    if packet_rx.tcp.dlen\
    or packet_rx.tcp.fin:
        tcpcb.ack_now = True

    accept_seg = _h_rx_seq(tcpcb=tcpcb, packet_rx=packet_rx)
    if accept_seg == TCP_ACCEPT_AND_HANDLE:

        if (
            _h_rx_rst(tcpcb=tcpcb, packet_rx=packet_rx)
            or _h_active_close_rx(tcpcb=tcpcb, packet_rx=packet_rx)
        ):
            return

        seq_acked = _h_rx_ack(tcpcb=tcpcb, packet_rx=packet_rx)
        with tcpcb.tcpcb_lock:
            tcpcb.snd_r_buf_offset = (
                (tcpcb.snd_r_buf_offset + seq_acked - packet_rx.tcp.fin) % len(tcpcb.snd_buf)
            )
            rcv_r_buf_offset = tcpcb.rcv_r_buf_offset
            rcv_w_buf_offset = tcpcb.rcv_w_buf_offset

        _compute_rcv_wnd(tcpcb=tcpcb,
                         w_offset=rcv_w_buf_offset,
                         r_offset=rcv_r_buf_offset)

        # check if all our seq are acked
        if tcpcb.snd_nxt == tcpcb.snd_una:
            stop_rtx_timer(tcpcb=tcpcb)

            if packet_rx.tcp.fin:
                _change_state(tcpcb=tcpcb, new=STATES.TIME_WAIT)
                start_time_wait_timer(tcpcb=tcpcb)

            else:
                _change_state(tcpcb=tcpcb, new=STATES.FIN_WAIT_2)

        else:
            # our fin not acked yet. check if the rx segment contains FIN
            if packet_rx.tcp.fin:
                _change_state(tcpcb=tcpcb, new=STATES.CLOSING)

        _h_rx_wnd(tcpcb=tcpcb, packet_rx=packet_rx)

        _append_rcv_data(tcpcb=tcpcb, packet_rx=packet_rx)

        if tcpcb.ack_now:
            _send_ack(tcpcb=tcpcb)

        return

    if accept_seg == TCP_ACCEPT_BUT_BUFFER:
        # OOO is not supported yet
        if tcpcb.ack_now:
            _send_ack(tcpcb=tcpcb)
        return

    if accept_seg == TCP_DROP:
        if tcpcb.ack_now:
            _send_ack(tcpcb=tcpcb)
        return


def _tx_fin_wait_1(tcpcb: TCPCB):
    # NOTE: The RX routine for this state does not schedule TX events.
    # Therefore, this routine is only expected to run for retransmissions
    # (e.g., retransmitting the outstanding FIN or DATA+FIN segment).
    # It assumes the FIN is still unacknowledged and retransmits it,
    # optionally together with any remaining unacknowledged data or separated

    data = _drain_snd_buf(tcpcb=tcpcb)

    with tcpcb.tcpcb_lock:
        rcv_r_buf_offset = tcpcb.rcv_r_buf_offset
        rcv_w_buf_offset = tcpcb.rcv_w_buf_offset
        close_req = tcpcb.close_requested

    _compute_rcv_wnd(tcpcb=tcpcb,
                     w_offset=rcv_w_buf_offset,
                     r_offset=rcv_r_buf_offset)
    if not data:
        if _h_active_close_tx(tcpcb=tcpcb, close_requested=close_req):
            return

        if tcpcb.snd_wnd > 0:
            # retransmit FIN
            _send_fin(tcpcb=tcpcb, next_state=None)

        return

    # Force shutdown_requested=True and close_requested=False.
    # This path is reached only during a graceful close, so we simulate it
    # by enabling shutdown behavior in the TX loop.
    _tx_loop(
        tcpcb=tcpcb,
        data=data,
        next_state=None,
        shutdown_requested=True,
        close_requested=False,
    )


def _rx_fin_wait_2(tcpcb: TCPCB, packet_rx: PacketRX):
    """ rx h for fin w 2 """
    if packet_rx.tcp.dlen > 0\
    or packet_rx.tcp.fin:
        tcpcb.ack_now = True


    accept_seq = _h_rx_seq(tcpcb=tcpcb, packet_rx=packet_rx)
    if accept_seq == TCP_ACCEPT_AND_HANDLE:

        if (
            _h_rx_rst(tcpcb=tcpcb, packet_rx=packet_rx)
            or _h_active_close_rx(tcpcb=tcpcb, packet_rx=packet_rx)
        ):
            return

        with tcpcb.tcpcb_lock:
            rcv_r_buf_offset = tcpcb.rcv_r_buf_offset
            rcv_w_buf_offset = tcpcb.rcv_w_buf_offset

        _compute_rcv_wnd(tcpcb=tcpcb,
                         w_offset=rcv_w_buf_offset,
                         r_offset=rcv_r_buf_offset)

        # FIN already acknowledged; no local send state remains.
        # ACK processed for correctness; peer window still updated for TCP state tracking.
        _ = _h_rx_ack(tcpcb=tcpcb, packet_rx=packet_rx)
        _h_rx_wnd(tcpcb=tcpcb, packet_rx=packet_rx)

        if packet_rx.tcp.fin:
            _change_state(tcpcb=tcpcb, new=STATES.TIME_WAIT)
            start_time_wait_timer(tcpcb=tcpcb)

        _append_rcv_data(tcpcb=tcpcb, packet_rx=packet_rx)

        _send_ack(tcpcb=tcpcb)

        return

    if accept_seq == TCP_ACCEPT_BUT_BUFFER:
        _send_ack(tcpcb=tcpcb)
        return

    if accept_seq == TCP_DROP:
        _send_ack(tcpcb=tcpcb)
        return

def _tx_fin_wait_2(tcpcb: TCPCB):
    """tx h for fin w 2"""

    # This TX handler does not generate ACKs; ACK processing is done in the RX path.
    # In FIN-WAIT-2, the local FIN has already been acknowledged and no application
    # data remains to be sent. This function only checks for a late close request
    # from the application and decides how to proceed with connection teardown.
    # The only possible transmission from this path is an RST in case of an abortive close.

    with tcpcb.tcpcb_lock:
        close_req = tcpcb.close_requested

    _h_active_close_tx(tcpcb=tcpcb, close_requested=close_req)



def _rx_closing(tcpcb: TCPCB, packet_rx: PacketRX):
    """ rx h for closing """

    # NOTE: This state indicates the peer has initiated connection termination.
    # Any incoming segment with data (SEG.LEN > 0) is ignored for processing purposes.
    # FIN handling does not alter state progression here.
    # The ACK number remains fixed at the last in-order sequence (rcv.nxt).
    # so do not use _h_rx_seq().

    if seq_leq(packet_rx.tcp.seq, tcpcb.rcv_nxt) \
    and seq_leq(tcpcb.rcv_nxt, last_seq(packet_rx)):

        if (
            _h_rx_rst(tcpcb=tcpcb, packet_rx=packet_rx)
            or _h_active_close_rx(tcpcb=tcpcb, packet_rx=packet_rx)
        ):
            return

        seq_acked = _h_rx_ack(tcpcb=tcpcb, packet_rx=packet_rx)

        # check if all our seq are acked (including our FIN)
        if tcpcb.snd_una == tcpcb.snd_nxt:
            stop_rtx_timer(tcpcb=tcpcb)
            _change_state(tcpcb=tcpcb, new=STATES.TIME_WAIT)
            start_time_wait_timer(tcpcb=tcpcb)

        with tcpcb.tcpcb_lock:
            tcpcb.snd_r_buf_offset = (
                (tcpcb.snd_r_buf_offset + seq_acked - packet_rx.tcp.fin) % len(tcpcb.snd_buf)
            )

        _h_rx_wnd(tcpcb=tcpcb, packet_rx=packet_rx )

        return


    _send_ack(tcpcb=tcpcb)

def _tx_closing(tcpcb: TCPCB):
    """ tx h for closing """

    # NOTE: In this state, we are waiting for an ACK from the peer
    # to acknowledge our FIN. The RX routine for this state handles
    # the ACK reception and state transition, while this routine
    # (TX side) deals only with retransmission of unacknowledged
    # sequences (FIN or DATA+FIN) until the corresponding ACK arrives.

    with tcpcb.tcpcb_lock:
        close_req = tcpcb.close_requested

    data = _drain_snd_buf(tcpcb=tcpcb)

    if not data:
        if _h_active_close_tx(tcpcb=tcpcb, close_requested=close_req):
            return

        if tcpcb.snd_wnd > 0:
            # retransmit FIN segment
            _send_fin(tcpcb=tcpcb, next_state=None)

        return

    # Force shutdown_requested=True and close_requested=False.
    # This path is reached only during a graceful close, so we simulate it
    # by enabling shutdown behavior in the TX loop.
    _tx_loop(
        tcpcb=tcpcb,
        data=data,
        next_state=None,
        shutdown_requested=True,
        close_requested=False
    )


def _rx_close_wait(tcpcb: TCPCB, packet_rx: PacketRX):
    """ rx h for close w """

    # NOTE: This state indicates the peer has initiated connection termination.
    # Any incoming segment with data (SEG.LEN > 0) is ignored for processing purposes.
    # FIN handling does not alter state progression here.
    # The ACK number remains fixed at the last in-order sequence (rcv.nxt).
    # so do not use _h_rx_seq() here.
    if seq_leq(packet_rx.tcp.seq, tcpcb.rcv_nxt) \
    and seq_leq(tcpcb.rcv_nxt, last_seq(packet_rx=packet_rx)):

        if (
            _h_rx_rst(tcpcb=tcpcb, packet_rx=packet_rx)
            or _h_active_close_rx(tcpcb=tcpcb, packet_rx=packet_rx)
        ):
            return

        seq_acked = _h_rx_ack(tcpcb=tcpcb, packet_rx=packet_rx)

        # check if all our seq are acked
        if tcpcb.snd_una == tcpcb.snd_nxt:
            stop_rtx_timer(tcpcb=tcpcb)

        _h_rx_wnd(tcpcb=tcpcb, packet_rx=packet_rx)

        with tcpcb.tcpcb_lock:
            tcpcb.snd_r_buf_offset = (
                (tcpcb.snd_r_buf_offset + seq_acked - packet_rx.tcp.fin) & 0xFF_FF_FF_FF
            )

    tcpcb.core.tcp_events_schedule.schedule_event(
            event=TCPEvent(
            type_=TCPEventType.SEND,
            tcpcb=tcpcb
        )
    )

def _tx_close_wait(tcpcb: TCPCB):
    """ tx h for close w """

    with tcpcb.tcpcb_lock:
        close_req = tcpcb.close_requested
        shutdown_req = tcpcb.shutdown_requested

    data = _drain_snd_buf(tcpcb)

    if not data:
        if _h_active_close_tx(tcpcb=tcpcb, close_requested=close_req):
            return

        if close_req or shutdown_req:

            if tcpcb.snd_wnd > 0:
                _send_fin(tcpcb=tcpcb, next_state=STATES.LAST_ACK)
                return

        if tcpcb.ack_now:
            # ESTAB is going to CLOSE_WAIT when an acceptable FIN recvd
            # so that there is a pending ack must be sent
            _send_ack(tcpcb=tcpcb)
            tcpcb.ack_now = False
            return

        return # no fin must be sent, exit

    _tx_loop(
        tcpcb=tcpcb,
        data=data,
        next_state=STATES.LAST_ACK,
        close_requested=close_req,
        shutdown_requested=shutdown_req
    )


def _rx_last_ack(tcpcb: TCPCB, packet_rx: PacketRX):
    """ rx h for last ack """

    if seq_leq(packet_rx.tcp.seq, tcpcb.rcv_nxt) \
    and seq_leq(tcpcb.rcv_nxt, last_seq(packet_rx=packet_rx)):

        seq_acked = _h_rx_ack(tcpcb=tcpcb, packet_rx=packet_rx)

        # check if all our seq (including FIN) are acked
        if tcpcb.snd_una == tcpcb.snd_nxt:
            stop_rtx_timer(tcpcb=tcpcb)
            _change_state(tcpcb=tcpcb, new=STATES.CLOSED)

        _h_rx_wnd(tcpcb=tcpcb, packet_rx=packet_rx)

        with tcpcb.tcpcb_lock:
            tcpcb.snd_r_buf_offset = (
                (tcpcb.snd_r_buf_offset + seq_acked - packet_rx.tcp.fin) % len(tcpcb.snd_buf)
            )


def _tx_last_ack(tcpcb: TCPCB):
    """ tx h for last ack """
    # NOTE: this routine invoked only by rtx timer
    # when our FIN or data+FIN not acked yet
    # NOTE2: sins we reach this state, so a graceful close
    # can be happened.

    with tcpcb.tcpcb_lock:
        close_req = tcpcb.close_requested

    data = _drain_snd_buf(tcpcb=tcpcb)

    if not data:
        if tcpcb.snd_wnd > 0:
            _send_fin(tcpcb=tcpcb, next_state=None)

        return

    _tx_loop(
        tcpcb=tcpcb,
        data=data,
        next_state=None,
        close_requested=False,
        shutdown_requested=True
    )


def _rx_time_wait(tcpcb: TCPCB, packet_rx: PacketRX):
    """ rx h for time wait """

    if packet_rx.tcp.fin:
        _send_ack(tcpcb=tcpcb)
        stop_time_wait_timer(tcpcb=tcpcb)
        start_time_wait_timer(tcpcb=tcpcb)



# NOTE: rx/tx map indexing depends on STATES class
# LISTEN        =      0
# SYN_SENT      =      1
# SYN_RECV      =      2
# ESTAB         =      3
# FIN_WAIT_1    =      4
# FIN_WAIT_2    =      5
# CLOSE_WAIT    =      6
# CLOSING       =      7
# LAST_ACK      =      8
# TIME_WAIT     =      9
# CLOSED        =      10

_rx_map: list[Callable | None] = [
    None, # rx_listen not implemented yet
    _rx_syn_sent,
    _rx_syn_recv,
    _rx_estab,
    _rx_fin_wait_1,
    _rx_fin_wait_2,
    _rx_close_wait,
    _rx_closing,
    _rx_last_ack,
    _rx_time_wait
]

_tx_map: list[Callable | None] = [
    None, # tx_listen not implemented yet,
    _tx_syn_sent,
    _tx_syn_recv,
    _tx_estab,
    _tx_fin_wait_1,
    _tx_fin_wait_2,
    _tx_close_wait,
    _tx_closing,
    _tx_last_ack
]

def connect(tcpcb: TCPCB):
    """
    called by tcp-event-driven for:
    TCP Event Driven Type: CONNECT
    """
    _activ_open(tcpcb=tcpcb)

def tx(tcpcb: TCPCB):
    """
    called by tcp-event-driven for:
    TCP Event Driven Type: SEND
    """
    _tx_map[tcpcb.state](tcpcb)


def rx(tcpcb: TCPCB, packet_rx: PacketRX):
    """
    called by tcp-event-driven for:
    TCP Event Driven Type: RX
    """
    _rx_map[tcpcb.state](tcpcb, packet_rx)

def rtx(tcpcb: TCPCB):
    """
    called by tcp-event-driven for:
    TCP Event Driven Type: RTX
    """
    _rollback_to_una(tcpcb=tcpcb)
    tcpcb.rtx_timer = None
    tx(tcpcb=tcpcb)

































