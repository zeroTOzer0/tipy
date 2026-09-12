from __future__ import annotations

from tipy.protocols.tcp.tcpcb import remove_tcpcb
from tipy.lib.logger import log
from tipy.protocols.tcp.tcp import (
TCPEvent, TCPEventType
)

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tipy.protocols.tcp.tcpcb import TCPCB

TIME_WAIT_TIMEOUT = 30

K = 4
G = 0.001 # Timer clock G is 1ms (0.001 sec)
MAX_RTO = 60.0
MIN_RTO = 1.0
BETA = 1/4  # [RFC 6298, (2.3)]
ALPHA = 1/8 # [RFC 6298, (2.3)]

def set_initial_rto(tcpcb: TCPCB):
    """
    Initialize the TCP retransmission timeout (RTO) from the first RTT sample.
    then clear the RTT sample so "tcpcb.rtt" can be reused for the next sample.
    """
    # [RFC 6298, (2.2)]
    tcpcb.srtt = tcpcb.rtt
    tcpcb.rttvar = tcpcb.rtt / 2
    tcpcb.rto = max(tcpcb.srtt + max(G , K * tcpcb.rttvar), MIN_RTO)

    if __debug__:
        log(
            "tcpcb",
            f"{tcpcb}: initial RTO: rtt={tcpcb.rtt:.3f}sec, "
            f"srtt={tcpcb.srtt:.3f}sec, rttvar={tcpcb.rttvar:.3f}sec, "
            f"rto={tcpcb.rto:.3f}sec",
            "DEBUG"
        )

    tcpcb.rtt = None

def set_new_rto(tcpcb: TCPCB):
    """
    Update the TCP retransmission timeout (RTO) from a new RTT sample.
    then clear the RTT sample so "tcpcb.rtt" can be reused for the next sample.
    """
    # [RFC 6298, (5)]

    # Reinitialize the estimator if it was cleared after RTO backoff.
    if tcpcb.srtt is None or tcpcb.rttvar is None:
        set_initial_rto(tcpcb=tcpcb)
        return

    tcpcb.rttvar = (
        (1 - BETA) * tcpcb.rttvar + BETA * abs(tcpcb.srtt - tcpcb.rtt)
    )

    tcpcb.srtt = (
        (1 - ALPHA) * tcpcb.srtt + ALPHA * tcpcb.rtt
    )

    tcpcb.rto = max(tcpcb.srtt + max(G, K * tcpcb.rttvar), MIN_RTO)

    if __debug__:
        log(
            "tcpcb",
            f"{tcpcb}: new RTO: rtt={tcpcb.rtt:.3f}sec, "
            f"srtt={tcpcb.srtt:.3f}sec, rttvar={tcpcb.rttvar:.3f}sec, "
            f"rto={tcpcb.rto:.3f}sec",
            "DEBUG"
        )

    tcpcb.rtt = None

def back_off_rto(tcpcb: TCPCB):
    """
    Back off the retransmission timeout after an RTO expiration.

    Double the current RTO, capped at MAX_RTO, and discard the RTT
    estimator state. A new RTT measurement will reinitialize the
    estimator.
    """
    back_off = min(tcpcb.rto * 2, MAX_RTO)

    if __debug__:
        log(
            "tcpcb",
            f"{tcpcb}: RTO backoff: {tcpcb.rto:.3f} -> {back_off:.3f}",
            "DEBUG",
        )

    tcpcb.rto = back_off
    tcpcb.rttvar = tcpcb.srtt = tcpcb.rtt = None

def start_rtx_timer(tcpcb: TCPCB):
    """
    start retransmission timer
    """
    if not tcpcb.rtx_timer:
        tcpcb.rtx_timer = tcpcb.core.timer.schedule_timer(
            expire_after=tcpcb.rto,
            remove_at_execute=True,
            call=lambda: tcpcb.core.tcp_events_schedule.schedule_event(
                            event=TCPEvent(
                            type_=TCPEventType.RTX,
                            tcpcb=tcpcb
                            )
                        ),
            timer_name='tcp-rtx'
        )

def restart_rtx_timer(tcpcb: TCPCB):
    """
    restart retransmission timer
    """
    if tcpcb.rtx_timer is not None:
        tcpcb.rtx_timer.remove()

    tcpcb.rtx_timer = tcpcb.core.timer.schedule_timer(
        expire_after=tcpcb.rto,
        remove_at_execute=True,
        call=lambda: tcpcb.core.tcp_events_schedule.schedule_event(
            event=TCPEvent(
                type_=TCPEventType.RTX,
                tcpcb=tcpcb
            )
        ),
        timer_name='(restart)tcp-rtx'
    )

def stop_rtx_timer(tcpcb: TCPCB):
    if tcpcb.rtx_timer:
        tcpcb.rtx_timer.remove()
        tcpcb.rtx_timer = None

def start_time_wait_timer(tcpcb: TCPCB):
    tcpcb.time_wait_timer = tcpcb.core.timer.schedule_timer(
        expire_after=TIME_WAIT_TIMEOUT,
        remove_at_execute=True,
        call=lambda: remove_tcpcb(tcpcb=tcpcb),
        timer_name='tcp-time-wait'
    )

def stop_time_wait_timer(tcpcb: TCPCB):
    if tcpcb.time_wait_timer:
        tcpcb.time_wait_timer.remove()
        tcpcb.time_wait_timer = None

def stop_all_timers(tcpcb: TCPCB):
    stop_rtx_timer(tcpcb=tcpcb)
    stop_time_wait_timer(tcpcb=tcpcb)




