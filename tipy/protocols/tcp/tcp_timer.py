from __future__ import annotations

from tipy.protocols.tcp.tcpcb import remove_tcpcb
from tipy.protocols.tcp.tcp import (
TCPEvent, TCPEventType
)

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tipy.protocols.tcp.tcpcb import TCPCB

RTX_TIMEOUT = 1.5 # TODO: use dynamic RTO calc
TIME_WAIT_TIMEOUT = 30

def start_rtx_timer(tcpcb: TCPCB):
    """
    start retransmission timer
    """
    if not tcpcb.rtx_timer:
        tcpcb.rtx_timer = tcpcb.core.timer.schedule_timer(
            expire_after=RTX_TIMEOUT,
            remove_at_execute=True,
            call=lambda: tcpcb.core.tcp_events_schedule.schedule_event(
                            event=TCPEvent(
                            type_=TCPEventType.RTX,
                            tcpcb=tcpcb
                            )
                        ),
            timer_name='tcp-rtx'
        )

def start_time_wait_timer(tcpcb: TCPCB):
    tcpcb.time_wait_timer = tcpcb.core.timer.schedule_timer(
        expire_after=TIME_WAIT_TIMEOUT,
        remove_at_execute=True,
        call=lambda: remove_tcpcb(tcpcb=tcpcb),
        timer_name='time-wait'
    )

def stop_rtx_timer(tcpcb: TCPCB):
    if tcpcb.rtx_timer:
        tcpcb.rtx_timer.remove()
        tcpcb.rtx_timer = None

def stop_time_wait_timer(tcpcb: TCPCB):
    if tcpcb.time_wait_timer:
        tcpcb.time_wait_timer.remove()
        tcpcb.time_wait_timer = None


def stop_all_timers(tcpcb: TCPCB):
    stop_rtx_timer(tcpcb=tcpcb)
    stop_time_wait_timer(tcpcb=tcpcb)




