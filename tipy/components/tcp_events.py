from __future__ import annotations

from time import sleep
from collections import deque
from threading import Condition, Thread

from tipy.lib.logger import log
from tipy.protocols.tcp.tcp import TCPEventType, TCPEvent

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from tipy.components.core import Core


from tipy.protocols.tcp.tcp_fsm import connect, tx, rx, rtx

MAX_EVENTS = 5000


def _h_active_open_event(event: TCPEvent):
    tcpcb = event.tcpcb
    connect(tcpcb=tcpcb)


def _h_rx_segment_event(event: TCPEvent):
    tcpcb = event.tcpcb
    rx(tcpcb=tcpcb, packet_rx=event.packet_rx)


def _h_send_event(event: TCPEvent):
    tcpcb = event.tcpcb
    tx(tcpcb=tcpcb)


def _h_rtx_event(event: TCPEvent):
    tcpcb = event.tcpcb
    rtx(tcpcb=tcpcb)


class TCPEvents:
    def __init__(self, core: Core | None = None):


        self._events_queue: deque[TCPEvent] = deque()
        self.core: Core = core
        self._stop_thread: bool = False
        self._cond: Condition = Condition()

        self._events_map: dict = {
            # event type : handler
            TCPEventType.CONNECT     : _h_active_open_event,
            TCPEventType.RX_SEGMENT  : _h_rx_segment_event,
            TCPEventType.SEND        : _h_send_event,
            TCPEventType.RTX         : _h_rtx_event
        }



    def start(self):
        Thread(target=self._tcp_events_loop, daemon=True).start()

    def shutdown(self):
        self._stop_thread = True
        with self._cond:
            self._cond.notify_all()
        __debug__ and log("stack",
                          "TCP Events shutdown",
                          level="INFO")



    def schedule_event(self, event: TCPEvent):
        with self._cond:
            self._events_queue.append(event)
            self._cond.notify()

    def _tcp_events_loop(self):
        if __debug__:
            log("stack",
                "TCP Events Started",
                level="INFO")

        while not self._stop_thread:

            q = self._events_queue
            cond = self._cond
            handlers = self._events_map

            with self._cond:
                if not q:
                    cond.wait()
                l = len(q)

            for x in range(min(MAX_EVENTS, l)):
                ev = q.popleft()
                handlers[ev.type](ev)

            sleep(0) # this may release the GIL. IDK...











