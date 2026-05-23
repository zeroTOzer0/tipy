# get the bytes from iface
# pars it using prx_ether

from __future__ import annotations

from tipy.lib.packet import PacketRX
from tipy.lib.logger import log
import os
from threading import Condition, Thread, Event
from collections import deque
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from tipy.components.core import Core

class RXRing:
    def __init__(self, core: Core | None = None):

        # initialize queue
        self._queue: deque[PacketRX] = deque()
        self._is_enqueued: Condition = Condition()
        self._stop_thread: bool = False

        self._receiver_is_ready = Event()
        self.core: Core = core

        self.iface: int | None = None # tap interface fd


    def start(self):
        Thread(target=self._rx_loop, daemon=True).start()
        # make sur the "self.__receive" is started first
        self._receiver_is_ready.wait()
        # Ensure receiver runs first so dequeue thread doesn’t wait unnecessarily
        Thread(target=self._dequeue, daemon=True).start()

    def shutdown(self):
        if __debug__:
            log(
                "stack",
                "RX ring shutdown",
                level="INFO"
            )
        self._stop_thread = True


    def _rx_loop(self):
        if __debug__:
            log(
                "stack",
                "RX ring started",
                level="INFO"
            )        # en-queueing to queue
        self._receiver_is_ready.set()
        while not self._stop_thread:
            data = os.read(self.iface, 2048)
            packet_rx = PacketRX(data)
            with self._is_enqueued:
                self._queue.append(packet_rx)
                if __debug__:
                    log(
                        "rx-ring",
                        f"[{packet_rx.tracker}] RX frame received, {len(packet_rx.frame)}B",
                        level="DEBUG"
                    )

                self._is_enqueued.notify()


    def _dequeue(self):
        while not self._stop_thread:
            batch: list[PacketRX] = []
            with self._is_enqueued:
                if not self._queue:
                    self._is_enqueued.wait()
                while self._queue:
                    batch.append(self._queue.popleft())

            if __debug__:
                log(
                    "rx-ring",
                    f"RX batch dequeue: {len(batch)} frames",
                    level="DEBUG"
                )
            self._deque_batch(batch)


    def _deque_batch(self, b: list[PacketRX]):
        for _ in b:
            self.core.handle_packet(_)
        b = []
