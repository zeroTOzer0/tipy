from __future__ import annotations

import os

from tipy.protocols.ether.builder import EtherBuilder
from tipy.config.config import MTU

from tipy.lib.logger import log

from threading import Condition, Thread
from collections import deque

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from tipy.components.core import Core

class TXRing:
    def __init__(self, core: Core | None = None):

        # initialize queue
        self._queue: deque[EtherBuilder] = deque()
        self._is_enqueued: Condition = Condition()
        self._stop_thread: bool = False

        self.iface: int|None = None



    def start(self):
        Thread(target=self._tx_loop, daemon=True).start()

    def shutdown(self):
        if __debug__:
            log(
                "stack",
                "TX ring shutdown",
                level="INFO"
            )
        self._stop_thread = True

    def enqueue(self, frame: EtherBuilder):
       with self._is_enqueued:
            self._queue.append(frame)

            if __debug__:
                log(
                    "tx-ring",
                    f"frame enqueued (queue={len(self._queue)})",
                    level="DEBUG"
                )

            self._is_enqueued.notify()

    def _tx_loop(self):
        if __debug__:
            log(
                "stack",
                "TX ring started",
                level="INFO"
            )

        # de-queueing from queue
        while not self._stop_thread:
            with self._is_enqueued:
                if not self._queue:
                    self._is_enqueued.wait()
                packet: EtherBuilder = self._queue.popleft()
                if __debug__:
                    log(
                        "tx-ring",
                        f"[{packet.tracker}] TX sent, {len(packet)}B, latency={packet.tracker.latency}",
                        level="DEBUG"
                    )

                frame = memoryview(bytearray(MTU + 14))

                packet.build(frame=frame)
                frame = frame[:len(packet)]
                os.write(self.iface, frame)
