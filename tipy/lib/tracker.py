from __future__ import annotations
import time

class Tracker:

    serial_rx = 0
    serial_tx = 0

    def __init__(self,
                 prefix: str,
                 echo_tracker: Tracker | None = None,
                 serial: str | None = None
                 ):

        self.__echo_tracker: Tracker | None = echo_tracker
        self.__timestamp = time.monotonic()

        if serial:
            self.__serial: str = serial
            return

        if prefix == 'rx':
            self.__serial = f'{prefix}{self.serial_rx:0>4x}'.upper()
            Tracker.serial_rx = (
                (Tracker.serial_rx + 1) & 0xFFFF
            )


        if prefix == 'tx':
            self.__serial = f'{prefix}{self.serial_rx:0>4x}'.upper()
            Tracker.serial_tx = (
                (Tracker.serial_tx + 1) & 0xFFFF
            )


    def __str__(self):
        if self.__echo_tracker:
            return f"{self.__serial} -> {self.__echo_tracker}"

        return self.__serial

    def timestamp(self):
        return self.__timestamp

    @property
    def latency(self):
        if self.__echo_tracker:
            return f'{(time.monotonic() - self.__echo_tracker.timestamp())* 1000:.3f}ms'
        return ""