from __future__ import annotations

from struct import unpack_from
from functools import cached_property

from typing import TYPE_CHECKING
from tipy.protocols.tcp.tcp import (
    TCP_EOL_KIND,
    TCP_NOP_KIND,
    TCP_MSS_KIND,

    TCP_MSS_LEN,
    TCP_NOP_LEN,
    )

if TYPE_CHECKING:
    from tipy.lib.packet import PacketRX


class TCPParser:

    __slots__ = ('_frame', '__dict__')

    def __init__(self, packet_rx: PacketRX):

        self._frame: memoryview = packet_rx.frame
        packet_rx.tcp = self


    @cached_property
    def src(self):
        return unpack_from('! H', self._frame, 0)[0]

    @cached_property
    def dst(self):
        return unpack_from('! H', self._frame, 2)[0]

    @cached_property
    def seq(self):
        return unpack_from('! L', self._frame, 4)[0]


    @cached_property
    def ack_seq(self):
        return unpack_from('! L', self._frame, 8)[0]

    @cached_property
    def doff(self):
        return (self._frame[12] >> 4) * 4

    @cached_property
    def flags(self):
        return self._frame[13]

    @property
    def cwr(self):
        return bool(self.flags & 0x80)

    @property
    def ece(self):
        return bool(self.flags & 0x40)

    @property
    def urg(self):
        return bool(self.flags & 0x20)

    @property
    def ack(self):
        return bool(self.flags & 0x10)

    @property
    def psh(self):
        return bool(self.flags & 0x08)

    @property
    def rst(self):
        return bool(self.flags & 0x04)

    @property
    def syn(self):
        return bool(self.flags & 0x02)

    @property
    def fin(self):
        return bool(self.flags & 0x01)


    @cached_property
    def window(self):
        return unpack_from('! H', self._frame, 14)[0]

    @cached_property
    def checksum(self):
        return unpack_from('! H', self._frame, 16)[0]

    @cached_property
    def urg_ptr(self):
        return unpack_from('! H', self._frame, 18)[0]

    @cached_property
    def options(self):
            frame = self._frame # local var better
            doff = self.doff
            options = dict()
            ptr = 20
            while ptr < doff:
                if frame[ptr] == TCP_MSS_KIND:
                    options[TCP_MSS_KIND] =\
                        unpack_from('! H', frame, ptr + 2)[0]
                    ptr += TCP_MSS_LEN

                elif frame[ptr] == TCP_NOP_KIND:
                    ptr += TCP_NOP_LEN

                elif frame[ptr] == TCP_EOL_KIND:
                    break
                else:
                    ptr+=1

            return options



    @cached_property
    def dlen(self):
        return len(self) - self.doff

    @cached_property
    def data(self):
        return self._frame[self.doff:]

    @cached_property
    def header(self):
        return self._frame[:self.doff]


    def __len__(self):
        return len(self._frame)

    def __str__(self):
        return (
            f"TCP {self.src} > {self.dst}, flags: "
            f"{"C" if self.cwr else "-"}"
            f"{"E" if self.ece else "-"}"
            f"{"U" if self.urg else "-"}"
            f"{"A" if self.ack else "-"}"
            f"{"P" if self.psh else "-"}"
            f"{"R" if self.rst else "-"}"
            f"{"S" if self.syn else "-"}"
            f"{"F," if self.fin else "-,"}"
            f" window {self.window}, seq {self.seq}, ack {self.ack_seq}, "
            f"dlen {self.dlen}"
        )



