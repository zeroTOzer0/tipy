from __future__ import annotations

from struct import unpack_from

from functools import cached_property

from tipy.protocols.icmp.icmp import (
    UNREACHABLE_CODES,
    DESTINATION_UNREACHABLE,
    ECHO_REQUEST,
    ECHO_REPLY,
    TIME_EXCEEDED,
    TIME_EXCEEDED_CODES

)

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from tipy.lib.packet import PacketRX



class ICMPParser:

    __slots__ = ('_frame', '__dict__')

    def __init__(self, packet_rx: PacketRX):
        self._frame = packet_rx.frame
        packet_rx.icmp = self


    @cached_property
    def type(self):
        return self._frame[0]

    @cached_property
    def code(self):
        return self._frame[1]

    @cached_property
    def checksum(self):
        return unpack_from('!H', self._frame, 2)[0]

    @cached_property
    def echo_id(self):
        return unpack_from('!H', self._frame, 4)[0]

    @cached_property
    def echo_seq(self):
        return unpack_from('!H', self._frame, 6)[0]

    @cached_property
    def err_data(self):
        return self._frame[8:]

    @cached_property
    def echo_data(self):
        return self._frame[8:]

    @cached_property
    def packet(self) :
        """
        Read the whole packet.
        """
        return self._frame

    @cached_property
    def dlen(self):
        return len(self._frame[8:])

    @cached_property
    def header(self):
        return self._frame[:8]


    def __len__(self) -> int:
        return len(self._frame)

    def __str__(self) -> str:
        if self.type == DESTINATION_UNREACHABLE:
            return (f"DESTINATION_UNREACHABLE/"
                    f"{UNREACHABLE_CODES.get(self.code, '???')}, "
                    f"dlen {len(self.err_data)}")

        if self.type == TIME_EXCEEDED:
            return (
                f"TIME_EXCEEDED/"
                f"{TIME_EXCEEDED_CODES.get(self.code, '???')}, "
                f"dlen {len(self) - 8}"
            )

        if self.type == ECHO_REQUEST and self.code == 0:
            return f"echo_request, id {self.echo_id}, seq {self.echo_seq}, dlen {len(self.echo_data)}"

        if self.type == ECHO_REPLY and self.code == 0:
            return (
                f"echo_reply, id {self.echo_id}, "
                f"seq {self.echo_seq}, dlen {len(self.echo_data)}"
            )

        return 'icmp-echo-rep'
