
import struct
from tipy.protocols.icmp.icmp import (
    UNREACHABLE_CODES,
    TIME_EXCEEDED_CODES,
    TIME_EXCEEDED,
    DESTINATION_UNREACHABLE,
    ECHO_REPLY,
    ECHO_REQUEST

)

from tipy.lib.csum import inet_csum
from tipy.lib.tracker import Tracker


class ICMPBuilder:
    def __init__(self,
                 type: int,
                 code: int,
                 data: bytes | None = None,
                 echo_id: int | None = None,
                 echo_seq: int | None = None,
                 tracker: Tracker | None = None,
                 ):

        self._type: int = type
        self._code: int = code
        self._data: bytes | None = data

        self._echo_id: int | None = echo_id
        self._echo_seq: int | None = echo_seq

        self.__tracker = Tracker(prefix='tx', echo_tracker=tracker)


    def build(self, frame: memoryview, psum: int=0):
        if self._type in (DESTINATION_UNREACHABLE, TIME_EXCEEDED):
            struct.pack_into(
                f'! B B H L {len(self._data)}s',
                frame,
                0,
                self._type,
                self._code,
                0, # chksum placeholder
                0,
                self._data
            )

            struct.pack_into(
                f'! H',
                frame,
                2,
                inet_csum(data=frame)
            )

        elif self._type in (ECHO_REQUEST, ECHO_REPLY):
            struct.pack_into(
                f'! B B H H H {len(self._data)}s',
                frame,
                0,
                self._type,
                self._code,
                0,  # checksum placeholder
                self._echo_id,
                self._echo_seq,
                self._data
            )
            # recalculate checksum
            struct.pack_into(
                f'! H',
                frame,
                2,
                inet_csum(data=frame)
            )


    def __len__(self):
        return len(self._data) + 8

    def __str__(self):
        if self._type == DESTINATION_UNREACHABLE:
            return (
                f"DESTINATION_UNREACHABLE/"
                f"{UNREACHABLE_CODES.get(self._code, '???')}, "
                f"dlen {len(self) - 8}"
            )

        if self._type == TIME_EXCEEDED:
            return (
                f"TIME_EXCEEDED/"
                f"{TIME_EXCEEDED_CODES.get(self._code, '???')}, "
                f"dlen {len(self) - 8}"
            )

        if self._type == ECHO_REQUEST and self._code == 0:
            return (
                f"echo_request, id {self._echo_id}, "
                f"seq {self._echo_seq}, dlen {len(self._data)}"
            )

        if self._type == ECHO_REPLY and self._code == 0:
            return (
                f"echo_reply, id {self._echo_id}, "
                f"seq {self._echo_seq}, dlen {len(self._data)}"
            )


        return f'UNSUPPORTED_ICMP_MESSAGE, type {self._type}, code {self._code}, dlen {len(self._data)}'

    @property
    def tracker(self):
        return self.__tracker