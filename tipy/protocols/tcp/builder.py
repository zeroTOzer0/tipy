from __future__ import annotations

import struct

from tipy.lib.csum import inet_csum
from tipy.lib.tracker import Tracker
from tipy.config.config import MSS
from tipy.protocols.tcp.tcp import (TCP_DOFF,
                                    TCP_EOL_LEN,
                                    TCP_NOP_LEN,
                                    TCP_MSS_LEN)


def _tcp_opt_padding(opt: list[TCPOptEOL | TCPOptNOP | TCPOptMSS]):
    """
    Used when TCP options exist. Adds EOL padding as needed.
    """
    l = sum(len(_) for _ in opt)
    pad = (-l) % 4
    if pad:
        opt.append(TCPOptEOL(count=pad))

class TCPBuilder:
    def __init__(self,
                 *,
                 src: int,
                 dst: int,
                 seq: int,
                 ack_seq: int,
                 cwr: bool = False,
                 ece: bool = False,
                 urg: bool = False,
                 ack: bool = False,
                 psh: bool = False,
                 rst: bool = False,
                 syn: bool = False,
                 fin: bool = False,
                 window: int,
                 urg_ptr: int = 0,
                 options: TCPOptBuilder|None = None,
                 data: memoryview,

                 tracker: Tracker | None,
                 ):

        self._src:  int = src
        self._dst: int = dst
        self._seq: int = seq
        self._ack_seq: int = ack_seq
        self._cwr: bool = cwr
        self._ece: bool = ece
        self._urg: bool = urg
        self._ack: bool = ack
        self._psh: bool = psh
        self._rst: bool = rst
        self._syn: bool = syn
        self._fin: bool = fin
        self._window: int = window
        self._urg_ptr: int = urg_ptr
        self._options: TCPOptBuilder|None = options
        self._data: memoryview = data

        self._doff: int = TCP_DOFF if not self._options \
                                    else (len(self._options) // 4) + TCP_DOFF
        self._tracker = Tracker(prefix='tx', echo_tracker=tracker)


    def build(self, frame: memoryview, psum: int):
        data_offset = 20
        struct.pack_into(
            f'! H H L L H H H H',
            frame,
            0,
            self._src,
            self._dst,
            self._seq,
            self._ack_seq,
            self._doff << 12
            | self._cwr << 7
            | self._ece << 6
            | self._urg << 5
            | self._ack << 4
            | self._psh << 3
            | self._rst << 2
            | self._syn << 1
            | self._fin,
            self._window,
            0, #check sum placeholder
            self._urg_ptr,
        )

        if self._options:
            self._options.build(frame=frame, offset=20)
            data_offset += len(self._options)

        frame[data_offset:data_offset+len(self._data)] = self._data

        # recalculate checksum
        struct.pack_into(
            '! H',
            frame,
            16,
            inet_csum(data=frame, pseudo_sum=psum)
        )


    def __len__(self):
        return self._doff * 4 + len(self._data)

    def __str__(self):
        return (
            f"TCP {self._src} > {self._dst}, flags: "
            f"{"C" if self._cwr else "-"}"
            f"{"E" if self._ece else "-"}"
            f"{"U" if self._urg else "-"}"
            f"{"A" if self._ack else "-"}"
            f"{"P" if self._psh else "-"}"
            f"{"R" if self._rst else "-"}"
            f"{"S" if self._syn else "-"}"
            f"{"F," if self._fin else "-,"}"
            f" window {self._window}, seq {self._seq}, ack {self._ack_seq}"
            f"{f", [{self._options}]" if self._options else ""}"
        )


    @property
    def tracker(self):
        return self._tracker

    def to_bytes(self, ps_hdr_sum: int):
        frame = memoryview(bytearray(len(self)))
        self.build(frame=frame, psum=ps_hdr_sum)
        return bytes(frame)



class TCPOptEOL:
    def __init__(self, count: int = 1):
        self._count = count

    def build(self, frame, offset):
        struct.pack_into(
            f'! {self._count}B',
            frame,
            offset,
            0
        )
    def __len__(self):
        return self._count

    def __str__(self):
        return f"{self._count}*EOL"


class TCPOptNOP:

    def build(self, frame, offset):
        struct.pack_into(
            f'! B',
            frame,
            offset,
            1
        )
    def __len__(self):
        return TCP_NOP_LEN

    def __str__(self):
        return f"NOP"

class TCPOptMSS:
    def build(self, frame, offset):
        struct.pack_into(
            '! BBH',
            frame,
            offset,
            2, TCP_MSS_LEN, MSS
        )

    def __len__(self):
        return TCP_MSS_LEN

    def __str__(self):
        return f"MSS={MSS}"

class TCPOptBuilder:
    def __init__(self, options: list[TCPOptNOP
                                    |TCPOptMSS
                                    |TCPOptEOL]):

        # Note that the sending interface doesn't deal with
        # TCP-EOL option. this is the TCPBuilder Module responsibility

        self._options = options

        if len(self) > 40:
            raise ValueError("TCP options exceed 40 bytes")

        # add EOL if needed as end_of_opt & padding
        _tcp_opt_padding(self._options)

    def build(self, frame, offset):
        for opt in self._options:
            opt.build(frame, offset)
            offset+=len(opt)



    def __len__(self):
        return sum(len(opt) for opt in self._options)

    def __str__(self):
        return ", ".join(str(opt) for opt in self._options)





