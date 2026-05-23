from __future__ import annotations

import struct

from tipy.config.config import  MTU
from tipy.lib.csum import inet_csum
from tipy.lib.tracker import Tracker
from tipy.lib.ip_address import IPAddress
from tipy.protocols.ip.ip import (
    IP_TTL,
    IP_VERSION,
    IP_PROTO,
    IP_IHL,
    IP_OPT_NOP_LEN,
)



from tipy.protocols.ip.exceptions import IPBadOptionError

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tipy.protocols.raw.builder import RAWBuilder
    from tipy.protocols.icmp.builder import ICMPBuilder
    from tipy.protocols.udp.builder import UDPBuilder


def _ip_opt_padding(opt: list[IPOptLSRR
                              | IPOptNOP
                              | IPOptEOL
                              | IPOptUnknown
                              ]):
    """
    Used when IP options exist. Adds EOL padding as needed.
    """
    l = sum(len(_) for _ in opt)
    r = l % 4
    if r != 0:
        opt.append(
            IPOptEOL(padd_count=4 - r)
        )

class IPBuilder:
    def __init__(self,
                 *,
                 payload: RAWBuilder | UDPBuilder | ICMPBuilder,
                 id: int,
                 ttl: int = IP_TTL,
                 protocol: int = 255,
                 offset: int = 0,
                 flag_df: bool = False,
                 flag_mf: bool = False,
                 src: IPAddress,
                 dst: IPAddress,
                 options: list[IPOptLSRR
                              |IPOptNOP
                              |IPOptEOL
                              |IPOptUnknown
                              ] | None = None
                 ) -> None:

        self.__payload = payload
        self.__payload_length: int = len(self.__payload)
        self.__id: int = id
        self.__offset: int = offset
        self.__flag_df: bool = flag_df
        self.__flag_mf: bool = flag_mf
        self.__ttl: int = ttl
        self.__protocol: int = protocol
        self.__options: list[IPOptLSRR
                              |IPOptNOP
                              |IPOptEOL
                              |IPOptUnknown
                              ] | None = options

        self.__version: int = IP_VERSION
        self.__ihl: int = IP_IHL if not self.__options else sum(len(opt) for opt in self.__options) // 4 \
                                                       + IP_IHL
        self.__tos: int = 0
        self.__total_len: int = (self.__ihl * 4) + self.__payload_length
        self.__checksum: int = 0
        self.__src: IPAddress = src
        self.__dst: IPAddress = dst


    def psum(self):
        """
        pseudo header sum
        """
        hdr = struct.pack(
                '! 4s 4s B B H',
                self.__src.ip2raw(),
                self.__dst.ip2raw(),
                0,
                self.__protocol,
                self.__total_len - self.__ihl*4
            )

        return sum(struct.unpack('!3L', hdr))


    def build(self, frame: memoryview):

        struct.pack_into(
            '! B B H H H B B H 4s 4s',
            frame,
            0,
            self.__version << 4 | self.__ihl,
            self.__tos,
            self.__total_len,
            self.__id,
            self.__flag_df << 14 | self.__flag_mf << 13 | self.__offset,
            self.__ttl,
            self.__protocol,
            self.__checksum,
            self.__src.ip2raw(),
            self.__dst.ip2raw(),
        )

        if self.__options:
            offset = 20
            for opt in self.__options:
                opt.build(frame=frame, offset=offset)
                offset+=len(opt)

        # Recalculate checksum
        struct.pack_into(
            '! H',
            frame,
            10,
            inet_csum(frame)
        )

        self.__payload.build(frame=frame[self.__ihl*4:], psum=self.psum())


    def __len__(self):
        return self.__ihl*4 + len(self.__payload)

    def __str__(self):
        return (
            f"{self.__src} > {self.__dst}, proto {self.__protocol} "
            f"({IP_PROTO.get(self.__protocol, '???')}) "
            f"id {self.__id},"
            f"{' DF,' if self.__flag_df else ''}"
            f" hlen {self.__ihl*4} bytes, "
            f'plen {self.__total_len - self.__ihl*4} bytes'
            f', options ({", ".join(f"{opt}(<ly>{len(opt)} bytes</>)" for opt in (self.__options or []))})'
        )

    @property
    def tracker(self):
        return self.__payload.tracker

class IPFragBuilder:
    def __init__(self,
                 *,
                 payload: bytes, # bytes needed, because of fragmentation
                 id: int,
                 ttl: int = IP_TTL,
                 protocol: int = 255,
                 offset: int = 0,
                 flag_df: bool=False,
                 flag_mf: bool=True,
                 src: IPAddress,
                 dst: IPAddress,
                 options: list[IPOptLSRR
                              |IPOptNOP
                              |IPOptEOL
                              |IPOptUnknown
                              ] | None = None,
                 tracker: Tracker | None=None,
                ):

        self._tracker = Tracker(prefix='tx', echo_tracker=tracker)

        self._payload = payload

        self._id: int = id
        self._offset: int = offset
        self._flag_df: bool = flag_df
        self._flag_mf: bool = flag_mf
        self._ttl: int = ttl
        self._protocol: int = protocol
        self._options: list[IPOptLSRR
                              |IPOptNOP
                              |IPOptEOL
                              |IPOptUnknown
                              ] | None = options

        self._version = IP_VERSION
        self._ihl = IP_IHL if not self._options else sum(len(opt) for opt in self._options) // 4 \
                                                       + IP_IHL
        self._tos = 0
        self._total_len = (self.__ihl * 4) + len(self._payload)
        self._checksum = 0
        self._src = src
        self._dst = dst


        self._frags = []

    def _fragment(self):

        offset = 0
        while self._total_len > MTU:
            nfb = (MTU - self._ihl*4) // 8
            data_portion = self._payload[:nfb*8]
            self._create_frags(
                data_portion,
                offset,
                True,
                self._options
            )

            # reset fields :
            self._payload = self._payload[nfb*8:]

            if self._options:
                self._options = [opt for opt in self._options if opt.copy_flag] if self._options else None
                # add EOL if needed
                _ip_opt_padding(self._options)
                self.__ihl = IP_IHL if not self._options else sum(len(opt) for opt in self._options) // 4 \
                                                                                             + IP_IHL
            self.__total_len = (self.__ihl * 4) + len(self._payload)
            offset += nfb

        nfb = (MTU - self.__ihl * 4) // 8
        self._create_frags(
            self._payload, # The rest of the payload
            offset,
            False,
            self._options,

        )

    def _create_frags(self, data_portion, offset, flag_mf, options):
        frag = IPFragBuilder(
            payload=data_portion,
            id=self._id,
            ttl=self._ttl,
            protocol=self._protocol,
            offset=offset,
            flag_df=False,
            flag_mf=flag_mf,
            src=self._src,
            dst=self._dst,
            options=options,
            tracker=self._tracker
        )
        self._frags.append(frag)

    def get_frags(self):
        self._fragment()
        return self._frags



    def ps_hdr_sum(self):
        hdr = struct.pack(
                '! 4s 4s B B H',
                self._src.ip2raw(),
                self._dst.ip2raw(),
                0,
                self._protocol,
                self._total_len - self.__ihl*4
            )

        return sum(struct.unpack('!3L', hdr))

    def build(self, frame: memoryview):
        struct.pack_into(
            '! B B H H H B B H 4s 4s',
            frame,
            0,
            self._version << 4 | self.__ihl,
            self._tos,
            self._total_len,
            self._id,
            self._flag_df << 14 | self._flag_mf << 13 | self._offset,
            self._ttl,
            self._protocol,
            self._checksum,
            self._src.ip2raw(),
            self._dst.ip2raw(),
        )
        if self._options:
            offset = 20
            for opt in self._options:
                opt.build(frame=frame, offset=offset)
                offset+=len(opt)

        # Recalculate checksum
        struct.pack_into(
            '! H',
            frame,
            10,
            inet_csum(frame)
        )

        # append payload
        struct.pack_into(
            f'! {len(self._payload)}s',
            frame,
            self.__ihl*4,
            self._payload
        )

    @property
    def tracker(self):
        return self._tracker


    def __len__(self):
        return self.__ihl*4 + len(self._payload)

    def __str__(self):
        return (
            f"{self._src} > {self._dst}, proto {self._protocol} "
            f"({IP_PROTO.get(self._protocol, '???')}) "
            f"id {self._id},"
            f"{' DF,' if self._flag_df else ''}"
            f"{' MF,' if self._flag_mf else ''}"
            f" offset {self._offset}, "
            f"hlen {self._ihl*4} bytes, "
            f'plen {self._total_len - self._ihl*4} bytes' #plen -> payload
            f', options ({", ".join(f"{opt}(<ly>{len(opt)} bytes</>)" for opt in (self._options or []))})'
        )


class IPOptEOL:
    """ type : 0 """
    def __init__(self, padd_count: int=1):
        self.copy_flag: bool = False
        self._padd_count = padd_count


    def build(self, frame: memoryview, offset: int):
        struct.pack_into(
            f'! {self._padd_count}s',
            frame,
            offset,
            bytes(0)
        )

    def __str__(self):
        return "ip-opt-EOL"

    def __len__(self):
        return self._padd_count

class IPOptNOP:
    """ type : 1 """
    def __init__(self, opt: int=1):
        self.copy_flag: bool = False
        self._opt = opt

    def build(self, frame: memoryview, offset: int):
        struct.pack_into('! B',
                                frame,
                                offset,
                                self._opt
                           )


    def __str__(self):
        return "ip-opt-NOP"

    def __len__(self):
        return IP_OPT_NOP_LEN

class IPOptLSRR:
    """ type : 131 """
    def __init__(self, opt: bytearray, start: int, end: int):
        self.copy_flag: bool = True
        self._opt = opt
        self._start = start
        self._end = end

    def build(self, frame: memoryview, offset: int):
        struct.pack_into(f'! {len(self._opt[self._start:self._start+self._end])}s',
                                frame,
                                offset,
                                self._opt
                                )

    def __str__(self):
        return "ip-opt-LSRR"

    def __len__(self):
        return len(self._opt)


class IPOptUnknown:
    """ type : UNK """
    def __init__(self, opt: bytearray, start: int, end: int):
        self._opt = opt
        self.copy_flag: bool = False
        self._start = start
        self._end = end

    def build(self, frame: memoryview, offset: int):
        # ignore...
        return

    def __str__(self):
        return f"ip-opt-UNK:{bytes(self._opt[self._start:])}"

    def __len__(self):
        return len(self._opt[self._start:])



class IPOptBuilder:
    IP_OPTIONS_MAP: dict[int, tuple] = {
        # opt-ID : (opt-class, is_variable_in_length)
         0   : (IPOptEOL, False),
         1   : (IPOptNOP, False),
         131 : (IPOptLSRR, True)
    }



    def __init__(self, raw_opts: bytearray|None):
        self._raw_opts: bytearray = raw_opts
        self._opts: list = []

    def build(self) -> list|None:
        if not self._raw_opts:
            return None
        if len(self._raw_opts) > 40:
            # log buff overflow
            return None

        self.__parse()
        return self._opts

    def __parse(self):
        ptr = 0
        raw_opt_len = len(self._raw_opts)
        while ptr < raw_opt_len:
            if self._raw_opts[ptr] in IPOptBuilder.IP_OPTIONS_MAP:
                cls, varlen = IPOptBuilder.IP_OPTIONS_MAP[self._raw_opts[ptr]]
                if not varlen: # single-octet
                    self._opts.append(
                        cls(self._raw_opts)
                    )
                    ptr += 1
                else:
                    if ptr + 1 >= raw_opt_len:
                        # Bad opt
                        raise IPBadOptionError('IP BAD OPT')

                    len_fld = self._raw_opts[ptr+1] # option len field
                    self._opts.append(
                        cls(opt=self._raw_opts, start=ptr, end=len_fld)
                    )
                    ptr += len_fld
            else:
                # Unknown option (length cannot be determined).
                # Pack remaining bytes into IPOptUnknown and break.
                # IPOptUnknown.build() will not pack this data into header.
                self._opts.append(
                    IPOptUnknown(opt=self._raw_opts[ptr:], start=ptr, end=len(self._raw_opts))
                )
                break


        # add EOL if needed
        _ip_opt_padding(self._opts)

