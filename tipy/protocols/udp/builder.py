import struct
from tipy.lib.csum import inet_csum
from tipy.protocols.udp.udp import UDP_HEADER_LEN
from tipy.lib.tracker import Tracker

class UDPBuilder:
    def __init__(self,
                 src: int,
                 dst: int,
                 data: bytes,
                 tracker: Tracker | None,

                 ):

        self._src = src
        self._dst = dst
        self._data = data

        self.__tracker = Tracker(prefix='tx', echo_tracker=tracker)

    def __len__(self):
        return len(self._data) + UDP_HEADER_LEN

    def __str__(self) -> str:
        return f"UDP {self._src} > {self._dst}, len {len(self)}"

    def build(self, frame: memoryview, psum: int):
        struct.pack_into(
            f'! H H H H {len(self._data)}s',
            frame,
            0,
            self._src,
            self._dst,
            len(self),
            0,
            self._data
        )

        # recalculate checksum
        struct.pack_into(
            '! H',
            frame,
            6,
            inet_csum(data=frame, pseudo_sum=psum)
        )

    @property
    def tracker(self):
        return self.__tracker

    def to_bytes(self, ps_hdr_sum: int):
        frame = memoryview(bytearray(len(self)))
        self.build(frame=frame, psum=ps_hdr_sum)
        return bytes(frame)