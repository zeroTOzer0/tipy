import struct
from tipy.lib.tracker import Tracker

class RAWBuilder:
    def __init__(self, data: bytes, echo_tracker: Tracker | None = None) -> None:
        self._data = data
        self._tracker = Tracker(prefix='tx', echo_tracker=echo_tracker)
    def __len__(self):
        """ len ddm: return data length """
        return len(self._data)

    def __str__(self):
        return f"RAW {len(self)} raw bytes"

    def build(self, frame: memoryview, psum: int=0) -> None:
        frame[:len(self._data)] = self._data

    def to_bytes(self):
        return bytes(self._data)

    @property
    def tracker(self):
        return self._tracker

