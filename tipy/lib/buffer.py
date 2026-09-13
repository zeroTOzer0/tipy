from tipy.lib.logger import log
from threading import RLock

# Ring buffers intentionally keep one byte unused to distinguish between
# the full and empty states, avoiding ambiguity. While not all use cases
# require this constraint, it is enforced here for simplicity.
# Empty: w == r
# Full:  (w + 1) % size == r

class RingBuffer:
    """
    Ring (Circular) buffer implementation.

    Supports enqueue and dequeue operations using a fixed-size circular buffer.

    Enqueue/dequeue operations advance the read/write offsets, making the
    previous buffer state unrecoverable from the offsets alone.
    """
    __slots__ = ("_size", "_ring", "_w", "_r", "_lock")

    def __init__(self, *, size: int):

        self._size = size
        self._ring: memoryview = memoryview(bytearray(self._size))
        self._w: int = 0
        self._r: int = 0
        self._lock = RLock()

    def free_space(self) -> int:
        """ return the number of bytes free to write on them in buffer """
        with self._lock:
            r_offset = self._r
            w_offset = self._w

        return (r_offset - w_offset - 1) % self._size

    def ready(self) -> int:
        """ return the number of bytes ready to be read in buffer """
        with self._lock:
            r_offset = self._r
            w_offset = self._w
        return (w_offset - r_offset) % self._size

    def is_empty(self) -> bool:
        with self._lock:
            r_offset = self._r
            w_offset = self._w
        return w_offset == r_offset

    def enqueue(self,
                *,
                buffer: memoryview
                ) -> int:
        """
        Copy data from given "buffer" into the ring buffer starting at "w_offset".
        The write operation wraps around the end of the buffer when necessary.
        """
        with self._lock:
            r_offset = self._r
            w_offset = self._w

        s = self._size
        ring = self._ring
        buf_len = len(buffer)
        # Calling 'free_space()' is unnecessary here since it acquires the lock before returning.
        # We already hold the lock to take the snapshots, so compute it directly.
        free = (r_offset - w_offset - 1) % self._size

        if free == 0:
            if __debug__:
                log(
                    "buffer",
                    "enqueue failed: buffer full",
                    level="DEBUG"
                )
            return 0


        if __debug__:
            log(
                "buffer",
                f"given buffer len={buf_len}, available={free}",
                level="DEBUG"
            )

        buf_len = min(buf_len, free) # clamp

        # check if we can put all possible buffer in a contiguous way
        if w_offset + buf_len <= s - 1:
            ring[w_offset:w_offset + buf_len] = buffer[:buf_len]

            if __debug__:
                log(
                    "buffer",
                    f"enqueue contiguous bytes={buf_len} "
                    f"range=[{w_offset}:{w_offset + buf_len}]",
                    level="DEBUG"
                )
            with self._lock:
                self._w = (self._w + buf_len) % s
            return buf_len

        # check if we can write all possible buffer but in wrapped way.
        else:
            # write first portion
            ring[w_offset:] = buffer[:s - w_offset]

            # write second portion
            ring[:buf_len - (s - w_offset)] = buffer[s - w_offset:buf_len]

            if __debug__:
                log(
                    "buffer",
                    f"enqueue wrapped bytes={buf_len} "
                    f"range=[{w_offset}:] & [:{buf_len - (s - w_offset)}]",
                    level="DEBUG"
                )
            with self._lock:
                self._w = (self._w + buf_len) % s
            return buf_len

    def dequeue(self, *, n: int) -> list[memoryview]:
        """
        Dequeue up to n bytes from self._ring.
        Returns a list of memoryviews as an IOV.
        Maximum returned list length is 2
        """

        # NOTE: sum IOV items lengths to get dequeued bytes.

        with self._lock:
            r_offset = self._r
            w_offset = self._w

        s = self._size
        ring = self._ring
        # Calling 'ready()' is unnecessary here since it acquires the lock before returning.
        # We already hold the lock to take the snapshots, so compute it directly.
        ready = (w_offset - r_offset) % self._size

        if __debug__:
            log(
                'buffer',
                f'requested buffer={n}, available={ready}'
            )
        n = min(n, ready) # clamp

        # read contiguously
        if r_offset < w_offset:

            if __debug__:
                log(
                    "buffer",
                    f"dequeue contiguous bytes={n} "
                    f"range=[{r_offset}:{r_offset + n}]",
                    level="DEBUG"
                )

            data = ring[r_offset : r_offset + n]
            with self._lock:
                self._r = (self._r + len(data)) % s
            return [ data ]

        if r_offset > w_offset:
            # w_offset is wrapped, but we can read contiguously
            if r_offset + n <= s:

                if __debug__:
                    log(
                        "buffer",
                        f"dequeue contiguous bytes={n} "
                        f"range=[{r_offset}:{r_offset + n}]",
                        level="DEBUG"
                    )

                # dequeue : [r: r+n]
                data = ring[r_offset:r_offset + n]
                with self._lock:
                    self._r = (self._r + len(data)) % s
                return [ data ]

            # w is wrapped, and n is exceeding the end of buffer
            # so we need to read circularly
            else:
                remainder = n - (s - r_offset)

                if __debug__:
                    log(
                        "buffer",
                        f"dequeue wrapped range=[{r_offset}:] & [:{remainder}]",
                        level="DEBUG"
                    )

                # dequeue : [r:] & [:remainder]
                data1 = ring[r_offset:]
                data2 = ring[:remainder]
                with self._lock:
                    self._r = (self._r + len(data1) + len(data2)) % s
                return [ data1, data2 ]

        return []

    def __len__(self):
        return len(self._ring)

