from tipy.lib.logger import log

class RingBuffer:
    """
    Ring (Circular) buffer implementation.

    Supports enqueue and dequeue operations using a fixed-size circular buffer.

    One byte is intentionally kept unused to distinguish between the
    full and empty states, avoiding ambiguity. While not all use cases
    require this constraint, it is enforced here for simplicity.
    """

    # w == r -> empty
    # (w + 1) % len(snd_buf) == r -> full

    __slots__ = ("_size", "_ring")

    def __init__(self, *, size: int):

        self._size = size
        self._ring: memoryview = memoryview(bytearray(self._size))

    def free(self, *, w_offset: int, r_offset: int) -> int:
        """ return the number of bytes free to write on them in buffer"""
        return (r_offset - w_offset - 1) % self._size

    def ready(self, *, w_offset: int, r_offset: int) -> int:
        """ return the number of bytes ready to be read in buffer"""
        return (w_offset - r_offset) % self._size

    def is_empty(self, *, w_offset: int, r_offset: int) -> bool:
        return w_offset == r_offset

    def enqueue(self,
                *,
                w_offset: int,
                r_offset: int,
                buffer: memoryview
                ) -> int:
        """
        Copy data from given "buffer" into the ring buffer starting at "w_offset".
        The write operation wraps around the end of the buffer when necessary.
        """

        s = self._size
        ring = self._ring
        buf_len = len(buffer)
        free = self.free(w_offset=w_offset, r_offset=r_offset)

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

            return buf_len

    def dequeue(self,
                *,
                w_offset: int,
                r_offset: int,
                n: int
                ) -> list[memoryview]:
        """
        Dequeue up to n bytes from self._ring.
        Returns a list of memoryviews as an IOV.
        Maximum returned list length is 2
        """

        # NOTE: sum IOV items lengths to get dequeued bytes.

        s = self._size
        ring = self._ring
        ready = self.ready(w_offset=w_offset, r_offset=r_offset)


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

            return [
                ring[r_offset : r_offset + n]
            ]

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
                return [
                    ring[r_offset:r_offset + n]
                ]

            # w is wrapped, and n is exceeding the end of buffer
            # so we need to read circularly
            else:
                remainder = n - (s - r_offset)

                if __debug__:
                    log(
                        "buffer",
                        f"dequeue wrapped range=[{r_offset:}] & [:{remainder}]",
                        level="DEBUG"
                    )

                # dequeue : [r:] & [:remainder]
                return [
                    ring[r_offset:],
                    ring[:remainder]
                ]

        return []

    def __len__(self):
        return len(self._ring)


