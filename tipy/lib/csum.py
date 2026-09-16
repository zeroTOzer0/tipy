import sys
from typing import Callable

def inet_csum_little(data: memoryview, inited_sum: int=0):
    """
    Compute the Internet checksum on a little-endian host.
    Args:
        data: Packet data to checksum.
        inited_sum: Optional pseudo-header sum. The pseudo-header must
            first be built in network byte order, then interpreted and
            passed in the host's native byte order.

            On little-endian hosts, construct the pseudo-header using
            network byte order ('!' or '>') and interpret its 32-bit
            words using native byte order ('=') before passing their sum
            as `inited_sum`.

    Returns:
        The 16-bit Internet checksum.
    """
    s = inited_sum
    n = len(data)
    i = 0

    qwords = n // 8
    # Sum all full 64-bit words at once
    s += sum(data[:qwords * 8].cast("Q"))

    i += (qwords * 8)

    # Sum all full remaining 16-bit words at once
    hwords = (n - i) // 2
    s += sum(data[i:i+hwords * 2].cast("H"))
    i += hwords * 2

    # If there is a leftover single byte, pad it
    if n % 2:
        s += (data[-1] << 8)

    # Fold 32-bit/64-bit sum into 16-bit by adding carries
    while s >> 16:
        s = (s >> 16) + (s & 0xFFFF)

    # swap 16-bits
    s = (s << 8 & 0xFF00) | (s >> 8)

    return ~s & 0xFFFF

def inet_csum_big(data: memoryview, inited_sum: int=0):
    """
    Compute the Internet checksum on a big-endian host.
    Args:
        data: Packet data to checksum.
        inited_sum: Optional pseudo-header sum. The pseudo-header must
            first be built in network byte order, then interpreted and
            passed in the host's native byte order.

            On big-endian hosts, network byte order is the same as the
            host's native byte order, so the pseudo-header can be built
            in network byte order and its words interpreted directly
            using the native byte order.

    Returns:
        The 16-bit Internet checksum.
    """
    s = inited_sum
    n = len(data)
    i = 0

    qwords = n // 8

    # Sum all full 64-bit words at once
    s += sum(data[:qwords * 8].cast("Q"))
    i += (qwords * 8)

    # Sum all full remaining 16-bit words at once
    hwords = (n - i) // 2
    s += sum(data[i:i + hwords * 2].cast("H"))
    i += hwords * 2

    # If there is a leftover single byte, pad it
    if n % 2:
        s += (data[-1] << 8)

    # Fold 32-bit/64-bit sum into 16-bit by adding carries
    while s >> 16:
        s = (s >> 16) + (s & 0xFFFF)

    return ~s & 0xFFFF

if sys.byteorder == 'little':
    inet_csum: Callable[[memoryview, int], int] = inet_csum_little
else:
    inet_csum: Callable[[memoryview, int], int] = inet_csum_big
