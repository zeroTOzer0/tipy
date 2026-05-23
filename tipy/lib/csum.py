from numba import njit

@njit(fastmath=True)
def inet_csum(data: memoryview, pseudo_sum: int=0):
    """ Compute internet checksum """
    s = pseudo_sum
    n = len(data)

    i = 0
    while i + 1 < n:
        s += (data[i] << 8) | data[i + 1]
        s = (s & 0xFFFF) + (s >> 16)
        i += 2

    if n & 1:
        s += (data[n - 1] << 8)
        s = (s & 0xFFFF) + (s >> 16)

    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)

    return (~s) & 0xFFFF
