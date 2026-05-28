from struct import unpack_from

def inet_csum(data: memoryview, pseudo_sum: int=0):
    """ Compute internet checksum """
    s = pseudo_sum
    n = len(data)
    i = 0

    num_qwords = n // 8

    # Sum all full 64-bit words at once
    s += sum(
        unpack_from(f'!{n // 8}Q', data[:num_qwords * 8])
    )
    i += (num_qwords * 8)

    # Process remaining data in 16-bit (2-byte) chunks
    while i + 1 < n:
        s += (data[i] + data[i+1])
        i += 2

    # If there is a leftover single byte, pad it
    if n % 2:
        s += (data[-1] << 8)

    # Fold 32-bit/64-bit sum into 16-bit by adding carries
    while s >> 16:
        s = (s >> 16) + (s & 0xFFFF)

    return ~s & 0xFFFF
