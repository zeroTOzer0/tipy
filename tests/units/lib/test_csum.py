import sys
import struct

from tipy.lib.inet import IPAddress
from tipy.lib.socket import IPPROTO_TCP
from tipy.lib.csum import inet_csum, inet_csum_big, inet_csum_little

def test_inet_csum_ip_header():
    # ver=4, ihl=5, tos=0x0, len=46, id=1, flags=None,
    # frag=0, ttl=64, proto=tcp, checksum=0xf4b0, src=192.168.2.199, dst=192.168.2.1
    ip_h = memoryview(
        b"E\x00\x00.\x00\x01\x00\x00@\x06\xf4\xb0\xc0\xa8\x02\xc7\xc0\xa8\x02\x01"
    )

    assert inet_csum(data=ip_h) == 0

def test_inet_csum_with_inited_sum():
    # pre-captured TCP segment
    # IP: ver=4, ihl=5, tos=0x0, len=46, id=1,flags=None,
    # frag=0, ttl=64, proto=tcp, checksum=0xf4b0, src=192.168.2.199, dst=192.168.2.1

    # TCP: sport=9999, dport=9999, seq=0, ack=0, dataofs=5,
    # flags=S, window=8192, checksum=0xc9be, urgptr=0

    # Payload: load='test\n\r'

    # Full IP+TCP+Payload packet
    # b"E\x00\x00.\x00\x01\x00\x00@\x06\xf4\xb0\xc0\xa8\x02\xc7\xc0\xa8\x02\x01"
    # b"'\x0f'\x0f\x00\x00\x00\x00\x00\x00\x00\x00P\x02 \x00\xc9\xbe\x00\x00test\n\r"

    IP_SRC = IPAddress("192.168.2.199")
    IP_DST = IPAddress("192.168.2.1")

    # TCP segment:
    tcp_seg = memoryview(
        b"'\x0f'\x0f\x00\x00\x00\x00\x00\x00\x00\x00P\x02 \x00\xc9\xbe\x00\x00test\n\r"
    )

    tcp_phdr = memoryview(
        struct.pack(
            "!IIBBH",
            IP_SRC.ip,
            IP_DST.ip,
            0,
            IPPROTO_TCP,
            len(tcp_seg)
        )
    )
    assert inet_csum(
        data=tcp_seg,
        inited_sum=sum(tcp_phdr.cast("I"))
    ) == 0

def test_inet_csum_with_odd_length_data():
    # pre-captured TCP segment with odd len (23)

    # IP: ver=4, ihl=5, tos=0x0, len=43, id=1, flags=None,
    # frag=0, ttl=64, proto=tcp, checksum=0xf4b3, src=192.168.2.199, dst=192.168.2.1

    # TCP: sport=9999, dport=9999, seq=0, ack=0, dataofs=5,
    # flags=S, window=8192, checksum=0x3766, urgptr=0

    # Payload: load='ABC'

    # Full IP+TCP+Payload packet
    # b"E\x00\x00+\x00\x01\x00\x00@\x06\xf4\xb3\xc0\xa8\x02\xc7\xc0\xa8\x02"
    # b"\x01'\x0f'\x0f\x00\x00\x00\x00\x00\x00\x00\x00P\x02 \x007f\x00\x00ABC"

    IP_SRC = IPAddress("192.168.2.199")
    IP_DST = IPAddress("192.168.2.1")

    tcp_seg = memoryview(
        b"'\x0f'\x0f\x00\x00\x00\x00\x00\x00\x00\x00P\x02 \x007f\x00\x00ABC"
    )

    tcp_phdr = memoryview(
        struct.pack(
            "!IIBBH",
            IP_SRC.ip,
            IP_DST.ip,
            0,
            IPPROTO_TCP,
            len(tcp_seg)
        )
    )

    assert inet_csum(
        data=tcp_seg,
        inited_sum=sum(tcp_phdr.cast("I"))
    ) == 0

def test_inet_csum_invalid_checksum():
    # ver=4, ihl=5, tos=0x0, len=46, id=1, flags=None,
    # frag=0, ttl=64, proto=tcp, checksum=0xf4b0, src=192.168.2.199, dst=192.168.2.2
    ip_h = memoryview(
        b"E\x00\x00.\x00\x01\x00\x00@\x06\xf4\xb0\xc0\xa8\x02\xc7\xc0\xa8\x02\x02"
    )

    assert inet_csum(data=ip_h) != 0

def test_inet_csum_little():
    # This test is intended to verify the checksum calculation as it would
    # behave on a little-endian host.

    # When run on a big-endian host, memoryview.cast() reads the data using
    # the host's native byte order. Since inet_csum_little() still performs
    # the final byte swap, its result is byte-swapped compared to the result
    # obtained on a little-endian host.

    # Therefore, on a big-endian host we expect the byte-swapped result.
    # On a little-endian host, we expect the normal result.

    # ver=4, ihl=5, tos=0x0, len=60, id=10080, flags=None,
    # frag=0, ttl=64, proto=icmp, checksum=0x0000,
    # src=192.168.2.200, dst=192.168.2.199

    ip_h = memoryview(
        b"E\x00\x00<'`\x00\x00@\x01\x00\x00\xc0\xa8\x02\xc8\xc0\xa8\x02\xc7"
    )

    if sys.byteorder == "little":
        assert inet_csum_little(data=ip_h) == 0xCC_81
    else:
        assert inet_csum_little(data=ip_h) == 0x81_CC

def test_inet_csum_big():
    # This test is intended to verify the checksum calculation as it would
    # behave on a big-endian host.

    # When run on a little-endian host, memoryview.cast() still reads the
    # data using the host's native byte order. Since inet_csum_big() does
    # not perform the final byte swap used by inet_csum_little(), its result
    # is byte-swapped compared to inet_csum_little().

    # Therefore, on a little-endian host we expect the byte-swapped result.
    # On a big-endian host, we expect the normal result.

    # ver=4, ihl=5, tos=0x0, len=60, id=10080, flags=None,
    # frag=0, ttl=64, proto=icmp, checksum=0x0000,
    # src=192.168.2.200, dst=192.168.2.199

    ip_h = memoryview(
        b"E\x00\x00<'`\x00\x00@\x01\x00\x00\xc0\xa8\x02\xc8\xc0\xa8\x02\xc7"
    )
    if sys.byteorder == "little":
        assert inet_csum_big(data=ip_h) == 0x81_CC
    if sys.byteorder == "big":
        assert inet_csum_big(data=ip_h) == 0xCC_81



