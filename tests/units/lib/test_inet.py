import pytest

from tipy.lib.inet import IPAddress, IPFormatError

# TEST: construction
def test_ip_from_string():
    ip = IPAddress("192.168.1.10")
    assert ip.ip == 0xC0A8010A

def test_str_ip():
    ip = IPAddress("192.168.1.10")
    assert ip.str_ip == "192.168.1.10"

def test_str():
    ip = IPAddress("192.168.1.10")
    assert str(ip) == "192.168.1.10"

def test_ip_from_integer():
    ip = IPAddress(0xC0A8010A)
    assert ip.ip == 0xC0A8010A
    assert ip.str_ip == "192.168.1.10"

# TEST: invalid address
@pytest.mark.parametrize(
    "ip",
    [
        "",
        "192.168.1",
        "192.168.1.256",
        "192.168.1.-1",
        "192.168.1.a",
        "192.168.1.1.1",
        "192.168..1",
        ".168.1.1",
        "192.168.1.",
        "1.2.3.004",
    ],
)
def test_invalid_ip(ip):
    with pytest.raises(IPFormatError):
        IPAddress(ip)

# TEST: private address
@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "192.168.255.255",
    ],
)
def test_private_ip(ip):
    assert IPAddress(ip).is_private is True
    assert IPAddress(ip).is_public is False

# TEST: public address
@pytest.mark.parametrize(
    "ip",
    [
        "8.8.8.8",
        "1.1.1.1",
        "172.15.255.255",
        "172.32.0.0",
        "192.167.255.255",
        "192.169.0.0",
    ],
)
def test_public_ip(ip):
    assert IPAddress(ip).is_private is False
    assert IPAddress(ip).is_public is True

# TEST: loopback
@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.0",
        "127.0.0.1",
        "127.255.255.255",
    ],
)
def test_loopback(ip):
    assert IPAddress(ip).is_loopback is True

# TEST: non-loopback
@pytest.mark.parametrize(
    "ip",
    [
        "126.255.255.255",
        "128.0.0.0",
    ],
)
def test_not_loopback(ip):
    assert IPAddress(ip).is_loopback is False

# TEST: multicast address
@pytest.mark.parametrize(
    "ip",
    [
        "224.0.0.0",
        "224.0.0.1",
        "239.255.255.255",
    ],
)
def test_multicast(ip):
    assert IPAddress(ip).is_multicast is True

# TEST: broadcast
def test_broadcast():
    ip = IPAddress("255.255.255.255")
    assert ip.is_broadcast is True
    assert ip.is_unicast is False

# TEST: unicast address
def test_unicast():
    ip = IPAddress("192.168.1.10")
    assert ip.is_unicast is True
    assert ip.is_multicast is False
    assert ip.is_broadcast is False

# TEST: address inside the LAN
def test_ip_in_subnet():
    ip = IPAddress("192.168.1.50")
    network = IPAddress("192.168.1.0")
    mask = IPAddress("255.255.255.0")
    assert ip.is_in_subnet(network, mask) is True

# TEST: address outside the LAN
def test_ip_not_in_subnet():
    ip = IPAddress("192.168.2.50")
    network = IPAddress("192.168.1.0")
    mask = IPAddress("255.255.255.0")
    assert ip.is_in_subnet(network, mask) is False

