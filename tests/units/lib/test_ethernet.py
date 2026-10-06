import pytest

from tipy.lib.ethernet import MACAddress, MACFormatError

# TEST: construction
def test_mac_from_string():
    mac = MACAddress("00:11:22:33:44:55")
    assert mac.mac == 0x001122334455

def test_mac_from_integer():
    mac = MACAddress(0x001122334455)
    assert mac.mac == 0x001122334455

# TEST: string representation
@pytest.mark.parametrize(
    "mac",
    [
        "00:11:22:33:44:55",
        "aa:bb:cc:dd:ee:ff",
        "AA:BB:CC:DD:EE:FF",
    ],
)
def test_mac_str(mac):
    address = MACAddress(mac)
    assert address.mac_str == mac
    assert str(address) == mac

def test_mac_from_dash_separated_string():
    mac = MACAddress("00-11-22-33-44-55")
    assert mac.mac == 0x001122334455
    assert mac.mac_str == "00:11:22:33:44:55"

def test_mac_str_from_integer():
    mac = MACAddress(0x001122334455)
    assert mac.mac_str == "00:11:22:33:44:55"
    assert str(mac) == "00:11:22:33:44:55"

# TEST: high / low parts
def test_mac_high():
    mac = MACAddress("00:11:22:33:44:55")
    assert mac.mac_high == 0x00112233

def test_mac_low():
    mac = MACAddress("00:11:22:33:44:55")
    assert mac.mac_low == 0x4455

# TEST: invalid MAC addresses
@pytest.mark.parametrize(
    "mac",
    [
        "",
        "001122334455",
        "00:11:22:33:44",
        "00:11:22:33:44:55:66",
        "00:11:22:33:44:5",
        "00:11:22:33:444:55",
        "00:11:2222:33:44:55",
        "00::22:33:44:55",
        ":00:11:22:33:44:55",
        "00:11:22:33:44:55:",
        "00:11:22:33:44:GG",
    ],
)
def test_invalid_mac(mac):
    with pytest.raises(MACFormatError):
        MACAddress(mac)

# TEST: invalid separators
@pytest.mark.parametrize(
    "mac",
    [
        "00:11-22:33:44:55",
        "00-11:22-33:44-55",
        "00:11:22-33:44:55",
        "00-11-22:33-44-55",
    ],
)
def test_mixed_mac_separators(mac):
    with pytest.raises(MACFormatError):
        MACAddress(mac)

@pytest.mark.parametrize(
    "mac",
    [
        "00.11.22.33.44.55",
        "00_11_22_33_44_55",
        "00 11 22 33 44 55",
        "00/11/22/33/44/55",
    ],
)
def test_invalid_mac_separators(mac):
    with pytest.raises(MACFormatError):
        MACAddress(mac)

# TEST: broadcast
def test_broadcast():
    mac = MACAddress("ff:ff:ff:ff:ff:ff")
    assert mac.is_broadcast is True
    assert mac.is_multicast is True
    assert mac.is_unicast is False

def test_not_broadcast():
    mac = MACAddress("ff:ff:ff:ff:ff:fe")
    assert mac.is_broadcast is False

# TEST: multicast / unicast
@pytest.mark.parametrize(
    "mac",
    [
        "01:00:00:00:00:00",
        "01:00:5e:00:00:01",
        "33:33:00:00:00:01",
        "ff:ff:ff:ff:ff:ff",
    ],
)
def test_multicast(mac):
    address = MACAddress(mac)

    assert address.is_multicast is True
    assert address.is_unicast is False

@pytest.mark.parametrize(
    "mac",
    [
        "00:00:00:00:00:00",
        "00:11:22:33:44:55",
        "02:11:22:33:44:55",
    ],
)
def test_unicast(mac):
    address = MACAddress(mac)

    assert address.is_unicast is True
    assert address.is_multicast is False

# TEST: global / local
@pytest.mark.parametrize(
    "mac",
    [
        "00:11:22:33:44:55",
        "01:11:22:33:44:55",
    ],
)

def test_global(mac):
    address = MACAddress(mac)

    assert address.is_global is True
    assert address.is_local is False

@pytest.mark.parametrize(
    "mac",
    [
        "02:11:22:33:44:55",
        "03:11:22:33:44:55",
    ],
)
def test_local(mac):
    address = MACAddress(mac)

    assert address.is_local is True
    assert address.is_global is False