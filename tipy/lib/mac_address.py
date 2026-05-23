import struct


class MACAddress:
    def __init__(self, mac_address: str | bytes | int | memoryview):
        self.mac_address = mac_address

    def mac2raw(self) -> bytes:
        if isinstance(self.mac_address, bytes):
            return self.mac_address

        if isinstance(self.mac_address, memoryview):
            return self.mac_address.tobytes()

        mac = self.mac_address.split(':')
        return struct.pack(
            '!6B',
            int(mac[0], base=16),
            int(mac[1], base=16),
            int(mac[2], base=16),
            int(mac[3], base=16),
            int(mac[4], base=16),
            int(mac[5], base=16),

        )

    def raw2mac(self) -> str:
        mac = self.mac_address.hex()
        return ':'.join(mac[i:i + 2] for i in range(0, 12, 2))

    def is_unicast(self) -> bool:
        # LSB of firs octet == 0
        # it's unicast
        return not bool(self.mac2raw()[0] & 1)

    def is_multicast(self) -> bool:
        # LSB of firs octet == 1
        # it's multicast
        return bool(self.mac2raw()[0] & 1)

    def is_broadcast(self) -> bool:
        return self.mac2raw() == b'\xff' * 6

    def is_global(self) -> bool:
        # second LSB of firs octet == 0
        # it's global
        return not bool(self.mac2raw()[0] & 2)

    def is_local(self) -> bool:
        # second LSB of firs octet == 1
        # it's local
        return bool(self.mac2raw()[0] & 2)

    def __str__(self):
        if not isinstance(self.mac_address, str):
            return self.raw2mac()
        return self.mac_address

