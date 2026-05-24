from struct import unpack_from
from functools import cached_property

from tipy.lib.packet import PacketRX
from tipy.lib.ip_address import IPAddress
from tipy.lib.mac_address import MACAddress
from tipy.protocols.arp.arp import ARP_OP_REPLY, ARP_OP_REQUEST

class ARPParser:

    __slots__ = ('_frame', '__dict__')

    def __init__(self, packet_rx: PacketRX):
        self._frame: memoryview = packet_rx.frame
        packet_rx.arp = self


    @cached_property
    def hwtype(self):
        return  unpack_from('! H', self._frame[0:2])[0]


    @cached_property
    def ptype(self):
        return  unpack_from('! H', self._frame[2:4])[0]


    @cached_property
    def hwlen(self):
        return self._frame[4]

    @cached_property
    def plen(self):
        return self._frame[5]

    @cached_property
    def op(self):
        return unpack_from('! H', self._frame[6:8])[0]

    @cached_property
    def sha(self):
        return MACAddress(bytes(self._frame[8:14]))

    @cached_property
    def spa(self):
        return IPAddress(bytes(self._frame[14:18]))

    @cached_property
    def tha(self):
        return MACAddress(bytes(self._frame[18:24]))

    @cached_property
    def tpa(self):
        return IPAddress(bytes(self._frame[24:28]))



    def __str__(self):
        if self.op == ARP_OP_REPLY:
            return (
                f'ARP reply, {self.spa} / {self.sha} > '
                f'{self.tpa} / {self.tha}'
            )

        if self.op == ARP_OP_REQUEST:
            return (
                f'ARP request, {self.spa} / {self.sha} > '
                f'{self.tpa} / {self.tha}'
            )

        return f'ARP UNKNOWN OPERATION'