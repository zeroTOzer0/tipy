import struct

from tipy.protocols.arp.arp import  ARP_OP_REQUEST, ARP_HEADER_LEN, ARP_OP_REPLY
from tipy.lib.mac_address import MACAddress
from tipy.lib.ip_address import IPAddress
from tipy.lib.tracker import Tracker

class ARPBuilder:
    def __init__(self,
                 sha: MACAddress,
                 spa: IPAddress,
                 tha: MACAddress,
                 tpa: IPAddress,
                 op: int = ARP_OP_REQUEST,
                 echo_tracker: Tracker | None = None
                 ):

        self._sha = sha
        self._spa = spa
        self._tha = tha
        self._tpa = tpa
        self._op = op

        self.__tracker = Tracker(prefix='tx', echo_tracker=echo_tracker)


    def build(self, frame: memoryview):
        struct.pack_into(
            '! H H B B H 6s 4s 6s 4s',
            frame,
            0,
            1,
            0x0800,
            6,
            4,
            self._op,
            self._sha.mac2raw(),
            self._spa.ip2raw(),
            self._tha.mac2raw(),
            self._tpa.ip2raw()

        )


    @property
    def tracker(self):
        return self.__tracker

    def __len__(self):
        return ARP_HEADER_LEN

    def __str__(self):
        if self._op == ARP_OP_REPLY:
            return (
                f'ARP reply, {self._spa} / {self._sha} > '
                f'{self._tpa} / {self._tha}'
            )

        if self._op == ARP_OP_REQUEST:
            return (
                f'ARP request, {self._spa} / {self._sha} > '
                f'{self._tpa} / {self._tha}'
            )

        return f'ARP UNKNOWN OPERATION'





