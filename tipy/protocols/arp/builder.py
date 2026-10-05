import struct

from tipy.protocols.arp.arp import  ARP_OP_REQUEST, ARP_HEADER_LEN, ARP_OP_REPLY
from tipy.lib.ethernet import MACAddress
from tipy.lib.inet import IPAddress
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
            '! H H B B H I H I I H I',
            frame,
            0,
            1,
            0x0800,
            6,
            4,
            self._op,
            self._sha.mac_high,
            self._sha.mac_low,
            self._spa.ip,
            self._tha.mac_high,
            self._tha.mac_low,
            self._tpa.ip

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





