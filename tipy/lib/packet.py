from __future__ import annotations
from tipy.lib.tracker import Tracker

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from tipy.protocols.ether.parser import EtherParser
    from tipy.protocols.arp.parser import ARPParser
    from tipy.protocols.ip.parser import IPParser
    from tipy.protocols.udp.parser import UDPParser
    from tipy.protocols.raw.parser import RAWParser
    from tipy.protocols.icmp.parser import ICMPParser
    from tipy.protocols.tcp.parser import TCPParser


class PacketRX:
    def __init__(self, frame: bytes):

        self.frame: memoryview = memoryview(frame)
        self.tracker: Tracker = Tracker(prefix='rx')

        self.ether: EtherParser
        self.arp: ARPParser
        self.ip: IPParser
        self.icmp: ICMPParser
        self.udp: UDPParser
        self.tcp: TCPParser
        self.raw: RAWParser

    def __len__(self):
        return len(self.frame)
