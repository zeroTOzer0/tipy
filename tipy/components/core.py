from __future__ import annotations

from tipy.config.config import (
    MAC_ADDRESS,
    IP_STATIC,
    IP_ADDRESS,
    IP_BROADCAST_ADDRESS,
    ROUTER,
    NETWORK,
    MASK,
)

from tipy.lib.logger import log

from tipy.lib.ip_address import IPAddress

from tipy.lib.mac_address import MACAddress

from tipy.components.timer import Timer
from tipy.components.tx_ring import TXRing
from tipy.components.rx_ring import RXRing
from tipy.components.arp_cache import ARPCache
from tipy.components.tcp_events import TCPEvents

from tipy.protocols.ether.tx import tx_ether
from tipy.protocols.ether.rx import rx_ether

from tipy.protocols.arp.tx import tx_arp
from tipy.protocols.arp.rx import rx_arp

from tipy.protocols.ip.tx import tx_ip
from tipy.protocols.ip.rx import rx_ip

from tipy.protocols.icmp.tx import tx_icmp
from tipy.protocols.icmp.rx import rx_icmp

from tipy.protocols.udp.tx import tx_udp
from tipy.protocols.udp.rx import rx_udp

from tipy.protocols.tcp.tx import tx_tcp
from tipy.protocols.tcp.rx import rx_tcp

from tipy.protocols.raw.rx import rx_raw
from tipy.protocols.raw.tx import tx_raw

from tipy.components.ip_cache import IPCache

from tipy.components.sockets_table import UDPTable, RAWV4Table, TCPTable
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from tipy.lib.packet import PacketRX




def drop_packet(packet_handler=None, packet_rx=None):
    return



class Core:
    ether_protocol_map = {
        0x0806: rx_arp,
        # IPv4 (0x0800) is not here yet because we don't support layer 3 multicast/broadcast.
        # Ideally, 0x0800 should be here to receive broadcasts even without a valid IP,
        # but as a temporary workaround, we inject it only after acquiring an IP.
        # 0x0800 : rx_ip,

        None: drop_packet
    }

    ip_protocol_map = {
        255 : rx_raw,
        1   : rx_icmp,
        17  : rx_udp,
        6   : rx_tcp
    }



    tx_ether = tx_ether

    tx_arp = tx_arp

    tx_ip = tx_ip

    tx_icmp = tx_icmp

    tx_udp = tx_udp

    tx_tcp = tx_tcp

    tx_raw = tx_raw

    ip_cache = IPCache()
    ip_fragment_cache = ip_cache.fragments_cache
    ip_fragment_cache_rlock = ip_cache.fragments_cache_rlock



    def __init__(self):

        self.tx_ring: Optional[TXRing] = None
        self.rx_ring: Optional[RXRing] = None
        self.arp_cache: Optional[ARPCache] = None
        self.timer: Optional[Timer] = None
        self.tcp_events_schedule: Optional[TCPEvents] = None

        self.udp: UDPTable = UDPTable()
        self.tcp: TCPTable = TCPTable()
        self.raw_v4: RAWV4Table = RAWV4Table()

        self.iface: int | None = None


        self.conflict_ips: list = []

        if IP_STATIC:
            self.unicast_ip: IPAddress
            self.broadcast_ip: IPAddress = IPAddress(IP_BROADCAST_ADDRESS)
            self.multicast_ip: list[IPAddress] = []
            self.router: IPAddress = IPAddress(ROUTER)
            self.network: IPAddress = IPAddress(NETWORK)
            self.mask: IPAddress = IPAddress(MASK)

        # else:
            # TODO : USE DHCP TO INITIATE IP ADDRESS FOR STACK

        self.unicast_mac: MACAddress = MACAddress(MAC_ADDRESS)


    def initialize_stack_components(self):
        if __debug__:
            log(
                "stack",
                "Initializing stack components...",
                level="INFO"
            )
        self.tx_ring = TXRing(core=self)
        self.rx_ring = RXRing(core=self)
        self.arp_cache = ARPCache(core=self)
        self.timer = Timer(core=self)
        self.tcp_events_schedule = TCPEvents(core=self)

        self.rx_ring.iface = self.iface
        self.tx_ring.iface = self.iface


    def start_stack(self):
        self.initialize_stack_components()

        if __debug__:
            log(
                "stack",
                "Starting stack components...",
                level="INFO"
            )

        self.tx_ring.start()
        self.rx_ring.start()
        self.timer.start()
        self.arp_cache.start()
        self.tcp_events_schedule.start()

        self._acquire_ipaddr(IP_ADDRESS)


    def stop_stack(self):
        self.tx_ring.shutdown()
        self.rx_ring.shutdown()
        self.timer.shutdown()
        self.arp_cache.shutdown()
        self.tcp_events_schedule.shutdown()

    def _send_arp_prob(self, ipaddr):
        Core.tx_arp(
            self,
            sha=self.unicast_mac,
            spa=IPAddress(0),
            tha=MACAddress(b'\x00'*6),
            tpa=IPAddress(ipaddr),
            op=1,
            prob=True
        )

    def _acquire_ipaddr(self, ipaddr):
        with self.arp_cache.arp_prob_cond:
            self._send_arp_prob(ipaddr)
            self.arp_cache.arp_prob_cond.wait()
        if ipaddr in self.conflict_ips:
            if __debug__:
                log(
                    "stack",
                    f"IP conflict detected: {ipaddr} is already in use",
                    level="ERROR"
                )
            self.stop_stack()
            exit(0)

        if __debug__:
            log(
                "stack",
                f"IP assigned: {ipaddr}",
                level="INFO"
            )
        self.unicast_ip = IPAddress(ipaddr)
        Core.ether_protocol_map[0x0800] = rx_ip


    def handle_packet(self, packet_rx: PacketRX):
        rx_ether(self, packet_rx)










