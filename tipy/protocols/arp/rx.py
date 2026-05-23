from __future__ import annotations

from tipy.config.config import MAC_ADDRESS , IP_ADDRESS
from tipy.lib.logger import log

from tipy.protocols.arp.parser import ARPParser
from tipy.protocols.arp.arp import ARP_OP_REPLY, ARP_OP_REQUEST

from tipy.lib.mac_address import MACAddress
from tipy.lib.ip_address import IPAddress

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from tipy.components.core import Core
    from tipy.lib.packet import PacketRX

def rx_arp(self: Core, packet_rx: PacketRX):
    ARPParser(packet_rx=packet_rx)
    if __debug__: log(
        'arp',
        f"{packet_rx.tracker} - "
        f'{packet_rx.arp}'
    )

    if packet_rx.arp.op == ARP_OP_REPLY:

        # check if this replay destined to me based on dst ether mac address
        if packet_rx.ether.dst.raw2mac() == MAC_ADDRESS:

            # If there was a pending normal ARP request for this IP
            if self.arp_cache.arp_wait_test(
                packet_rx.arp.spa.raw2ip()
            ):

                self.arp_cache.update_arp_cache(
                    packet_rx.arp.spa.raw2ip(),
                    packet_rx.arp.sha.raw2mac()
                )

                self.ip_cache.dequeue(
                    core=self,
                    ip_address=str(packet_rx.arp.spa),
                    mac_address=str(packet_rx.arp.sha)
                )
                return

            # If this IP was being probed via ARP probe
            if self.arp_cache.arp_probe_test(
                packet_rx.arp.spa.raw2ip()
            ):
                with self.arp_cache.arp_prob_cond:
                    if __debug__:
                        log(
                            "arp",
                            f"probe response: {packet_rx.arp.spa.raw2ip()} in use",
                            level="INFO"
                        )
                    # Mark conflict and notify stack core
                    self.conflict_ips.append(packet_rx.arp.spa.raw2ip())
                    self.arp_cache.arp_prob_cond.notify()
                return

            if __debug__:
                log(
                    "arp",
                    "unsolicited ARP reply received, dropped",
                    level="WARN"
                )

        if __debug__:
            log(
                "arp",
                "ARP reply not for this host, dropped",
                level="WARN"
            )

    if packet_rx.arp.op == ARP_OP_REQUEST:
        # check if the destined ip is me based on
        # tpa field, send arp rep
        if packet_rx.arp.tpa.raw2ip() == IP_ADDRESS:
            self.tx_arp(
                sha=MACAddress(MAC_ADDRESS),
                spa=IPAddress(IP_ADDRESS),
                tha=packet_rx.ether.src,
                tpa=packet_rx.arp.spa,
                op=ARP_OP_REPLY,
                tracker=packet_rx.tracker
            )
            # update arp cache
            self.arp_cache.update_arp_cache(
                packet_rx.arp.spa.raw2ip(),
                packet_rx.ether.src.raw2mac()
            )
