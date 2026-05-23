from __future__ import annotations

from threading import RLock
from tipy.lib.ip_address import IPAddress
from tipy.lib.mac_address import MACAddress
from typing import TYPE_CHECKING
from tipy.config.config import MAC_ADDRESS
from tipy.lib.logger import log
if TYPE_CHECKING:
    from tipy.protocols.ip.builder import IPBuilder, IPFragBuilder
    from tipy.components.core import Core

class IPCache:
    def __init__(self) -> None:


        # {buffer-id : {defragmentation-resources}}
        self.fragments_cache: dict[ tuple[str, str, int, int], dict ] = dict()

        # Lock to protect the fragments_cache from
        # race conditions
        self.fragments_cache_rlock = RLock()


        # {ip : [builder-objects,]}
        self._arp_pending_datagrams_queue: dict[
                                            str,
                                            list[IPBuilder|IPFragBuilder]
                                            ] \
                                            = dict()


    def enqueue(self, ip_address: str,
                datagram: IPBuilder|IPFragBuilder
    ):
        if self.is_enqueued(ip_address):
            self._arp_pending_datagrams_queue[ip_address].append(datagram)
            if __debug__:
                qlen = len(self._arp_pending_datagrams_queue[ip_address])
                log(
                    "ip-c",
                    f"enqueue: {ip_address} (size={qlen})",
                    level="DEBUG"
                )

        else:
            self._arp_pending_datagrams_queue[ip_address] = [datagram]
            if __debug__:
                log(
                    "ip-c",
                    f"enqueue: {ip_address} (new queue, size=1)",
                    level="DEBUG"
                )

    def dequeue(self,
                core: Core,
                ip_address: str,
                mac_address: str
                ):

        if __debug__:
            qlen = len(self._arp_pending_datagrams_queue[ip_address])

            log(
                "ip-c",
                f"ARP resolved: releasing {qlen} datagrams to {ip_address} ({mac_address})",
                level="INFO"
            )
        for datagram in self._arp_pending_datagrams_queue[ip_address]:
            core.tx_ether(
                payload=datagram,
                src=MACAddress(MAC_ADDRESS),
                dst=MACAddress(mac_address),
                type=0x0800
            )


        # clean this pending queue
        self._arp_pending_datagrams_queue.pop(ip_address, None)

    def is_enqueued(self, ip_address: str):
        # function returns True if there is a pending datagram
        # waiting a replay of an arp request
        if ip_address in self._arp_pending_datagrams_queue:
            return True
        return False


