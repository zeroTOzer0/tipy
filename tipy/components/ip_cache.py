from __future__ import annotations

from threading import RLock
from typing import TYPE_CHECKING
from tipy.lib.logger import log
if TYPE_CHECKING:
    from tipy.protocols.ip.builder import IPBuilder, IPFragBuilder
    from tipy.lib.ethernet import MACAddress
    from tipy.lib.inet import IPAddress
    from tipy.components.core import Core

class IPCache:
    def __init__(self, core: Core | None = None) -> None:


        # {buffer-id : {defragmentation-resources}}
        # buffer-id: src,dst,proto,id
        self.fragments_cache: dict[ tuple[int, int, int, int], dict ] = dict()

        # Lock to protect the fragments_cache
        self.fragments_cache_rlock = RLock()

        # {ip : [builder-objects,]}
        self._arp_pending_datagrams_queue: dict[
                                            int,
                                            list[IPBuilder|IPFragBuilder]
                                            ] \
                                            = dict()

        self.core = core

    def enqueue(self, ip_address: IPAddress,
                datagram: IPBuilder|IPFragBuilder
    ):

        ip = ip_address.ip

        if self.is_enqueued(ip_address=ip_address):
            self._arp_pending_datagrams_queue[ip].append(datagram)
            if __debug__:
                qlen = len(self._arp_pending_datagrams_queue[ip])
                log(
                    "ip-c",
                    f"enqueue: {ip_address} (size={qlen})",
                    level="DEBUG"
                )

        else:
            self._arp_pending_datagrams_queue[ip] = [datagram]
            if __debug__:
                log(
                    "ip-c",
                    f"enqueue: {ip_address} (new queue, size=1)",
                    level="DEBUG"
                )

    def dequeue(self,
                core: Core,
                ip_address: IPAddress,
                mac_address: MACAddress
                ):

        ip = ip_address.ip

        if __debug__:
            qlen = len(self._arp_pending_datagrams_queue[ip])

            log(
                "ip-c",
                f"ARP resolved: releasing {qlen} datagrams to {ip_address} ({mac_address})",
                level="INFO"
            )
        for datagram in self._arp_pending_datagrams_queue[ip]:
            core.tx_ether(
                payload=datagram,
                src=self.core.unicast_mac,
                dst=mac_address,
                type_=0x0800
            )

        # clean this pending queue
        self._arp_pending_datagrams_queue.pop(ip, None)

    def is_enqueued(self, ip_address: IPAddress):
        # returns True if there is a pending datagram
        # waiting for a replay of an arp request
        if ip_address.ip in self._arp_pending_datagrams_queue:
            return True
        return False


