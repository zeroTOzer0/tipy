from __future__ import annotations

import time


from tipy.lib.logger import log
from threading import Condition
from tipy.config.config import ARP_CACHE_TTL, ARP_REPLY_TIMEOUT
from tipy.lib.ethernet import MACAddress

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from tipy.lib.inet import IPAddress
    from tipy.components.core import Core


class ARPCacheEntry:
    def __init__(self, mac_address: MACAddress):
        self.mac_address = mac_address
        self.flush_after: float = time.monotonic() + ARP_CACHE_TTL

class ARPCache:
    def __init__(self, core: Core | None = None):

        # int = remote-ip-address
        self._arp_cache: dict[int, ARPCacheEntry] = dict()

        # Set of IP addresses (as int) waiting for ARP replies
        self._arp_wait_list: set[int] = set()

        # Set of IP addresses pending ARP probe responses
        # If no reply is received, the IP is considered free and can be claimed
        self._arp_wait_prob_list: set[int] = set()

        # General condition variable for normal ARP operations
        self._cond: Condition = Condition()

        # Condition variable notifying the stack core when ARP probe completes
        self.arp_prob_cond: Condition = Condition()

        self.core = core

    def flush_entry(self, ip_address: IPAddress):
        if __debug__:
            entry = self._arp_cache.get(ip_address.ip)

            mac = entry.mac_address if entry else None

            log(
                "arp-c",
                f"ARP cache entry expired: ip={ip_address}, mac={mac}",
                level="INFO"
            )
        self._arp_cache.pop(ip_address.ip, None)


    def find_entry(self, ip_address: IPAddress) -> MACAddress | None:
        with self._cond:
            result = self._arp_cache.get(ip_address.ip, None)

        if result:
            if __debug__:
                ttl = result.flush_after - time.monotonic()

                log(
                    "arp-c",
                    f"ARP cache hit: {ip_address} -> {result.mac_address}, ttl={ttl:.1f}s",
                    level="INFO"
                )
            return result.mac_address

        return None

    def update_arp_cache(self, ip_address: IPAddress, mac_address: MACAddress) -> None:

        ip = ip_address.ip

        with self._cond:
            if ip not in self._arp_cache:
                self._arp_cache[ip] = ARPCacheEntry(mac_address)

                if __debug__:
                    log(
                        "arp",
                        f"ARP cache set: {ip_address} -> {mac_address}",
                        level="INFO"
                    )
                self._cond.notify()

    def arp_probe_add(self, ip_address: IPAddress):
        """
        Add an IP to the ARP probe pending list.
        If the IP is not already pending, schedule a timer to expire
        after ARP_REPLY_TIMEOUT seconds. Upon expiration, the probe
        is cleared and the stack core is notified.

        :param ip_address: IP address in string format.
        """
        ip = ip_address.ip

        if ip not in self._arp_wait_prob_list:
            self._arp_wait_prob_list.add(ip)
            if __debug__:
                if __debug__:
                    log(
                        "arp-c",
                        f"ARP PROBE pending: target={ip_address}, timeout={ARP_REPLY_TIMEOUT}s",
                        level="INFO"
                    )
            # add a timer that automatically clean this pending replay
            # if no replay received and notify the stack core
            self.core.timer.schedule_timer(
                expire_after=ARP_REPLY_TIMEOUT,
                remove_at_execute=True,
                call=lambda: self._probe_done(ip_address),
                timer_name='pending arp prob reply'
            )

    def arp_probe_test(self, ip_address: IPAddress) -> bool:
        """
        Check if an ARP probe is pending for a given IP.

        :param ip_address: IP address in string format.
        :return: True if an ARP probe is awaiting reply, False otherwise.
        """
        if ip_address.ip in self._arp_wait_prob_list:
            return True
        return False

    def _probe_done(self, ip_address: IPAddress):
        """
        Complete the ARP probe for the given IP.
        Removes the IP from the pending list and notifies stack core
        that the IP is now available for the stack.

        :param ip_address: IP address in string format.
        """
        if __debug__:
            log(
                "arp-c",
                f"ARP PROBE timeout: {ip_address} (no reply, entry removed)",
                level="INFO"
            )
        self._arp_wait_prob_list.remove(ip_address.ip)
        with self.arp_prob_cond:
            self.arp_prob_cond.notify_all()


    def arp_wait_add(self, ip_address: IPAddress) -> None:
        """
        Add an IP to the ARP wait list.

        If the IP is not already waiting, schedule a timer to expire
        after ARP_REPLY_TIMEOUT seconds. Upon expiration, the entry
        is removed from the list.

        :param ip_address: Target IP address (string format).
        """
        ip = ip_address.ip

        if not self.arp_wait_test(ip_address):
            self._arp_wait_list.add(ip)
            if __debug__:
                log(
                    "arp-c",
                    f"ARP reply pending: {ip_address} (timeout={ARP_REPLY_TIMEOUT}s)",
                    level="INFO"
                )
            # add a timer that automatically clean this pending replay
            # if no replay received
            self.core.timer.schedule_timer(
                expire_after=ARP_REPLY_TIMEOUT,
                remove_at_execute=True,
                call=lambda: self._arp_wait_remove(ip_address),
                timer_name='pending arp reply'
            )


    def arp_wait_test(self, ip_address: IPAddress) -> bool :
        """
        Check if an ARP request is waiting for a reply.

        :param ip_address: Target IP address (string).
        :return: True if an ARP request is pending, False otherwise.
        """
        # This may help to avoid arp-spoofs attacks
        if ip_address.ip in self._arp_wait_list:
            return True
        return False

    def _arp_wait_remove(self, ip_address: IPAddress):
        """
        Remove an IP from the ARP wait list.
        Called by a timer registered in arp_wait_add().

        :param ip_address: Target IP address (string).
        """

        if __debug__:
            log(
                "arp-c",
                f"ARP waiting for reply failed: {ip_address} (timeout)",
                level="INFO"
            )
        self._arp_wait_list.remove(ip_address.ip)



