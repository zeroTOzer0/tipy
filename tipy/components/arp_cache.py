from __future__ import annotations

import time
from tipy.lib.logger import log
from threading import Thread, Condition
from tipy.config.config import ARP_CACHE_TTL, ARP_REPLY_TIMEOUT


from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from tipy.components.core import Core


class ARPCacheEntry:
    def __init__(self, mac_address: str):
        self.mac_address: str = mac_address
        self.flush_after: float = time.monotonic() + ARP_CACHE_TTL



class ARPCache:
    def __init__(self, core: Core | None = None):

        # str -> remote-ip-address
        self._arp_cache: dict[str, ARPCacheEntry] = dict()

        # Set of IP addresses (as strings) waiting for ARP replies
        self._arp_wait_list: set[str] = set()

        # Set of IP addresses pending ARP probe responses
        # If no reply is received, the IP is considered free and can be claimed
        self._arp_wait_prob_list: set[str] = set()

        self._stop_thread = False

        # General condition variable for normal ARP operations
        self._cond: Condition = Condition()

        # Condition variable notifying the stack core when ARP probe completes
        self.arp_prob_cond: Condition = Condition()

        self.core = core


    def start(self):
        Thread(target=self._arp_cache_loop).start()

    def shutdown(self):
        self._stop_thread = True
        with self._cond:
            self._cond.notify_all()
        if __debug__:
            log("stack", "ARP cache shutdown", level="INFO")


    def _arp_cache_loop(self):
        if __debug__:
            log("stack", "ARP cache started", level="INFO")
        while not self._stop_thread:
            with self._cond:
                if self._arp_cache:
                    now = time.monotonic()
                    # must change to list
                    # to avoid RuntimeError: dictionary changed size during iteration
                    for _ in list(self._arp_cache):
                        if self._arp_cache[_].flush_after <= now:
                            self._flush_entry(_)

                if self._arp_cache:
                    smallest_ttl = min(
                        self._arp_cache[_].flush_after \
                        for _ in self._arp_cache
                    )
                    timeout = max(0, smallest_ttl - time.monotonic())
                    self._cond.wait(timeout=timeout)

                elif not self._arp_cache:
                    self._cond.wait()


    def _flush_entry(self, ip_address: str):
        if __debug__:
            entry = self._arp_cache.get(ip_address)

            mac = entry.mac_address if entry else None

            log(
                "arp-c",
                f"ARP cache entry expired: ip={ip_address}, mac={mac}",
                level="INFO"
            )
        self._arp_cache.pop(ip_address, None)


    def find_entry(self, ip_address) -> str | None:
        with self._cond:
            result = self._arp_cache.get(ip_address, None)

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

    def update_arp_cache(self, ip_address: str, mac_address: str) -> None:
        with self._cond:
            if ip_address not in self._arp_cache:
                self._arp_cache[ip_address] = ARPCacheEntry(mac_address)

                if __debug__:
                    log(
                        "arp",
                        f"ARP cache set: {ip_address} -> {mac_address}",
                        level="INFO"
                    )
                self._cond.notify()

    def arp_probe_add(self, ipaddr: str):
        """
        Add an IP to the ARP probe pending list.
        If the IP is not already pending, schedule a timer to expire
        after ARP_REPLY_TIMEOUT seconds. Upon expiration, the probe
        is cleared and the stack core is notified.

        :param ipaddr: IP address in string format.
        """
        if ipaddr not in self._arp_wait_prob_list:
            self._arp_wait_prob_list.add(ipaddr)
            if __debug__:
                if __debug__:
                    log(
                        "arp-c",
                        f"ARP PROBE pending: target={ipaddr}, timeout={ARP_REPLY_TIMEOUT}s",
                        level="INFO"
                    )
            # add a timer that automatically clean this pending replay
            # if no replay received and notify the stack core
            self.core.timer.schedule_timer(
                expire_after=ARP_REPLY_TIMEOUT,
                remove_at_execute=True,
                call=lambda: self._probe_done(ipaddr),
                timer_name='pending arp prob reply'
            )

    def arp_probe_test(self, ipaddr: str) -> bool:
        """
        Check if an ARP probe is pending for a given IP.

        :param ipaddr: IP address in string format.
        :return: True if an ARP probe is awaiting reply, False otherwise.
        """
        if ipaddr in self._arp_wait_prob_list:
            return True
        return False

    def _probe_done(self, ipaddr: str):
        """
        Complete the ARP probe for the given IP.
        Removes the IP from the pending list and notifies stack core
        that the IP is now available for the stack.

        :param ipaddr: IP address in string format.
        """
        if __debug__:
            log(
                "arp-c",
                f"ARP PROBE timeout: {ipaddr} (no reply, entry removed)",
                level="INFO"
            )
        self._arp_wait_prob_list.remove(ipaddr)
        with self.arp_prob_cond:
            self.arp_prob_cond.notify_all()


    def arp_wait_add(self, ipaddr:str) -> None:
        """
        Add an IP to the ARP wait list.

        If the IP is not already waiting, schedule a timer to expire
        after ARP_REPLY_TIMEOUT seconds. Upon expiration, the entry
        is removed from the list.

        :param ipaddr: Target IP address (string format).
        """
        if not self.arp_wait_test(ipaddr):
            self._arp_wait_list.add(ipaddr)
            if __debug__:
                log(
                    "arp-c",
                    f"ARP reply pending: {ipaddr} (timeout={ARP_REPLY_TIMEOUT}s)",
                    level="INFO"
                )
            # add a timer that automatically clean this pending replay
            # if no replay received
            self.core.timer.schedule_timer(
                expire_after=ARP_REPLY_TIMEOUT,
                remove_at_execute=True,
                call=lambda: self._arp_wait_remove(ipaddr),
                timer_name='pending arp reply'
            )


    def arp_wait_test(self, ip_address: str) -> bool :
        """
        Check if an ARP request is waiting for a reply.

        :param ip_address: Target IP address (string).
        :return: True if an ARP request is pending, False otherwise.
        """
        # This may help to avoid arp-spoofs attacks
        if ip_address in self._arp_wait_list:
            return True
        return False

    def _arp_wait_remove(self, ip_address: str):
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
        self._arp_wait_list.remove(ip_address)



