from __future__ import annotations
from typing import TYPE_CHECKING

from random import randint
from tipy.lib.logger import log
from tipy.protocols.ip.builder import IPBuilder, IPFragBuilder, IPOptBuilder, IPOptEOL, IPOptLSRR
from tipy.config.config import MAC_ADDRESS
from tipy.lib.mac_address import MACAddress
from tipy.lib.ip_address import IPAddress
from tipy.config.config import MTU
from tipy.lib.socket import (
        IPPROTO_IP,          # sock_opt -> level
        IPPROTO_OPTIONS,     # sock_opt -> name
        IPPROTO_TTL          # sock_opt -> name
    )


if TYPE_CHECKING:
    from tipy.protocols.raw.builder import RAWBuilder
    from tipy.protocols.udp.builder import UDPBuilder
    from tipy.protocols.icmp.builder import ICMPBuilder

    from tipy.protocols.ip.builder import (
        IPOptNOP,
        IPOptEOL,
        IPOptLSRR
    )

    from tipy.components.core import Core



def _h_unresolved_mac_datagrams(self: Core,
                                src: IPAddress,
                                dst: IPAddress,
                                datagram: IPBuilder | IPFragBuilder):

    # Check if pending datagram queue is empty (no previous item)
    if not self.ip_cache.is_enqueued(str(dst)):
        # send arp request
        self.tx_arp(
            sha=MACAddress(MAC_ADDRESS),
            spa=src,
            tha=MACAddress(b'\x00'*6),
            tpa=dst,
            op=1,
        )

    # enqueue this datagram temporarily in a pending queue
    return self.ip_cache.enqueue(dst.ip_address, datagram)

def _prep_ip_options(opts: bytes) -> list[IPOptLSRR |IPOptNOP |IPOptEOL]:
    opt_buff = bytearray(opts)
    return IPOptBuilder(opt_buff).build()




def tx_ip(self: Core,
          payload: UDPBuilder
                    |RAWBuilder
                    |ICMPBuilder,

          src:IPAddress,
          dst:IPAddress,
          ttl=64,
          protocol=255,
          options:list[IPOptLSRR
                              |IPOptNOP
                              |IPOptEOL
                              ]|None=None,

          sock_opt: dict|None=None):

    # this var changes when a gateway is needed to reach dst
    # _tpa = dst, if the pkt is delivered within the same subnet
    # _tpa = gateway's ip if the pkt is delivered outside our subnet
    _tpa: IPAddress = dst

    if sock_opt:
        if (IPPROTO_IP, IPPROTO_TTL) in sock_opt:
            ttl = sock_opt[(IPPROTO_IP, IPPROTO_TTL)]
        if (IPPROTO_IP, IPPROTO_OPTIONS) in sock_opt:
            options = _prep_ip_options(
                                        sock_opt[(IPPROTO_IP, IPPROTO_OPTIONS)]
                                      )


    if dst.is_broadcast():
        mac_address = b'\xff\xff\xff\xff\xff\xff'

    # check for the route inside/outside
    elif dst.is_in_subnet(self.network, self.mask):
        mac_address = self.arp_cache.find_entry(dst.ip_address)
        if __debug__: log(
            'ip',
            f'found route to {dst} inside our network'
            f'{self.network}',
            level='INFO'
        )
    else:
        mac_address = self.arp_cache.find_entry(self.router.ip_address)
        _tpa = self.router
        if __debug__: log(
            'ip',
            f'found route to {dst} outside our network, use'
            f'{self.router} to reach {dst.ip_address}',
            level='INFO'
        )

    ip_builder: IPBuilder = IPBuilder(
        payload=payload,
        id=randint(0x0001, 0xffff),
        protocol=protocol,
        src=src,
        dst=dst,
        ttl=ttl,
        options=options
    )

    if __debug__: log(
        'ip',
        f'{payload.tracker} - '
        f'IP {ip_builder}'
    )

    if len(ip_builder) <= MTU:
        # check if we have resolved mac from dst ip
        if mac_address:
            return self.tx_ether(
                payload=ip_builder,
                dst=MACAddress(mac_address),
                src=MACAddress(MAC_ADDRESS),
                type=0x0800
            )
        return _h_unresolved_mac_datagrams(self, src, _tpa, ip_builder)

    # else, fragment needed
    if __debug__: log(
        'ip',
        'IP total length exceeded mtu, fragmentation needed'
    )

    # must take a whole copy of the payload in this case
    # as a bytes format, not a UDPBuilder-obj format for example
    payload = payload.to_bytes(ps_hdr_sum=ip_builder.psum())

    frags: list[IPFragBuilder] = IPFragBuilder(
        payload=payload,
        id=randint(0x0001, 0xffff),
        protocol=protocol,
        src=src,
        dst=dst,
        ttl=ttl,
        options=options,
    ).get_frags()

    # check if we have resolved mac from dst ip
    mac_address = self.arp_cache.find_entry(dst.ip_address)
    if mac_address:
        for frag in frags:
            if __debug__: log(
                'ip',
                f'{frag.tracker} - ' # No tracker, cuz high layer converted to byte object
                f'IP {frag}'
            )
            self.tx_ether(
                payload=frag,
                dst=MACAddress(mac_address),
                src=MACAddress(MAC_ADDRESS),
                type=0x0800
            )
        return

    for frag in frags:
        if __debug__: log(
            'ip',
            f'{frag.tracker} - ' # No tracker, cuz high layer converted to byte object
            f'IP {frag}'
        )
        _h_unresolved_mac_datagrams(self, src, dst, frag)
    return