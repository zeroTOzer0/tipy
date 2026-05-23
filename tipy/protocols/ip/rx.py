from __future__ import annotations
import struct

from tipy.lib.logger import log
from tipy.protocols.ip.parser import IPParser
from tipy.config.config import DEFRAGMENTATION_TIMEOUT, ENABLE_IP_OPTION
from tipy.protocols.icmp.icmp import (
        DESTINATION_UNREACHABLE, # type
        PROTOCOL_UNREACHABLE,
        TIME_EXCEEDED, # type
        TTL_EXCEEDED,
        REASSEMBLY_TIME_EXCEEDED
    )
from tipy.lib.packet import PacketRX
from tipy.lib.ip_address import IPAddress
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tipy.components.core import Core
    from tipy.components.timer import TimerTask


# NOTE: In _ip_reass, when a new fragment arrives, we update the session timer.
# Timers are stored in a heapq as tuple(execute_at, task), so we must remove the old
# entry and push a new one.
# Updating the task's execute_at attribute in place does not affect the heap order, because the
# tuple's priority (index 0) remains unchanged. Modifying entries within the
# heap would also be inefficient.


def _icmp_proto_unreach(self: Core, packet_rx: PacketRX):
    """
    send icmp protocol unreachable messages
    """
    self.tx_icmp(
        src=IPAddress(packet_rx.ip.dst),
        dst=IPAddress(packet_rx.ip.src),
        type=DESTINATION_UNREACHABLE,
        code=PROTOCOL_UNREACHABLE,
        data=packet_rx.ip.header + packet_rx.ip.data[:8]
    )

def _icmp_defragment_exceeded(self: Core, packet_rx: PacketRX):
    """
    send icmp time exceeded message: reassembly timer exceeded
    type 11 code 1
    """
    self.tx_icmp(
        src=IPAddress(packet_rx.ip.dst),
        dst=IPAddress(packet_rx.ip.src),
        type=TIME_EXCEEDED,
        code=REASSEMBLY_TIME_EXCEEDED,
        data=packet_rx.ip.header + packet_rx.ip.data[:8]
    )

def _icmp_ttl_exceeded(self: Core, packet_rx: PacketRX):
    """
    send icmp time exceeded message: ttl exceeded
    type 11 code 0
    """
    self.tx_icmp(
        src=IPAddress(packet_rx.ip.dst),
        dst=IPAddress(packet_rx.ip.src),
        type=TIME_EXCEEDED,
        code=TTL_EXCEEDED,
        data=packet_rx.ip.header + packet_rx.ip.data[:8]
    )


def _reass_timer_exceeded(self: Core, packet_rx: PacketRX, buffer_id):
    """
    free resources when timer is exceeded, and send out an icmp report
    """
    with self.ip_fragment_cache_rlock:
        if self.ip_fragment_cache.pop(buffer_id, None):
            if __debug__:
                log(
                    "ip-reass",
                    f"incomplete datagram timeout, buffer {buffer_id} released",
                    level="INFO"
                )
            # send icmp message
            _icmp_defragment_exceeded(
                self=self,
                packet_rx=packet_rx
            )


def _dealloc_ip_reass_mem(self: Core, buffer_id):
    """
    deallocate memory resources when reassembly done successfully
    """
    with self.ip_fragment_cache_rlock:
        if self.ip_fragment_cache.pop(buffer_id, None):
            if __debug__:
                log(
                    "ip-reass",
                    f"reassembly complete, buffer released: {buffer_id}",
                    level="DEBUG"
                )

def _ip_reass_timer(self: Core,
                    packet_rx: PacketRX,
                    reass_mem: dict,
                    buffer_id: tuple):
    """
    start new timer for the reassembly session
    used also to extend the timer delay by deleting
    the old timer and starts another one.
    """
    t: TimerTask = self.timer.schedule_timer(
        expire_after=DEFRAGMENTATION_TIMEOUT,
        remove_at_execute=True,
        call=lambda: _reass_timer_exceeded(
            self, packet_rx, buffer_id
        ),
        timer_name='ip-reass'
    )
    self.ip_fragment_cache[buffer_id]['timer'] = t
    if __debug__:
        log(
            "ip-reass",
            f"IP reassembly started, buffer allocated (id={buffer_id})",
            level="DEBUG"
        )

def _alloc_ip_reass_mem(self: Core,
                        packet_rx: PacketRX,
                        buffer_id: tuple):
    """
    allocate ip reassembly memory resources
    """
    with self.ip_fragment_cache_rlock:
        if buffer_id not in self.ip_fragment_cache:
            self.ip_fragment_cache[buffer_id] = {
                'data_buffer' : bytearray(),
                'header_buffer' : bytearray(),
                'block_count' : 0,
                'total_data_len' : 0,
                'temporary_data_buffer' : dict(), # {offset : data}
                'last' : False
            }

            _ip_reass_timer(
                self=self,
                packet_rx=packet_rx,
                reass_mem=self.ip_fragment_cache,
                buffer_id=buffer_id
            )



def _is_reassembled(last: bool, block_count: int, total_data_len: int):
    if last:
        if block_count == int ((total_data_len + 7) // 8):
            return True

    return False



def _ip_reass(self: Core,
              packet_rx: PacketRX):

    buffer_id: tuple = (packet_rx.ip.src,
                        packet_rx.ip.dst,
                        packet_rx.ip.id,
                        packet_rx.ip.protocol
                        )

    # Create buffer-id if needed
    _alloc_ip_reass_mem(self, packet_rx, buffer_id)

    offset = packet_rx.ip.offset
    flag_mf = packet_rx.ip.flag_mf
    total_len = packet_rx.ip.total_len
    ihl = packet_rx.ip.ihl

    with self.ip_fragment_cache_rlock:

        reass_resources = self.ip_fragment_cache[buffer_id]


        if not flag_mf: # The last Fragment
            # Calculate total data len
            reass_resources['total_data_len'] = \
                total_len - ihl + offset*8

            # Activate 'last' Flag
            reass_resources['last'] = True

            # Initialize the data buffer
            reass_resources['data_buffer'] = bytearray(
                                                    reass_resources['total_data_len']
                                                                        )

            # Put the last fragment data in 'data_buffer'
            struct.pack_into(
                        f'!{len(packet_rx.ip.data)}s',
                        reass_resources['data_buffer'],
                        offset*8,
                        packet_rx.ip.data
                            )

            # Put all precedence frags data in the buffer
            for frag in reass_resources['temporary_data_buffer']:
                data = reass_resources['temporary_data_buffer'][frag]
                struct.pack_into(
                    f'!{len(data)}s',
                    reass_resources['data_buffer'],
                    frag * 8,
                    data
                )

            # Clear the 'temporary_data_buffer' to free memory
            del reass_resources['temporary_data_buffer']

            # Increase block_count
            reass_resources['block_count'] += int((offset*8 + total_len - ihl + 7) // 8) - offset

            # Update the total len field in the first header if exists
            if reass_resources['header_buffer']:
                reass_resources['header_buffer'][2:4] =\
                struct.pack(
                    '!H',
                    len(reass_resources['header_buffer']) + \
                    reass_resources['total_data_len']
                )


            # Check the defragmentation status, if True -> Defragmentation Done!
            if _is_reassembled(last=True,
                               block_count=reass_resources['block_count'],
                               total_data_len=reass_resources['total_data_len']
                               ):
                defragmented_ip =\
                    bytes(reass_resources['header_buffer'] +
                          reass_resources['data_buffer'])

                # Reassembly Done ?
                # So stop the timer
                # And clear the defragment resources
                t: TimerTask = reass_resources['timer']
                t.remove() # remove timer
                _dealloc_ip_reass_mem(self, buffer_id)

                return defragmented_ip

            # Update the timer value by removing it and starts another one
            reass_resources['timer'].remove() # remove timer
            _ip_reass_timer(
                self=self,
                packet_rx=packet_rx,
                reass_mem=self.ip_fragment_cache,
                buffer_id=buffer_id
            )

        elif flag_mf and reass_resources['last']:

            if offset == 0:
                # Put this fragment header in 'header_buffer'
                reass_resources['header_buffer'][:] = packet_rx.ip.header
                # Update the total len field
                struct.pack_into(
                    '!H',
                    reass_resources['header_buffer'],
                    4,
                    ihl + reass_resources['total_data_len']
                )

            # Update block_count
            reass_resources['block_count'] += int((offset*8 + total_len - ihl + 7) // 8) - offset

            # Put this fragment data in 'data_buffer'
            struct.pack_into(
                f'!{len(packet_rx.ip.data)}s',
                reass_resources['data_buffer'],
                offset * 8,
                packet_rx.ip.data
            )



            # Check the defragmentation status, if True -> Defragmentation Done!
            if _is_reassembled(last=True,
                               block_count=reass_resources['block_count'],
                               total_data_len=reass_resources['total_data_len']
                               ):
                defragmented_ip = \
                    bytes(reass_resources['header_buffer'] +
                          reass_resources['data_buffer'])

                # Reassembly Done ?
                # Then stop the timer
                # And clear the defragment resources
                t: TimerTask = reass_resources['timer']
                t.remove() # remove timer
                _dealloc_ip_reass_mem(self, buffer_id)


                return defragmented_ip

            # Update the Timer Value by removing it and starts another one
            reass_resources['timer'].remove()  # remove timer
            _ip_reass_timer(
                self=self,
                packet_rx=packet_rx,
                reass_mem=self.ip_fragment_cache,
                buffer_id=buffer_id
            )

        elif flag_mf and not reass_resources['last']:

            if offset == 0:
                # Put this fragment header in 'header_buffer'
                reass_resources['header_buffer'][:] = packet_rx.ip.header

            # Update block_count
            reass_resources['block_count'] += int((offset*8 + total_len - ihl + 7) // 8) - offset

            # Put this fragment data in 'temporary_data_buffer'
            reass_resources['temporary_data_buffer'][offset] = packet_rx.ip.data

            # Update the Timer Value by removing it and starts another one
            reass_resources['timer'].remove()  # remove timer
            _ip_reass_timer(
                self=self,
                packet_rx=packet_rx,
                reass_mem=self.ip_fragment_cache,
                buffer_id=buffer_id
            )


        return False

def rx_ip(self: Core, packet_rx: PacketRX):
    IPParser(packet_rx)

    if __debug__: log(
        'ip',
        f"{packet_rx.tracker} - "
        f'{packet_rx.ip}'
    )

    if packet_rx.ip.ihl > 20 and not ENABLE_IP_OPTION:
        if __debug__:
            log(
                "ip",
                f"{packet_rx.tracker} IP options disabled, packet dropped",
                level="WARN"
            )
        return

    #TODO(ip): add proper multicast/broadcast handling in IP input path
    # Current limitation: only unicast packets destined to this host are accepted

    if IPAddress(packet_rx.ip.src).is_broadcast()\
            or IPAddress(packet_rx.ip.src).is_multicast()\
               or packet_rx.ip.dst != str(self.unicast_ip):

        if __debug__:
            log(
                "ip",
                f"{packet_rx.tracker} packet dropped (not unicast to host): "
                f"{packet_rx.ip.src} -> {packet_rx.ip.dst}",
                level="WARN"
            )
        return


    if packet_rx.ip.ttl == 0:
        if __debug__:
            log(
                "ip",
                f"{packet_rx.tracker} TTL expired, sending ICMP time exceeded",
                level="INFO"
            )
        return _icmp_ttl_exceeded(self, packet_rx)

    if packet_rx.ip.offset == 0 and not packet_rx.ip.flag_mf:
        packet_rx.frame = packet_rx.frame[packet_rx.ip.ihl:
                                         packet_rx.ip.total_len]
        next_layer = self.ip_protocol_map.get(
            packet_rx.ip.protocol, None
        )
        if next_layer:
            return next_layer(self, packet_rx)
        return _icmp_proto_unreach(
            self=self,
            packet_rx=packet_rx
        )


    if reassembled_ip_dgram := _ip_reass(self, packet_rx):
        packet_rx = PacketRX(reassembled_ip_dgram)
        IPParser(packet_rx)
        packet_rx.frame = packet_rx.frame[packet_rx.ip.ihl:
                                         packet_rx.ip.total_len]

        if __debug__:
            log(
                "ip",
                f"{packet_rx.tracker} IP reassembly completed",
                level="INFO"
            )

        next_layer = self.ip_protocol_map.get(
            packet_rx.ip.protocol, None
        )
        if next_layer:
            return next_layer(self, packet_rx)
        return _icmp_proto_unreach(
            self=self,
            packet_rx=packet_rx
        )
    return None


