from __future__ import annotations

from tipy.lib.logger import log
from tipy.protocols.tcp.tcpcb import TCPCB
from tipy.lib.socket_errors import gaierror
from tipy.lib.ip_address import IPAddress, IPFormatError
from tipy.protocols.tcp.tcp import NON_RECEIVABLE_STATES
from tipy.protocols.tcp.tcp import TCPEvent, TCPEventType

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tipy.components.core import Core
    from tipy.protocols.tcp.socket import TCPSocket


def tcp_bind(*, self: Core, so: TCPSocket, address: tuple[str, int]):
    try:
        if str(IPAddress(address[0])) != str(self.unicast_ip):
            raise OSError('[Errno 99] Cannot assign requested address')
        so.local_ip = IPAddress(address[0])
    except IPFormatError:
        raise gaierror('[Errno -2] Name or service not known')

    if so.local_port in range(1, 65535):
        # Already bound, cannot bind again this
        # raises an exception when we call bind more than once
        raise OSError("[Errno 22] Invalid argument")

    so.local_port = address[1]

    if self.tcp.check_bound((so.local_ip.ip_address,
                                   so.local_port)):
        raise OSError("[Errno 98] Address already in use")

    so.sock_id = (
        so.local_ip.ip_address, so.local_port,
        so.remote_ip.ip_address, so.remote_port
    )
    self.tcp.register_socket(so.sock_id, so)
    self.tcp.register_bound_socket((so.local_ip.ip_address,
                                          so.local_port))

def tcp_connect(*, self: Core, so: TCPSocket, address: tuple[str, int]):
    so.remote_ip = IPAddress(address[0])
    so.remote_port = address[1]

    if not so.local_port:
        so.local_port = self.tcp.pick_ephemeral_tcp_port()
        # just select the configured IP
        so.local_ip = self.unicast_ip

        so.sock_id = (
            so.local_ip.ip_address, so.local_port,
            so.remote_ip.ip_address, so.remote_port
        )

        self.tcp.register_socket(so.sock_id, so)

    else:
        so.sock_id = (
            so.local_ip.ip_address, so.local_port,
            so.remote_ip.ip_address, so.remote_port
        )

        self.tcp.update_socket(
            (so.local_ip.ip_address, so.local_port, '0.0.0.0', 0),
            so.sock_id,
            so
        )

    # create a TCPCB and register it: STATE=CLOSED
    tcpcb = TCPCB(local_ip=so.local_ip,
                  local_port=so.local_port,
                  remote_ip=so.remote_ip,
                  remote_port=so.remote_port,
                  connect_events=so.connect_events,
                  rcv_events=so.rcv_events,
                  send_events=so.send_events,
                  close_events=so.close_events,
                  sock_opt=so.sock_opt,
                  core=self)

    self.tcp.register_tcpcb(sock_id=so.sock_id, tcpcb=tcpcb)
    with so.connect_events:
        self.tcp_events_schedule.schedule_event(
            event=TCPEvent(
                type_=TCPEventType.CONNECT,
                tcpcb=tcpcb
            )
        )
        so.connect_events.wait()

def tcp_send(*, self: Core, so: TCPSocket, data: bytes) -> int:
    tcpcb = self.tcp.tcpcbs.get(so.sock_id, None)
    mv = memoryview(data)
    original_len = len(mv)
    dlen = len(mv)

    with tcpcb.tcpcb_lock:
        snd_r_buf_offset = tcpcb.snd_r_buf_offset
        snd_w_buf_offset = tcpcb.snd_w_buf_offset

    if __debug__:
        log(
            "tcpcb",
            f"{tcpcb}: send request size={dlen}, "
            f"available_space="
            f"{tcpcb.snd_buf.free(w_offset=snd_w_buf_offset,
                                  r_offset=snd_r_buf_offset
                                  )}",
            level="DEBUG"
        )

    while dlen > 0:
        l = tcpcb.snd_buf.enqueue(
                    w_offset=snd_w_buf_offset,
                    r_offset=snd_r_buf_offset,
                    buffer=mv
                )

        dlen -= l

        with tcpcb.tcpcb_lock:
            tcpcb.snd_w_buf_offset = (
                ( tcpcb.snd_w_buf_offset + l ) % len(tcpcb.snd_buf)
            )

        self.tcp_events_schedule.schedule_event(
            event=TCPEvent(
                type_=TCPEventType.SEND,
                tcpcb=tcpcb
            )
        )

        if dlen > 0:
            with tcpcb.send_events:
                tcpcb.send_events.wait()

    return original_len


def tcp_recv(*, self: Core, so: TCPSocket, bufsize: int) -> list[memoryview]:
    tcpcb = self.tcp.tcpcbs.get(so.sock_id, None)

    with tcpcb.tcpcb_lock:
        state = tcpcb.state
        rcv_r_buf_offset = tcpcb.rcv_r_buf_offset
        rcv_w_buf_offset = tcpcb.rcv_w_buf_offset

    if state in NON_RECEIVABLE_STATES:
        return []

    # check if there is no data in rcv_buf
    if tcpcb.rcv_buf.is_empty(w_offset=rcv_w_buf_offset,
                              r_offset=rcv_r_buf_offset
                              ):
        with tcpcb.recv_events:
            tcpcb.recv_events.wait()

    # retake a snapshot, because we may get notified
    # so the rcv states may be modified
    with tcpcb.tcpcb_lock:
        rcv_r_buf_offset = tcpcb.rcv_r_buf_offset
        rcv_w_buf_offset = tcpcb.rcv_w_buf_offset

    if __debug__:
        available = tcpcb.rcv_buf.free(w_offset=rcv_w_buf_offset,
                                       r_offset=rcv_r_buf_offset
                                       )

        log(
            "tcpcb",
            f"{tcpcb}: recv request bufsize={bufsize}, available={available}",
            level="DEBUG"
        )

    l = tcpcb.rcv_buf.dequeue(w_offset=rcv_w_buf_offset,
                              r_offset=rcv_r_buf_offset,
                              n=bufsize
                              )
    with tcpcb.tcpcb_lock:
        iov_dlen = sum(len(part) for part in l)
        tcpcb.rcv_r_buf_offset = (
            (tcpcb.rcv_r_buf_offset + iov_dlen )  % len(tcpcb.rcv_buf)
        )

    return l


def tcp_close(*, self: Core, so: TCPSocket) -> None:
    tcpcb = self.tcp.tcpcbs.get(so.sock_id, None)
    with tcpcb.tcpcb_lock:
        tcpcb.close_requested = True

    self.tcp_events_schedule.schedule_event(
        event=TCPEvent(
            type_=TCPEventType.SEND,
            tcpcb=tcpcb
        )
    )

def tcp_shutdown(*, self: Core, so: TCPSocket) -> None:
    tcpcb = self.tcp.tcpcbs.get(so.sock_id, None)
    with tcpcb.tcpcb_lock:
        tcpcb.shutdown_requested = True

    self.tcp_events_schedule.schedule_event(
        event=TCPEvent(
            type_=TCPEventType.SEND,
            tcpcb=tcpcb
        )
    )