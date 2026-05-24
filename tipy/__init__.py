from tipy.lib.stack import core

from tipy.lib import socket
from tipy.lib.logger import log

import os
import sys
import fcntl
import struct


TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000


def open_tap_interface(ifname: str) -> int:
    try:
        fd = os.open("/dev/net/tun", os.O_RDWR)

    except FileNotFoundError:
        log("stack",
            "Unable to access '/dev/net/tun' device",
            level="ERROR"
            )
        sys.exit(-1)

    fcntl.ioctl(
        fd,
        TUNSETIFF,
        struct.pack("16sH", ifname.encode(), IFF_TAP | IFF_NO_PI),
    )
    

    return fd



class Tipy:

    def __init__(self,*, ifname: str):
        self.__ifname = ifname

        self.__iface: int = open_tap_interface(ifname=ifname)
        core.iface = self.__iface


    def start(self):
        core.start_stack()


    def stop(self):
        core.stop_stack()


