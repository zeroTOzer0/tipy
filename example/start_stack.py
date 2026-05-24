from tipy import Tipy, socket

IFNAME = "tap7"

stack = Tipy(ifname=IFNAME)

try:
    stack.start()
except KeyboardInterrupt:
    stack.stop()
