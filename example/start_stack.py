from tipy import Wyr, socket

IFNAME = "tap7"

stack = Wyr(ifname=IFNAME)

try:
    stack.start()
except KeyboardInterrupt:
    stack.stop()
