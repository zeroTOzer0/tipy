from tipy import Tipy, socket


IFNAME = "tap7"
LISTEN_IP = "192.168.2.200"
LISTEN_PORT = 9999
PEER_IP = "192.168.2.199"
PEER_PORT = 9999
stack = Tipy(ifname=IFNAME)

try:
    stack.start()

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((LISTEN_IP, LISTEN_PORT))
    udp_sock.connect((PEER_IP, PEER_PORT))
    udp_sock.send(b'test\n\r')

    stack.stop()
except KeyboardInterrupt:
    stack.stop()
