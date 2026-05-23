from tipy import Wyr, socket

IFNAME = "tap7"
LISTEN_IP = "192.168.2.200"
LISTEN_PORT = 9999
PEER_IP = "192.168.2.199"
PEER_PORT = 9992


stack = Wyr(ifname=IFNAME)

try:
    stack.start()

    input("")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((LISTEN_IP, LISTEN_PORT))
    s.connect((PEER_IP, PEER_PORT))

    s.send(b'data\n\r')
    data = s.recv(1024)
    print(data)

    stack.stop()

except KeyboardInterrupt:
    stack.stop()
















