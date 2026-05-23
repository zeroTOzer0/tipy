from tipy import Wyr, socket
from time import monotonic, sleep
import statistics
import struct
import sys
import os

PACKET_DATA = b"abcdefghijklmnopqrstuvwabcdefghi"

class Ping:
    def __init__(self, remote_host):

        self.remote_host = remote_host

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IP_PROTO_ICMP)
        self.sock.connect((self.remote_host, 0))
        self.sock.setsockopt(socket.IPPROTO_IP
                             , socket.IPPROTO_TTL,
                             128)

        self.icmp_id = os.getpid() & 0xFFFF
        self.sequence = 0

    def close(self):
        self.sock.close()

    def csum(self, data):
        if len(data) % 2:
            data += b'\x00'

        total = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            total += word
            total = (total & 0xffff) + (total >> 16)

        return ~total & 0xffff

    def build_echo_req(self, sequence, payload):
        icmp_type = 8
        icmp_code = 0
        checksum = 0

        header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, self.icmp_id, sequence)
        packet = header + payload

        checksum = self.csum(packet)
        header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, self.icmp_id, sequence)

        return header + payload

    def parse_reply(self, raw_data):
        if len(raw_data) < 8:
            return None

        icmp_type, icmp_code, checksum, packet_id, sequence \
            = struct.unpack('!BBHHH', raw_data[:8])
        payload = raw_data[8:]

        return {
            'type': icmp_type,
            'code': icmp_code,
            'checksum': checksum,
            'id': packet_id,
            'seq': sequence,
            'payload': payload
        }

    def ping(self, count=50, interval=1):
        rtts = []
        sent = 0
        received = 0

        print(f"Pinging {self.remote_host} with {len(PACKET_DATA)} bytes of data...\n")

        try:
            for seq in range(count):
                sent += 1

                icmp_packet = self.build_echo_req(seq, PACKET_DATA)

                start = monotonic()

                self.sock.send(icmp_packet)

                try:
                    self.sock.settimeout(2.0)
                    raw_reply = self.sock.recv(bufsize=128)

                    reply_info = self.parse_reply(raw_reply)

                    if reply_info and reply_info['type'] == 0:  # Echo Reply
                        if reply_info['id'] == self.icmp_id and reply_info['seq'] == seq:
                            rtt = (monotonic() - start) * 1000
                            rtts.append(rtt)
                            received += 1
                            print(f"Reply from {self.remote_host}: seq={seq} time={rtt:.2f} ms")
                        else:
                            print(f"Mismatched ID/Seq for seq={seq}")
                    else:
                        print(f"Unexpected ICMP type {reply_info['type'] if reply_info else 'None'}")

                except TimeoutError:
                    print(f"Request timeout for seq={seq}")

                sleep(interval)

        except KeyboardInterrupt:
            pass

        print("\n--- Ping statistics ---")
        loss = (1 - (received / sent)) * 100 if sent else 0
        print(f"{sent} packets transmitted, {received} received, {loss:.1f}% packet loss")

        if rtts:
            print(
		        f"--- {self.remote_host} ping statistics ---"
                f"rtt min/avg/max = {min(rtts):.2f}/"
                f"{statistics.mean(rtts):.2f}/"
                f"{max(rtts):.2f} ms"
            )




args = sys.argv
if len(args) == 1:
    print('usage : PYTHONPATH=. python3 ping.py <destination ip address>')
    sys.exit(0)
stack = Wyr(ifname="tap7")

try:
    stack.start()
    ping = Ping(args[1])
    ping.ping(count=50000, interval=0.0000001)
    ping.close()
    stack.stop()
except KeyboardInterrupt:
    stack.stop()
