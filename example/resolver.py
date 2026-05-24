from tipy import Tipy, socket
import struct, sys
import socket as _sk

# simple DNS client

def build_query(domain: str):
    ID = 0x1234
    FLAGS = 0x0100
    QDCOUNT = 1
    ANCOUNT = 0
    NSCOUNT = 0
    ARCOUNT = 0

    header = struct.pack('!HHHHHH', ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)

    qname = b''
    for part in domain.encode('utf-8').split(b'.'):
        qname += bytes([len(part)]) + part

    qname += b'\x00'

    qtype = 1  # A record
    qclass = 1  # IN class
    question = struct.pack('!HH', qtype, qclass)

    return header + qname + question





def parse_query(response):
    header = response[:12]
    ID, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', header)

    pos = 12
    for _ in range(qdcount):
        while response[pos] != 0:
            pos += response[pos] + 1
        pos += 5

    ip_addresses = []
    for _ in range(ancount):
        if response[pos] & 0xC0 == 0xC0:  # ضغط DNS
            pos += 2
        else:
            while response[pos] != 0:
                pos += response[pos] + 1
            pos += 1

        type_, class_, ttl, rdlength = struct.unpack('!HHIH', response[pos:pos + 10])
        pos += 10

        if type_ == 1 and class_ == 1 and rdlength == 4:  # A record
            ip = _sk.inet_ntoa(response[pos:pos + 4])
            ip_addresses.append(ip)

        pos += rdlength

    return ip_addresses


def dns_lookup(domain):
    query = build_query(domain)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(('192.168.2.1', 53))
    sock.settimeout(5)

    sock.send(query)

    response = sock.recv(512)

    ips = parse_query(response)

    sock.close()

    return ips


args = sys.argv
if len(args) == 1:
    print('usage : PYTHONPATH=. python3 ping.py <example.com>')
    sys.exit(0)

stack = Tipy(ifname="tap7")

try:
    stack.start()

    name = sys.argv[1]
    ip = dns_lookup(domain=name)
    print(f"IP addresses for {name}: {ip}")

    stack.stop()

except KeyboardInterrupt:
    stack.stop()

except Exception as e:
    print(f"Error: {e}")
    stack.stop()
