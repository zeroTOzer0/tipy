IP_STATIC = True

MAC_ADDRESS = '00:11:22:33:44:55'

NETWORK: str | None = '192.168.2.0'
IP_ADDRESS: str | None = '192.168.2.200'
IP_BROADCAST_ADDRESS: str | None = '192.168.2.255'
ROUTER: str | None = '192.168.2.1'
MASK: str | None = '255.255.255.0'

MTU = 1500
IFACE = 'tap7'
DEFRAGMENTATION_TIMEOUT = 10
ARP_REPLY_TIMEOUT = 3
ARP_CACHE_TTL = 300

MSS = 1460

ENABLE_IP_OPTION = False

LOG_CHANEL = {
    "stack",
    'socket',
    "timer",
    "rx-ring",
    "tx-ring",
    "arp-c",
    "ip-c",
    "ether",
    "arp",
    "ip",
    "icmp",
    "udp",
    "tcp",
    "tcpcb",
    'ip-reass',
    'tcp-sched',
    # 'None',
}

EPHEMERAL_PORTS = range(32768, 60999)

