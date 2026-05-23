IP_VERSION = 4
IP_TTL = 64
IP_IHL = 5
IP_OPT_EOL_LEN = 1
IP_OPT_NOP_LEN = 1
IP_PROTO: dict =  {
                255 : 'raw',
                1 :'icmp',
                17 : 'udp',
                6 : 'tcp'
            }


