# tipy

Beginner implementation of a TCP/IP stack in Python for learning purposes.  It draws inspiration from [PyTCP](https://github.com/ccie18643/PyTCP)'s modular architecture and zero-copy design, while introducing its own internal logic, architecture, and protocol handling.

---

# Features

## Layer 2 — Data Link Layer

### Ethernet II
- Support Ethernet II frame

### ARP (Address Resolution Protocol)
- ARP request and reply handling
- ARP cache
- Temporary buffering of IP datagrams during MAC resolution
- ARP probe support

### Not yet supported
- Gratuitous ARP
- ARP retry mechanism
- Multicast Ethernet frames

---

## Layer 3 — Network Layer

### IPv4
- Full IPv4 support
- IP fragmentation and reassembly

### Routing
- Direct delivery within the local network
- Default gateway fallback when no matching route exists

### IPv4 Options
- Sending supported
- Receiving not yet implemented

### ICMPv4
- Echo Request / Echo Reply
- Destination Unreachable (port/protocol)
- TTL Exceeded
- Reassembly Timeout Exceeded

### Not yet supported
- Multicast handling
- Broadcast handling

---

## Layer 4 — Transport Layer

### UDP
- Fully supported

### TCP
Basic TCP implementation with support for:

- MSS (Maximum Segment Size)
- TCP options:
  - EOL
  - NOP

### Not yet implemented
- Delayed ACK
- Improved out-of-order segment handling
- Window scaling
- TCP Congestion Control

---

# Socket API

tipy provides a Python-like socket API for easy integration.

## Supported socket types

- `AF_INET / SOCK_DGRAM` — UDP
- `AF_INET / SOCK_STREAM` — TCP
- `AF_INET / SOCK_RAW` — Raw IPv4 access

## Supported operations

- `bind()`
- `connect()`
- `send()`
- `recv()`
- `close()`
- `shutdown()`
- `settimeout()`
- `setsockopt()`

## Not yet supported

- `sendto()`
- `recvfrom()`
- `listen()`

## Supported socket options

### Levels
- `IPPROTO_IP`
- `SOL_SOCKET`

### Options
- `IP_TTL`
- `IP_OPTIONS`
- `SO_LINGER`

---

# Known Limitations

- Packet integrity validation is not yet implemented.
- DHCP is not supported; static network configuration is required.
- `shutdown()` currently only closes the TCP receive path (`SHUT_RD` behavior). `SHUT_WR` is not yet supported.

---

# Usage

## Import the stack

Run your script from the tipy project root directory, then import:

```python
from tipy import tipy, socket
```
## Start the stack
```python
stack = tipy(ifname="tap7")
stack.start()
```

## Create a socket (UDP example)
```python
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((LISTEN_IP, LISTEN_PORT))
sock.connect((PEER_IP, PEER_PORT))
```

## Send data
```python
sock.send(DATA)
```

## Receive data
```python
data = sock.recv(1024)
```

## Close the socket
```python
sock.close()
```

---

# Linux Network Setup (Bridge + TAP using `nmcli`)

This section prepares a Linux bridge and TAP interface required for running tipy.

## Assumptions

The following names and network settings are used in this example:

- Physical interface: `enp0s3`
- Bridge interface: `br0`
- TAP interface: `tap7`
- Network: `192.168.2.0/24`

## 1. Disable the active network connection

```bash
nmcli con down <profile>
```

## 2. Create the bridge interface
```bash
nmcli con add \
  con-name br0 \
  ifname br0 \
  type bridge \
  ipv4.addresses 192.168.2.199/24 \
  ipv4.gateway 192.168.2.1 \
  ipv4.dns 192.168.2.1

nmcli con mod br0 stp no
nmcli con mod br0 ethernet.accept-all-mac-addresses yes
```
- This creates a bridge interface with a static IP address and disables STP for simplicity.

## 3. Attach the physical interface to the bridge
```bash
nmcli con add \
  con-name enp0s3-slave \
  ifname enp0s3 \
  type bridge-slave \
  master br0
```
- This connects your physical network card to the bridge.

## 4. Create the TAP interface
```bash
nmcli con add \
  con-name tap7 \
  ifname tap7 \
  type tun \
  mode tap \
  master br0

nmcli con mod tap7 ethernet.cloned-mac-address 00:11:22:33:44:55
```
- This creates a TAP device and assigns it a fixed MAC address.
- Important: The MAC address assigned here must match the MAC configured in tipy's config.py.

## 5. Bring all interfaces up
```bash
nmcli con up br0
nmcli con up enp0s3-slave
nmcli con up tap7
```
- This activates the bridge, physical interface, and TAP device.

# Python Environment Setup

Set up a Python virtual environment before running tipy.

## 1. Create a virtual environment

```bash
python3 -m venv venv
```

## 2. Activate the virtual environment
```bash
source venv/bin/activate
```

## 3. Install dependencies
```bash
pip install numba
```
- Note: tipy uses numba to speed up checksum calculations.

---

# Running Your Scripts

All scripts must be executed from the **root directory of the tipy project** to ensure proper module resolution.

## Run in optimized mode (no logs)

```bash
PYTHONPATH=. python3 -O your_script.py
```

## Run in normal mode (with logs)
```bash
PYTHONPATH=. python3 your_script.py
```







