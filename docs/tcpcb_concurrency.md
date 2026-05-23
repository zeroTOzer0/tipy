# Concurrency Model

### The TCPCB class follows an event-driven design for handling send and receive operations. The event loop acts as the primary owner of the connection state.

### However, there are external access points from other threads, such as:
- Application calls (e.g., socket.recv())
- Send requests (e.g., socket.send())
- Other operations that may modify the connection state

### By relying on an event-driven architecture, the amount of shared state that requires protection from race conditions is minimized.

### Only variables that can be accessed or modified from outside the event loop need to be protected.

## Protected variables:
    self._state
    self._rcv_wnd
    self._rcv_adv
    self._rcv_w_buf_offset
    self._snd_r_buf_offset
    self._snd_w_buf_offset
    self._close_requested
    self._shutdown_requested

## Locking strategy:

- ### In all cases, the following lock must be used: self._tcpcb_lock

- ### For read-only access:
    ### Prefer take a snapshot of the variables needed

- ### For modifications:
    ### Acquire the lock manually, update the required variable(s), and release the lock immediately after.

## Note:
### This design aims to minimize concurrency complexity by limiting the scope of shared mutable state.
