from __future__ import annotations

from enum import IntEnum

from typing import TYPE_CHECKING, Callable
if TYPE_CHECKING:
    from tipy.lib.socket import Socket

class gaierror(Exception):...

class Errno(IntEnum):
    ECONNREFUSED = 1
    ECONNRESET = 2
    EPIPE = 3
    EADDRNOTAVAIL = 4
    EADDRINUSE = 5
    ENOPROTOOPT = 6
    EOPNOTSUPP = 7
    EINVAL = 8
    ETIMEDOUT = 9
    EDESTADDRREQ = 10
    ENOTCONN = 11

    def __str__(self):
        return self.name

class GaiError(IntEnum):
    EAI_NONAME = -1

    def __str__(self):
        return self.name

def raise_econrefused(so: Socket):
    raise ConnectionRefusedError(f"[Errno {int(so.error)}] Connection refused")

def raise_econreset(so: Socket):
    raise ConnectionResetError(f"[Errno {int(so.error)}] Connection reset by peer")

def raise_epipe(so: Socket):
    raise BrokenPipeError(f"[Errno {int(so.error)}] Broken pipe")

def raise_eaddrnotavail(so: Socket):
    raise OSError(f'[Errno {int(so.error)}] Cannot assign requested address')

def raise_eaddrinuse(so: Socket):
    raise OSError(f"[Errno {int(so.error)}] Address already in use")

def raise_enoprotoopt(so: Socket):
    raise OSError(f'[Errno {int(so.error)}] Protocol not available')

def raise_eopnotsupp(so: Socket):
    raise OSError(f"[Errno {int(so.error)}] Operation not supported")

def raise_einval(so: Socket):
    raise OSError(f"[Errno {int(so.error)}] Invalid argument")

def raise_etimedout(so: Socket):
    raise TimeoutError('timed out')

def raise_edestaddrreq(so: Socket):
    raise OSError(f"[Errno {int(so.error)}] Destination address required")

def rain_enotconn(so: Socket):
    raise OSError(f"[Errno {int(so.error)}] Transport endpoint is not connected")

def raise_eai_noname(so: Socket):
    raise gaierror(f"[Errno {int(so.error)}] Name or service not known")

so_error: dict[int, Callable] = {
    0 : lambda _ : None,
    Errno.ECONNREFUSED   : raise_econrefused,
    Errno.ECONNRESET     : raise_econreset,
    Errno.EPIPE          : raise_epipe,
    Errno.EADDRNOTAVAIL  : raise_eaddrnotavail,
    Errno.EADDRINUSE     : raise_eaddrinuse,
    Errno.ENOPROTOOPT    : raise_enoprotoopt,
    Errno.EOPNOTSUPP     : raise_eopnotsupp,
    Errno.EINVAL         : raise_einval,
    Errno.ETIMEDOUT      : raise_etimedout,
    Errno.EDESTADDRREQ   : raise_edestaddrreq,
    Errno.ENOTCONN       : rain_enotconn,

    GaiError.EAI_NONAME : raise_eai_noname

}