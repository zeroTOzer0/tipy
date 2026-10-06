from struct import pack

class MACFormatError(Exception): ...

class MACAddress:
    """
    Represent a 48-bit MAC address.

    A MAC address can be constructed from either a hexadecimal string or an
    integer. String inputs are parsed and validated when the object is created.
    Integer inputs are assumed to already represent a valid 48-bit MAC address
    and are intentionally not validated for performance reasons. The caller is
    responsible for ensuring that integer inputs are valid.

    Integers are used internally instead of bytes-like objects because MAC
    addresses may be obtained from packet data as ``memoryview`` objects.
    Passing a ``memoryview`` directly to some packing operations requires
    an explicit conversion to ``bytes``. Storing the address as an integer
    avoids these conversions and provides convenient bitwise operations for
    extracting address fields and checking MAC address properties.

    Parameters
    ----------
    macadd : str | int
        The MAC address as a hexadecimal string (with ``:`` or ``-``
        separators) or as its integer representation.

    Raises
    ------
    MACFormatError
        If ``macadd`` is a string that does not contain exactly 12
        hexadecimal digits.

    Notes
    -----
    Integer inputs are not validated. The caller is responsible for
    providing a valid 48-bit MAC address.
    """

    __slots__= (
        "_macadd_int",
        "_macadd_int_high",
        "_macadd_int_low",
        "_macadd_str"
    )

    def __init__(self, macadd: str | int):
        self._macadd_int: int = 0
        self._macadd_int_high: int = 0
        self._macadd_int_low: int = 0
        self._macadd_str: str = ''

        if isinstance(macadd, str):
            # Reject MAC addresses that mix ':' and '-' separators.
            if ":" in macadd and "-" in macadd:
                raise MACFormatError

            # Normalize '-' separators to ':'.
            macadd = macadd.replace("-", ":")

            # A valid MAC address must contain exactly six octets.
            if len(macadd.split(":")) != 6:
                raise MACFormatError

            m = macadd.replace(":", "")

            if len(m) != 12:
                raise MACFormatError

            try:
                self._macadd_int = int(m, 16)
            except ValueError:
                raise MACFormatError

            self._macadd_str = macadd
            self._macadd_int_high = self._macadd_int >> 16
            self._macadd_int_low = self._macadd_int & 0xFFFF
            return

        self._macadd_int = macadd
        self._macadd_int_high = macadd >> 16
        self._macadd_int_low = macadd & 0xFFFF

    @property
    def mac(self):
        """Return the complete 48-bit MAC address as an integer."""
        return self._macadd_int

    @property
    def mac_high(self):
        """Return the upper 32 bits of the MAC address."""
        return self._macadd_int_high

    @property
    def mac_low(self):
        """Return the lower 16 bits of the MAC address."""
        return self._macadd_int_low

    @property
    def mac_str(self):
        """Return the MAC address in colon-separated hexadecimal notation."""
        if not self._macadd_str:
            m = pack("!IH", self._macadd_int_high, self._macadd_int_low)
            self._macadd_str = ":".join(f"{b:02x}" for b in m)

        return self._macadd_str

    def __str__(self):
        return self.mac_str

    @property
    def is_broadcast(self):
        """Return True if this is the broadcast MAC address."""
        return self.mac == 0xFF_FF_FF_FF_FF_FF

    @property
    def is_multicast(self):
        """Return True if the MAC address is a multicast address."""
        # lsb of firs octet == 1
        return (self.mac >> 40) & 0x01 == 1

    @property
    def is_unicast(self):
        """Return True if the MAC address is a unicast address."""
        # lsb of first octet == 0
        return (self.mac >> 40) & 0x01 == 0

    @property
    def is_global(self):
        """Return True if the MAC address uses a globally assigned address."""
        # second lsb of firs octet == 0
        return (self.mac >> 40) & 0x02 == 0

    @property
    def is_local(self):
        """Return True if the MAC address uses a locally administered address."""
        # second lsb of firs octet == 1
        return (self.mac >> 40) & 0x02 != 0
