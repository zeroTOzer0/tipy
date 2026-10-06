from __future__ import annotations

class IPFormatError(Exception): ...

class IPAddress:
    """
    Represent an IPv4 address using a 32-bit integer representation.

    An IPv4 address can be constructed from either a dotted-decimal string
    or an integer. String inputs are parsed and validated when the object is
    created. Integer inputs are assumed to already represent a valid
    unsigned 32-bit IPv4 address and are intentionally not validated for
    performance reasons. The caller is responsible for ensuring that integer
    inputs are valid.

    The address is stored internally as an integer to provide efficient
    comparisons, bitwise operations, subnet checks, and other operations
    commonly performed in a network stack. The string representation is
    generated lazily and cached when needed.

    Parameters
    ----------
    ipadd : str | int
        The IPv4 address as a dotted-decimal string or as its unsigned
        32-bit integer representation.

    Raises
    ------
    IPFormatError
        If a string input is not a valid dotted-decimal IPv4 address.

    Notes
    -----
    Validation is performed only when parsing string input, which is
    considered a boundary operation such as reading configuration or
    receiving application-level input. Integer inputs use the fast path
    and therefore do not perform defensive validation.
    """

    __slots__ = ("_ipadd_int", "_ipadd_str")

    def __init__(self, ipadd: str | int):
        self._ipadd_int: int = 0
        self._ipadd_str: str = ''

        # String parsing is assumed to happen only at boundary/configuration levels
        # (e.g., application socket binding, reading configuration file).
        if isinstance(ipadd, str):
            if "." not in ipadd:
                raise IPFormatError
            ip_octets = ipadd.split(".")

            if len(ip_octets) != 4:
                raise IPFormatError

            for i in range(4):
                # check if the str is ascii but no digits
                if not (ip_octets[i].isascii()
                        and ip_octets[i].isdigit()):
                    raise IPFormatError

                # Reject octets with leading zeros (e.g. "001" or "008").
                if len(ip_octets[i]) > 1 and ip_octets[i].startswith("0"):
                    raise IPFormatError

                octet = int(ip_octets[i], 10)

                if not (0x00 <= octet <= 0xFF):
                    raise IPFormatError

                self._ipadd_int = (octet << (24 - i * 8)) | self._ipadd_int

            self._ipadd_str = ipadd
            return

        self._ipadd_int: int = ipadd

    @property
    def ip(self):
        """Return the IPv4 address as an unsigned 32-bit integer."""
        return self._ipadd_int

    @property
    def str_ip(self):
        """Return the IPv4 address in dotted-decimal notation."""
        if not self._ipadd_str:
            ip = self.ip
            self._ipadd_str = (
                f"{(ip >> 24) & 0xFF}."
                f"{(ip >> 16) & 0xFF}."
                f"{(ip >> 8) & 0xFF}."
                f"{ip & 0xFF}"
            )
        return self._ipadd_str

    @property
    def is_private(self):
        """Return True if the address belongs to an RFC 1918 private range."""
        ip = self.ip
        return (
                ip & 0xFF000000 == 0x0A000000
                or ip & 0xFFF00000 == 0xAC100000
                or ip & 0xFFFF0000 == 0xC0A80000  # 255.255.0.0 -> 192.168.0.0
                )

    @property
    def is_public(self):
        """Return True if the address is not in an RFC 1918 private range."""
        return not self.is_private

    @property
    def is_loopback(self) -> bool:
        """Return True if the address belongs to the IPv4 loopback range."""
        return (self.ip & 0xFF000000) == 0x7F000000

    @property
    def is_unicast(self):
        """Return True if the address is a unicast address."""
        return not self.is_multicast and self.ip != 0xFFFFFFFF

    @property
    def is_broadcast(self):
        """Return True if the address is the IPv4 limited broadcast address."""
        return self.ip == 0xFFFFFFFF

    @property
    def is_multicast(self):
        """Return True if the address belongs to the IPv4 multicast range."""
        return self.ip & 0xF0000000 == 0xE0000000

    def is_in_subnet(self, network: IPAddress, mask: IPAddress):
        """
        Return whether this address belongs to the specified subnet.

        Parameters
        ----------
        network : IPAddress
            The network address.
        mask : IPAddress
            The subnet mask.

        Returns
        -------
        bool
            ``True`` if applying the subnet mask to this address produces the
            specified network address.
        """
        return (self.ip & mask.ip) == network.ip

    def __str__(self):
        return self.str_ip
