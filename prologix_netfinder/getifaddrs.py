#!/usr/bin/env python3
# pylint: disable=too-few-public-methods

"""
Call *nix `getifaddrs` & extract the information returned.

Rough replication & some exapnsion of the example program listed in
man(3) getifaddrs (https://www.man7.org/linux/man-pages/man3/getifaddrs.3.html)

Modified from https://github.com/Gautier/minifail/blob/master/minifail/getifaddrs.py
who said in their version of the code:
    "Mostly copied http://carnivore.it/2010/07/22/python_-_getifaddrs"
However, this last link no longer works, so I cannot fully credit the original.
"""

import json
import re
import sys
from ctypes import (
    c_char,
    c_char_p,
    c_int,
    c_short,
    c_uint,
    c_uint8,
    c_uint16,
    c_uint32,
    c_uint64,
    c_ushort,
    c_void_p,
    get_errno,
    pointer,
    CDLL,
    Structure,
    Union,
)
from collections import defaultdict
from enum import IntFlag
from socket import AddressFamily, inet_ntop  # pylint: disable=no-name-in-module
from typing import Any, Dict, Generator, Tuple

PLATFORM = sys.platform
IS_BSD = PLATFORM.startswith("darwin") or PLATFORM.startswith("freebsd")


class IFF(IntFlag):
    """SIOCGIFFLAGS; see ioctl(2); used to interpret `ifa_flags` field"""

    UP = 1 << 0
    BROADCAST = 1 << 1
    DEBUG = 1 << 2
    LOOPBACK = 1 << 3
    POINTOPOINT = 1 << 4
    NOTRAILERS = 1 << 5
    RUNNING = 1 << 6
    NOARP = 1 << 7
    PROMISC = 1 << 8
    ALLMULTI = 1 << 9
    MASTER = 1 << 10
    SLAVE = 1 << 11
    MULTICAST = 1 << 12
    PORTSEL = 1 << 13
    AUTOMEDIA = 1 << 14
    DYNAMIC = 1 << 15


class sockaddr(Structure):
    """AF_UNKNOWN or generic socket address"""

    _fields_ = (
        [
            ("sa_len", c_uint8),
            ("sa_family", c_uint8),
            ("sa_data", (c_uint8 * 14)),
        ]
        if IS_BSD
        else [
            ("sa_family", c_uint16),
            ("sa_data", (c_uint8 * 14)),
        ]
    )


class ifa_ifu_u(Union):
    """union of either broadcast address (multicast, more typical) or
    point-to-point destination address (less typical)"""

    _fields_ = [
        ("ifu_broadaddr", c_void_p),
        ("ifu_dstaddr", c_void_p),
    ]


class rtnl_link_stats(Structure):
    """Main device statistics structure; see
    https://www.kernel.org/doc/html/latest/networking/statistics.html
    """

    _fields_ = [
        ("rx_packets", c_uint32),
        ("tx_packets", c_uint32),
        ("rx_bytes", c_uint32),
        ("tx_bytes", c_uint32),
        ("rx_errors", c_uint32),
        ("tx_errors", c_uint32),
        ("rx_dropped", c_uint32),
        ("tx_dropped", c_uint32),
        ("multicast", c_uint32),
        ("collisions", c_uint32),
        ("rx_length_errors", c_uint32),
        ("rx_over_errors", c_uint32),
        ("rx_crc_errors", c_uint32),
        ("rx_frame_errors", c_uint32),
        ("rx_fifo_errors", c_uint32),
        ("rx_missed_errors", c_uint32),
        ("tx_aborted_errors", c_uint32),
        ("tx_carrier_errors", c_uint32),
        ("tx_fifo_errors", c_uint32),
        ("tx_heartbeat_errors", c_uint32),
        ("tx_window_errors", c_uint32),
        ("rx_compressed", c_uint32),
        ("tx_compressed", c_uint32),
        ("rx_nohandler", c_uint32),
    ]


class rtnl_link_stats64(Structure):
    """Main device statistics structure; see
    https://www.kernel.org/doc/html/latest/networking/statistics.html
    """

    _fields_ = [
        ("rx_packets", c_uint64),
        ("tx_packets", c_uint64),
        ("rx_bytes", c_uint64),
        ("tx_bytes", c_uint64),
        ("rx_errors", c_uint64),
        ("tx_errors", c_uint64),
        ("rx_dropped", c_uint64),
        ("tx_dropped", c_uint64),
        ("multicast", c_uint64),
        ("collisions", c_uint64),
        ("rx_length_errors", c_uint64),
        ("rx_over_errors", c_uint64),
        ("rx_crc_errors", c_uint64),
        ("rx_frame_errors", c_uint64),
        ("rx_fifo_errors", c_uint64),
        ("rx_missed_errors", c_uint64),
        ("tx_aborted_errors", c_uint64),
        ("tx_carrier_errors", c_uint64),
        ("tx_fifo_errors", c_uint64),
        ("tx_heartbeat_errors", c_uint64),
        ("tx_window_errors", c_uint64),
        ("rx_compressed", c_uint64),
        ("tx_compressed", c_uint64),
        ("rx_nohandler", c_uint64),
        ("rx_otherhost_dropped", c_uint64),
    ]


class ifaddrs(Structure):
    """struct populated by `getifaddrs` C-function; see
    https://www.man7.org/linux/man-pages/man3/getifaddrs.3.html"""

    _fields_ = [
        ("ifa_next", c_void_p),
        ("ifa_name", c_char_p),
        ("ifa_flags", c_uint),
        ("ifa_addr", c_void_p),  # -> struct sockaddr
        ("ifa_netmask", c_void_p),  # -> struct sockaddr
        ("ifa_ifu", ifa_ifu_u),
        ("ifa_data", c_void_p),  # -> rtnl_link_stats64
    ]


class in_addr(Union):
    """AF_INET / IPv4 address"""

    _fields_ = [("s_addr", c_uint32)]


class sockaddr_in(Structure):
    """AF_INET / IPv4 interface"""

    _fields_ = (
        [
            ("sin_len", c_uint8),
            ("sin_family", c_uint8),
            ("sin_port", c_uint16),
            ("sin_addr", c_uint8 * 4),
            ("sin_zero", c_uint8 * 8),  # padding
        ]
        if IS_BSD
        else [
            ("sin_family", c_short),
            ("sin_port", c_ushort),
            ("sin_addr", in_addr),
            ("sin_zero", (c_char * 8)),  # padding
        ]
    )


class in6_u(Union):
    """AF_INET6 / IPv6 4, 8, or 16-byte address"""

    _fields_ = [
        ("u6_addr8", (c_uint8 * 16)),
        ("u6_addr16", (c_uint16 * 8)),
        ("u6_addr32", (c_uint32 * 4)),
    ]


class in6_addr(Union):
    """AF_INET6 / IPv6 address"""

    # _fields_ = [("in6_u", in6_u)]
    _fields_ = [("in6_u", c_char * 16)]


class sockaddr_in6(Structure):
    """AF_INET6 / IPv6 interface; see vmlinux.h"""

    _fields_ = [
        ("sin6_family", c_short),
        ("sin6_port", c_ushort),
        ("sin6_flowinfo", c_uint32),
        ("sin6_addr", in6_addr),
        ("sin6_scope_id", c_uint32),
    ]


class sockaddr_ll(Structure):
    """device-independent physical-layer address; see
    https://www.man7.org/linux/man-pages/man7/packet.7.html"""

    _fields_ = [
        ("sll_family", c_ushort),
        ("sll_protocol", c_uint16),
        ("sll_ifindex", c_int),
        ("sll_hatype", c_ushort),
        ("sll_pkttype", c_char),
        ("sll_halen", c_uint8),
        # NOTE: c_char forces interpretation as null-terminated string, but
        # \x00 is a valid part of an address! So using c_byte instead.
        ("sll_addr", (c_uint8 * 8)),
    ]


class sockaddr_dl(Structure):
    """AF_LINK / BSD|OSX"""

    _fields_ = [
        ("sdl_len", c_uint8),
        ("sdl_family", c_uint8),
        ("sdl_index", c_uint16),
        ("sdl_type", c_uint8),
        ("sdl_nlen", c_uint8),
        ("sdl_alen", c_uint8),
        ("sdl_slen", c_uint8),
        ("sdl_data", (c_uint8 * 46)),
    ]


def getifaddrs() -> Generator[Tuple[AddressFamily, str, Dict[str, Any]], str, None]:
    """Get all addresses associated with all network interface on the local
    host, replicating the functionality of calling the `getifaddrs` POSIX
    function.

    Yields
    ------
    address_family
    interface_name
    interface_info

    """

    libc = CDLL("libc.dylib" if PLATFORM == "darwin" else "libc.so.6")

    ifaddrlist_head_ptr = c_void_p(None)

    # error if non-zero return code
    if libc.getifaddrs(pointer(ifaddrlist_head_ptr)) != 0:
        errno = get_errno()
        raise OSError(errno, "call to libc.getifaddrs() failed")

    try:
        if not ifaddrlist_head_ptr.value:  # pointer to head is NULL
            return

        ifa = ifaddrs.from_address(ifaddrlist_head_ptr.value)

        while True:
            name = ifa.ifa_name.decode("utf-8")
            flags = IFF(ifa.ifa_flags)
            if_info: Dict[str, Any] = {"flags": flags}
            if ifa.ifa_addr is None:
                # advance to the next interface
                ifa = ifaddrs.from_address(ifa.ifa_next)
                continue
            sa = sockaddr.from_address(ifa.ifa_addr)
            if sa.sa_family == AddressFamily.AF_INET:
                if ifa.ifa_addr is not None:
                    si4 = sockaddr_in.from_address(ifa.ifa_addr)
                    if_info["addr"] = inet_ntop(AddressFamily.AF_INET, si4.sin_addr)
                    # NOTE: omit port; irrelevant (always 0?) for adapter
                    si4 = sockaddr_in.from_address(ifa.ifa_ifu.ifu_broadaddr)
                    if_info["broadcast"] = inet_ntop(
                        AddressFamily.AF_INET, si4.sin_addr
                    )
                if ifa.ifa_netmask is not None:
                    si4 = sockaddr_in.from_address(ifa.ifa_netmask)
                    if_info["netmask"] = inet_ntop(AddressFamily.AF_INET, si4.sin_addr)

            elif sa.sa_family == AddressFamily.AF_INET6:
                if ifa.ifa_addr is not None:
                    si6 = sockaddr_in6.from_address(ifa.ifa_addr)
                    if_info["family"] = si6.sin6_family
                    # NOTE: omit port; irrelevant (always 0?) for adapter
                    if_info["addr"] = inet_ntop(AddressFamily.AF_INET6, si6.sin6_addr)
                    if_info["flowid"] = si6.sin6_flowinfo
                    if_info["scopeid"] = si6.sin6_scope_id
                if ifa.ifa_netmask is not None:
                    si6 = sockaddr_in6.from_address(ifa.ifa_netmask)
                    if_info["netmask"] = inet_ntop(
                        AddressFamily.AF_INET6, si6.sin6_addr
                    )

            elif sa.sa_family == AddressFamily.AF_PACKET:  # and ifa.ifa_data:
                if ifa.ifa_addr is not None:
                    sll = sockaddr_ll.from_address(ifa.ifa_addr)
                    if_info["addr"] = ":".join(
                        f"{x:02x}" for x in sll.sll_addr[: sll.sll_halen]
                    )

                if ifa.ifa_data is not None:
                    stats = rtnl_link_stats.from_address(ifa.ifa_data)
                    # pylint: disable=protected-access
                    if_info["stats"] = {
                        field: getattr(stats, field)
                        for field, *_ in rtnl_link_stats._fields_
                    }
                    # rx_bytes = if_info["stats"]["rx_bytes"]
                    # if_info["stats"]["rx_bytes"] = rx_bytes / (1024**3)

            if if_info:
                yield AddressFamily(sa.sa_family), name, if_info

            if not ifa.ifa_next:  # pointer to next struct is NULL
                break

            ifa = ifaddrs.from_address(ifa.ifa_next)

    finally:
        libc.freeifaddrs(ifaddrlist_head_ptr)


def getifinfo() -> Dict[str, Dict[AddressFamily, Dict[str, Any]]]:
    """Produce the same information as call to `getifaddrs`, but formatted as a
    dictionary whose keys are interface names and values are themsleves
    dictionaries keyed by address family and values are all further information
    about the address. This structure can be easier to use for iterating over
    all interfaces on the host (rather than iterating over all addresses of all
    adapters on the host).

    Returns
    -------
    if_infos

    """

    if_infos: Dict[str, Dict[AddressFamily, Dict[str, Any]]] = defaultdict(dict)
    for fam, nam, dat in getifaddrs():
        if_infos[nam][fam] = dat
    return {k: dict(sorted(v.items())) for k, v in sorted(if_infos.items())}


def main():
    """command line interface to module which simply displays all info"""
    for ifname, addr_infos in getifinfo().items():
        formatted_addr_infos = {}
        for addr_type, addr_info in addr_infos.items():
            flags = addr_info["flags"]
            flags_str = "|".join(f"{(x & flags).name}" for x in IFF if x & flags)
            addr_info["flags"] = f"{flags.value}<{flags_str}>"
            formatted_addr_infos[addr_type.name] = addr_info
        print(f"[ {ifname} ]")
        print(
            re.compile(r"\s+$")
            .sub(
                "",
                json.dumps(formatted_addr_infos, indent=2)
                .replace('"', "")
                .replace("{", "")
                .replace("}", "")
                .replace(",", ""),
            )
            .replace("\n\n", "\n")
        )
        print()


if __name__ == "__main__":
    main()
