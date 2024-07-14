"""
Prologix GPIB-ETHERNET NetFinder protocol definitions and core functions
"""

import logging
import socket
from collections import namedtuple
from enum import IntEnum
from random import randint
from socket import (  # pylint: disable=no-name-in-module
    AddressFamily,
    inet_aton,
    inet_ntoa,
)
from struct import calcsize, pack, unpack
from time import perf_counter
from typing import Any, Callable, Dict, Optional, Union

from prologix_netfinder.getifaddrs import IFF, getifinfo


logger = logging.getLogger(__name__)


# fmt: off
class Command(IntEnum):
    """command & reply ID's for Prologix controller"""

    IDENTIFY           =  0
    IDENTIFY_REPLY     =  1
    ASSIGNMENT         =  2
    ASSIGNMENT_REPLY   =  3
    FLASH_ERASE        =  4
    FLASH_ERASE_REPLY  =  5
    BLOCK_SIZE         =  6
    BLOCK_SIZE_REPLY   =  7
    BLOCK_WRITE        =  8
    BLOCK_WRITE_REPLY  =  9
    VERIFY             = 10
    VERIFY_REPLY       = 11
    REBOOT             = 12
    SET_MAC_ADDR       = 13
    SET_MAC_ADDR_REPLY = 14
    TEST               = 15
    TEST_REPLY         = 16


class Result(IntEnum):
    """results of commands"""

    SUCCESS             = 0
    CRC_MISMATCH        = 1
    INVALID_MEMORY_TYPE = 2
    INVALID_SIZE        = 3
    INVALID_IP_TYPE     = 4


class IPType(IntEnum):
    """type of IP address"""

    DYNAMIC = 0
    STATIC  = 1


class Alert(IntEnum):
    """alert codes (not used below; when are these used?)"""

    OK    = 0x00
    WARN  = 0x01
    ERROR = 0xFF


class Mode(IntEnum):
    """modes (others possible?)"""

    BOOTLOADER  = 0
    APPLICATION = 1


class MemoryType(IntEnum):
    """memory type (for reading or writing)"""

    FLASH  = 0
    EEPROM = 1


class RebootType(IntEnum):
    """reboot type"""

    CALL_BOOTLOADER = 0
    RESET           = 1


HEADER_FMT = "!2cH6s2x"
FMTS = {
    "HEADER"             : "!2cH6s2x",
    "IDENTIFY"           : HEADER_FMT,
    "IDENTIFY_REPLY"     : "!H6c4s4s4s4s4s4s32s",
    "ASSIGNMENT"         : "!3xc4s4s4s32x",
    "ASSIGNMENT_REPLY"   : "!c3x",
    "FLASH_ERASE"        : HEADER_FMT,
    "FLASH_ERASE_REPLY"  : HEADER_FMT,
    "BLOCK_SIZE"         : HEADER_FMT,
    "BLOCK_SIZE_REPLY"   : "!H2x",
    "BLOCK_WRITE"        : "!cxHI",
    "BLOCK_WRITE_REPLY"  : "!c3x",
    "VERIFY"             : HEADER_FMT,
    "VERIFY_REPLY"       : "!c3x",
    "REBOOT"             : "!c3x",
    "SET_MAC_ADDR"       : "!6s2x",
    "SET_MAC_ADDR_REPLY" : HEADER_FMT,
    "TEST"               : HEADER_FMT,
    "TEST_REPLY"         : "!32s",
}
# fmt: on

HEADER_LEN = calcsize(HEADER_FMT)
LENS = {name: calcsize(fmt) for name, fmt in FMTS.items()}

MAGIC = 0x5A
MAGIC_BCHR = chr(MAGIC).encode("ascii")

NETFINDER_SERVER_PORT = 3040

MAX_ATTEMPTS = 10
MAX_TIMEOUT = 0.5


Uptime = namedtuple("Uptime", ["days", "hours", "minutes", "seconds"])


def make_header(command: int, seq: int, mac_addr: Union[int, str, bytes]) -> bytes:
    return pack(
        HEADER_FMT,
        MAGIC_BCHR,
        chr(command).encode("ascii"),
        seq,
        mac_addr2bytes(mac_addr),
    )


def extract_header(msg: bytes) -> Dict[str, Any]:
    params = unpack(HEADER_FMT, msg)
    return {
        "magic": ord(params[0]),
        "command": Command(ord(params[1])),
        "seq": params[2],
        "mac_addr": mac_addr2str(params[3]),
    }


def make_identify_message(seq: int) -> bytes:
    return make_header(
        command=Command.IDENTIFY,
        seq=seq,
        mac_addr=b"\xFF\xFF\xFF\xFF\xFF\xFF",
    )


def extract_identify_reponse(msg: bytes) -> Dict[str, Any]:
    info = extract_header(msg[:HEADER_LEN])

    params = unpack(FMTS["IDENTIFY_REPLY"], msg[HEADER_LEN:])

    info.update(
        {
            "uptime": Uptime(
                days=params[0],
                hours=ord(params[1]),
                minutes=ord(params[2]),
                seconds=ord(params[3]),
            ),
            "mode": Mode(ord(params[4])),
            "alert": Alert(ord(params[5])),
            "ip_type": IPType(ord(params[6])),
            "ip_addr": inet_ntoa(params[7]),
            "ip_netmask": inet_ntoa(params[8]),
            "ip_gateway": inet_ntoa(params[9]),
            "app_ver": inet_ntoa(params[10]),
            "boot_ver": inet_ntoa(params[11]),
            "hw_ver": inet_ntoa(params[12]),
            "name": params[13],
        }
    )

    return info


def make_assignment_message(
    seq: int,
    mac_addr: Union[int, str, bytes],
    ip_type: Union[int, str, IPType],
    ip_addr: Union[int, bytes, str],
    netmask: Union[int, bytes, str],
    gateway: Union[int, bytes, str],
) -> bytes:
    if isinstance(ip_type, str):
        ip_type = IPType[ip_type.upper()]
    ip_addr = ip2bytes(ip_addr)
    netmask = ip2bytes(netmask)
    gateway = ip2bytes(gateway)

    return make_header(command=Command.ASSIGNMENT, seq=seq, mac_addr=mac_addr) + pack(
        FMTS["ASSIGNMENT"],
        chr(ip_type).encode("ascii"),
        ip_addr,
        netmask,
        gateway,
    )


def extract_assignment_response(msg: bytes) -> Dict[str, Any]:
    info = extract_header(msg[:HEADER_LEN])
    params = unpack(FMTS["ASSIGNMENT_REPLY"], msg[HEADER_LEN:])
    info["result"] = Result(ord(params[0]))
    return info


def make_flash_erase_message(seq: int, mac_addr: Union[int, str, bytes]) -> bytes:
    return make_header(command=Command.FLASH_ERASE, seq=seq, mac_addr=mac_addr)


def extract_flash_erase_response(msg: bytes) -> Dict[str, Any]:
    return extract_header(msg)


def make_block_size_message(seq: int, mac_addr: Union[int, str, bytes]) -> bytes:
    return make_header(command=Command.BLOCK_SIZE, seq=seq, mac_addr=mac_addr)


def extract_block_size_response(msg: bytes) -> Dict[str, Any]:
    info = extract_header(msg[:HEADER_LEN])
    params = unpack(FMTS["BLOCK_SIZE_REPLY"], msg[HEADER_LEN:])
    info["size"] = params[0]
    return info


def make_block_write_message(
    seq: int,
    mac_addr: Union[int, str, bytes],
    memtype: Union[int, str, MemoryType],
    addr: int,
    data: bytes,
) -> bytes:
    if isinstance(memtype, str):
        memtype = MemoryType[memtype.upper()]

    return (
        make_header(command=Command.BLOCK_WRITE, seq=seq, mac_addr=mac_addr)
        + pack(
            FMTS["BLOCK_WRITE"],
            chr(memtype).encode("ascii"),
            len(data),
            addr,
        )
        + data
    )


def extract_block_write_response(msg: bytes) -> Dict[str, Any]:
    info = extract_header(msg[:HEADER_LEN])
    params = unpack(FMTS["BLOCK_WRITE_REPLY"], msg[HEADER_LEN:])
    info["result"] = Result(ord(params[0]))
    return info


def make_verify_message(seq: int, mac_addr: Union[int, str, bytes]) -> bytes:
    return make_header(command=Command.VERIFY, seq=seq, mac_addr=mac_addr)


def extract_verify_response(msg: bytes) -> Dict[str, Any]:
    info = extract_header(msg[:HEADER_LEN])
    params = unpack(FMTS["VERIFY_REPLY"], msg[HEADER_LEN:])
    info["result"] = Result(ord(params[0]))
    return info


def make_reboot_message(
    seq: int, mac_addr: Union[int, str, bytes], reboottype: Union[int, str, RebootType]
) -> bytes:
    if isinstance(reboottype, str):
        reboottype = RebootType[reboottype.upper()]

    return make_header(command=Command.REBOOT, seq=seq, mac_addr=mac_addr) + pack(
        FMTS["REBOOT"], chr(reboottype).encode("ascii")
    )


def make_test_message(seq: int, mac_addr: Union[int, str, bytes]) -> bytes:
    return make_header(command=Command.TEST, seq=seq, mac_addr=mac_addr)


def extract_test_response(msg: bytes) -> Dict[str, Any]:
    info = extract_header(msg[:HEADER_LEN])
    params = unpack(FMTS["TEST_REPLY"], msg[HEADER_LEN:])
    # NOTE: split extracts null-terminated bytes "string" (as bytes object) by
    # splitting on the null char and taking the first split (works with empty
    # string as well)
    info["result"] = params[0].split(b"\00")[0]
    print(f"{info['result'] = }")
    return info


def make_set_mac_addr_message(
    seq: int, mac_addr: Union[int, str, bytes], new_mac_addr: Union[int, str, bytes]
) -> bytes:
    return make_header(command=Command.SET_MAC_ADDR, seq=seq, mac_addr=mac_addr) + pack(
        FMTS["SET_MAC_ADDR"], mac_addr2bytes(new_mac_addr)
    )


def extract_set_mac_addr_response(msg: bytes) -> Dict[str, Any]:
    return extract_header(msg)


def send_message(send_skt: socket.socket, msg: bytes) -> None:
    send_skt.sendto(msg, ("<broadcast>", NETFINDER_SERVER_PORT))


def receive_message(recv_skt: socket.socket, buffersize: int = 4096) -> bytes:
    # TODO: previously 256 bytes, now set to 4096; should be something else?
    return recv_skt.recv(buffersize)


def discover_devices(
    send_skt: socket.socket, recv_skt: socket.socket
) -> Dict[str, Dict[str, Any]]:
    devices = {}

    for _attempt in range(2):
        seq = randint(1, 65535)
        msg = make_identify_message(seq)

        try:
            send_message(send_skt, msg)
        except OSError as err:
            logger.debug(
                "send_message failed, send_skt=%s, msg=%s", send_skt, msg, exc_info=err
            )
            continue

        expiration_time = perf_counter() + MAX_TIMEOUT
        while perf_counter() < expiration_time:
            try:
                reply = receive_message(recv_skt)
            except OSError as err:
                logger.debug(
                    "receive_message failed, recv_skt=%s", recv_skt, exc_info=err
                )
                continue

            if len(reply) != HEADER_LEN + LENS["IDENTIFY_REPLY"]:
                logger.debug(
                    "len(reply) = %d != HEADER_LEN + LENS['IDENTIFY_REPLY'] = %d",
                    len(reply),
                    HEADER_LEN + LENS["IDENTIFY_REPLY"],
                )
                continue

            info = extract_identify_reponse(reply)

            if info["magic"] != MAGIC:
                logger.debug("info['magic']=%d != MAGIC=%d", info["magic"], MAGIC)
                continue
            if info["command"] != Command.IDENTIFY_REPLY:
                logger.debug(
                    "info['command']=%d != Command.IDENTIFY_REPLY=%d",
                    info["command"],
                    Command.IDENTIFY_REPLY,
                )
                continue
            if info["seq"] != seq:
                logger.debug("info['seq']=%d != seq=%d", info["seq"], seq)
                continue

            devices[info["mac_addr"]] = info

    return devices


def identify_device(
    send_skt: socket.socket, recv_skt: socket.socket, mac_addr: Union[int, bytes, str]
) -> Dict[str, Any]:
    mac_addr = mac_addr2str(mac_addr)

    for _attempt in range(2):
        seq = randint(1, 65535)
        msg = make_identify_message(seq)

        try:
            send_message(send_skt, msg)
        except OSError:
            continue

        expiration_time = perf_counter() + 2  # Longer timeout

        while perf_counter() < expiration_time:
            try:
                reply = receive_message(recv_skt)
            except OSError:
                continue

            if len(reply) != HEADER_LEN + LENS["IDENTIFY_REPLY"]:
                continue

            info = extract_identify_reponse(reply)

            if info["magic"] != MAGIC:
                continue
            if info["command"] != Command.IDENTIFY_REPLY:
                continue
            if info["seq"] != seq:
                continue
            if info["mac_addr"] != mac_addr:
                continue

            return info

    return {}


def set_network_settings(
    send_skt: socket.socket,
    recv_skt: socket.socket,
    mac_addr: Union[int, str, bytes],
    ip_type: Union[int, str, IPType],
    ip_addr: Union[int, str, bytes],
    netmask: Union[int, str, bytes],
    gateway: Union[int, str, bytes],
):
    mac_addr = mac_addr2str(mac_addr)

    for _attempt in range(MAX_ATTEMPTS):
        seq = randint(1, 65535)
        msg = make_assignment_message(
            seq=seq,
            mac_addr=mac_addr,
            ip_type=ip_type,
            ip_addr=ip_addr,
            netmask=netmask,
            gateway=gateway,
        )

        try:
            send_message(send_skt, msg)
        except OSError:
            continue

        expiration_time = perf_counter() + MAX_TIMEOUT

        while perf_counter() < expiration_time:
            try:
                reply = receive_message(recv_skt)
            except OSError:
                continue

            if len(reply) != HEADER_LEN + LENS["ASSIGNMENT_REPLY"]:
                continue

            info = extract_assignment_response(reply)

            if info["magic"] != MAGIC:
                continue
            if info["command"] != Command.ASSIGNMENT_REPLY:
                continue
            if info["seq"] != seq:
                continue
            if info["mac_addr"] != mac_addr:
                continue

            return info

    return {}


def erase_flash(
    send_skt: socket.socket, recv_skt: socket.socket, mac_addr: Union[int, str, bytes]
) -> Dict[str, Any]:
    for _attempt in range(MAX_ATTEMPTS):
        seq = randint(1, 65535)
        msg = make_flash_erase_message(seq, mac_addr)

        try:
            send_message(send_skt, msg)
        except OSError:
            continue

        expiration_time = perf_counter() + 10  # Flash erase could take a while

        while perf_counter() < expiration_time:
            try:
                reply = receive_message(recv_skt)
            except OSError:
                continue

            if len(reply) != HEADER_LEN:
                continue

            info = extract_flash_erase_response(reply)

            if info["magic"] != MAGIC:
                continue
            if info["command"] != Command.FLASH_ERASE_REPLY:
                continue
            if info["seq"] != seq:
                continue
            if info["mac_addr"] != mac_addr:
                continue

            return info

    return {}


def block_size(
    send_skt: socket.socket, recv_skt: socket.socket, mac_addr: Union[int, str, bytes]
) -> Dict[str, Any]:
    for _attempt in range(MAX_ATTEMPTS):
        seq = randint(1, 65535)
        msg = make_block_size_message(seq, mac_addr)

        try:
            send_message(send_skt, msg)
        except OSError:
            continue

        expiration_time = perf_counter() + MAX_TIMEOUT

        while perf_counter() < expiration_time:
            try:
                reply = receive_message(recv_skt)
            except OSError:
                continue

            if len(reply) != HEADER_LEN + LENS["BLOCK_SIZE_REPLY"]:
                continue

            info = extract_block_size_response(reply)

            if info["magic"] != MAGIC:
                continue
            if info["command"] != Command.BLOCK_SIZE_REPLY:
                continue
            if info["seq"] != seq:
                continue
            if info["mac_addr"] != mac_addr:
                continue

            return info

    return {}


def write_block(
    send_skt: socket.socket,
    recv_skt: socket.socket,
    mac_addr: Union[int, str, bytes],
    memtype: Union[int, str, MemoryType],
    addr: int,
    data: bytes,
) -> Dict[str, Any]:
    for _attempt in range(MAX_ATTEMPTS):
        seq = randint(1, 65535)
        msg = make_block_write_message(
            seq=seq, mac_addr=mac_addr, memtype=memtype, addr=addr, data=data
        )

        try:
            send_message(send_skt, msg)
        except OSError:
            continue

        expiration_time = perf_counter() + MAX_TIMEOUT

        while perf_counter() < expiration_time:
            try:
                reply = receive_message(recv_skt)
            except OSError:
                continue

            if len(reply) != HEADER_LEN + LENS["BLOCK_WRITE_REPLY"]:
                continue

            info = extract_block_write_response(reply)

            if info["magic"] != MAGIC:
                continue
            if info["command"] != Command.BLOCK_WRITE_REPLY:
                continue
            if info["seq"] != seq:
                continue
            if info["mac_addr"] != mac_addr:
                continue

            return info

    return {}


def verify(
    send_skt: socket.socket, recv_skt: socket.socket, mac_addr: Union[int, str, bytes]
) -> Dict[str, Any]:
    for _attempt in range(MAX_ATTEMPTS):
        seq = randint(1, 65535)
        msg = make_verify_message(seq, mac_addr)

        try:
            send_message(send_skt, msg)
        except OSError:
            continue

        expiration_time = perf_counter() + MAX_TIMEOUT

        while perf_counter() < expiration_time:
            try:
                reply = receive_message(recv_skt)
            except OSError:
                continue

            if len(reply) != HEADER_LEN + LENS["VERIFY_REPLY"]:
                continue

            info = extract_verify_response(reply)

            if info["magic"] != MAGIC:
                continue
            if info["command"] != Command.VERIFY_REPLY:
                continue
            if info["seq"] != seq:
                continue
            if info["mac_addr"] != mac_addr:
                continue

            return info

    return {}


def reboot(
    send_skt: socket.socket,
    mac_addr: Union[int, str, bytes],
    reboottype: Union[int, str, RebootType],
):
    seq = randint(1, 65535)
    msg = make_reboot_message(seq, mac_addr, reboottype)
    send_message(send_skt, msg)


def test(
    send_skt: socket.socket, recv_skt: socket.socket, mac_addr: Union[int, str, bytes]
) -> Dict[str, Any]:
    seq = randint(1, 65535)
    msg = make_test_message(seq, mac_addr)

    send_message(send_skt, msg)
    expiration_time = perf_counter() + MAX_TIMEOUT

    while perf_counter() < expiration_time:
        try:
            reply = receive_message(recv_skt)
        except OSError:
            continue

        if len(reply) != HEADER_LEN + LENS["TEST_REPLY"]:
            continue

        info = extract_test_response(reply)

        if info["magic"] != MAGIC:
            continue
        if info["command"] != Command.TEST_REPLY:
            continue
        if info["seq"] != seq:
            continue
        if info["mac_addr"] != mac_addr:
            continue

        return info

    return {}


def set_mac_addr(
    send_skt: socket.socket,
    recv_skt: socket.socket,
    mac_addr: Union[int, str, bytes],
    new_mac_addr: Union[int, str, bytes],
) -> Dict[str, Any]:
    seq = randint(1, 65535)
    msg = make_set_mac_addr_message(seq, mac_addr, new_mac_addr)

    send_message(send_skt, msg)
    expiration_time = perf_counter() + MAX_TIMEOUT

    while perf_counter() < expiration_time:
        try:
            reply = receive_message(recv_skt)
        except OSError:
            continue

        if len(reply) != HEADER_LEN:
            continue

        info = extract_set_mac_addr_response(reply)

        if info["magic"] != MAGIC:
            continue
        if info["command"] != Command.SET_MAC_ADDR_REPLY:
            continue
        if info["seq"] != seq:
            continue
        if info["mac_addr"] != mac_addr:
            continue

        return info

    return {}


def mac_addr2bytes(mac_addr: Union[int, str, bytes]) -> bytes:
    """Convert MAC address to a len-6 bytes object.

    parameters
    ----------
    mac_addr

    Returns
    -------
    mac_addr_bytes

    """

    orig_mac_addr = mac_addr

    if isinstance(mac_addr, str):
        mac_addr = bytes.fromhex(mac_addr.replace("-", "").replace(":", ""))
    elif isinstance(mac_addr, int):
        mac_addr = mac_addr.to_bytes(6, "big")

    if not isinstance(mac_addr, bytes):
        raise TypeError(
            f"`mac_addr` must have type `bytes`, but {mac_addr=}"
            f" has type {type(mac_addr)}"
        )

    if len(mac_addr) != 6:
        raise ValueError(
            f"MAC address must be 6 bytes but mac_addr={orig_mac_addr!r} is"
            f" {len(mac_addr)} bytes"
        )

    return mac_addr


def mac_addr2str(mac_addr: Union[int, str, bytes]) -> str:
    """Convert MAC address, represented as a len-6 bytes object, integer, or
    already-formatted string, to a human-readable string of colon-separated
    2-hexadecimal-digit bytes.

    parameters
    ----------
    mac_addr

    Returns
    -------
    mac_addr_str

    """

    mac_addr = mac_addr2bytes(mac_addr)
    return mac_addr.hex(":")


def ip2bytes(ip: Union[int, str, bytes]) -> bytes:
    if isinstance(ip, str):
        ip = inet_aton(ip)
    elif isinstance(ip, int):
        ip = ip.to_bytes(4, "big")
    elif not isinstance(ip, bytes):
        raise TypeError

    if len(ip) != 4:
        raise ValueError

    return ip


TMPLT = """MAC address: {mac_addr}
IP address assignment: {ip_type.name}
IP address: {ip_addr}   Netmask: {ip_netmask}   Gateway: {ip_gateway}
Hardware version: {hw_ver}   Bootloader version: {boot_ver}   Application version: {app_ver}
Uptime: {uptime.days} days {uptime.hours:d}:{uptime.minutes:02d}:{uptime.seconds:02d}
Bootloader or application mode: {mode.name}
Alert pending? {alert.name}"""


def format_controller_info(info: Dict[str, Any]) -> str:
    return TMPLT.format(**info)


def find_all_devices(
    filt_func: Optional[Callable] = None,
) -> Dict[str, Dict[str, Any]]:
    """Find all Progix GPIB-ETHERNET controllers.

    Parameters
    ----------
    filt_func
        if callable is provided, it must take `addr_fam`, `name`, and
        `iface_info` as parameters and return True to kep an entry and False to
        discard it

    Returns
    -------
    devices

    """

    devices = {}
    for name, addrs in getifinfo().items():
        if (ipv4_addr_info := addrs.get(AddressFamily.AF_INET, None)) is None:
            continue

        if ipv4_addr_info["flags"] & IFF.LOOPBACK:
            continue

        if callable(filt_func) and not filt_func(name, ipv4_addr_info):
            continue

        host_ip = ipv4_addr_info["addr"]

        logger.info(
            "Searching for Prologix ETHERNET-GPIB controllers via host"
            " interface %s (IP addr=%s)",
            name,
            host_ip,
        )

        send_skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            send_skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            send_skt.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

            port = 0

            try:
                send_skt.bind((host_ip, port))
            except OSError as err:
                logger.warning(
                    "Bind error on send socket %s:%d", host_ip, port, exc_info=err
                )
                continue

            port = send_skt.getsockname()[1]
            logger.debug("port = %d", port)

            recv_skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                recv_skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                recv_skt.setblocking(True)
                recv_skt.settimeout(0.1)

                try:
                    recv_skt.bind(("", port))
                except OSError as err:
                    logger.warning(
                        "Bind error on receive socket :%d", port, exc_info=err
                    )
                    continue

                devices_at_ip = discover_devices(send_skt, recv_skt)
                logger.debug("devices_at_ip = %s", devices_at_ip)

                for mac_addr, info in devices_at_ip.items():
                    info["host_ip"] = host_ip
                    devices[mac_addr] = info

            finally:
                recv_skt.close()
        finally:
            send_skt.close()

    return devices


def validate_network_params(ip_str: str, netmask_str: str, gateway_str: str) -> None:
    """Validate network parameters.

    parameters
    ----------
    ip_str
    netmask_str
    gateway_str

    Raises
    ------
    ValueError
        if any net params are deemed invalid

    """

    try:
        ip_bytes = inet_aton(ip_str)
    except Exception as err:
        raise ValueError(f'IP address "{ip_str}" is invalid.') from err

    try:
        netmask_bytes = inet_aton(netmask_str)
    except Exception as err:
        raise ValueError(f'Network mask "{netmask_str}" is invalid.') from err

    try:
        gateway_bytes = inet_aton(gateway_str)
    except Exception as err:
        raise ValueError(f'Gateway address "{gateway_str}" is invalid.') from err

    # Validate network mask

    # Convert to integer from byte array
    netmask_int: int = unpack("!L", netmask_bytes)[0]

    # Exclude restricted masks
    if netmask_int in {0, 0xFFFFFFFF}:
        raise ValueError(f'Network mask "{netmask_str}" is invalid.')

    # Exclude non-left-contiguous masks
    if ((netmask_int + (netmask_int & -netmask_int)) & 0xFFFFFFFF) != 0:
        raise ValueError(f'Network mask "{netmask_str}" is not contiguous.')

    # Validate gateway address

    octet1 = gateway_bytes[0]  # NOTE: picking out single byte gives its int value

    # Convert to integer from byte array
    gateway_int = unpack("!L", gateway_bytes)[0]

    # Exclude restricted gateway addresses
    # NOTE: 0.0.0.0 is valid
    if (gateway_int != 0) and ((octet1 == 0) or (octet1 == 127) or (octet1 > 223)):
        raise ValueError(f'Gateway address "{gateway_str}" is invalid.')

    # Validate IP address

    octet1 = ip_bytes[0]

    # Convert to integer from byte array
    ip_int = unpack("!L", ip_bytes)[0]

    # Exclude restricted addresses
    if (octet1 == 0) or (octet1 == 127) or (octet1 > 223):
        raise ValueError(f'IP address "{ip_str}" is invalid.')

    # Exclude subnet network address
    if (ip_int & ~netmask_int) == 0:
        raise ValueError(f'IP address "{ip_str}" is invalid.')

    # Exclude subnet broadcast address
    if (ip_int & ~netmask_int) == (0xFFFFFFFF & ~netmask_int):
        raise ValueError(f'IP address "{ip_str}" is invalid.')
