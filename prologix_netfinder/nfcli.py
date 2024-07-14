#!/usr/bin/env python3

"""
Netfinder command-line interface
"""

import argparse
import logging
import socket
from functools import partial
from typing import Union

from prologix_netfinder.nfutil import (
    Result,
    IPType,
    set_network_settings,
    find_all_devices,
    format_controller_info,
    mac_addr2str,
    validate_network_params,
)


__all__ = ["main"]


logger = logging.getLogger("nfcli")


def main():
    """Command-line interface"""

    logging.basicConfig(level=logging.INFO)

    def list_devices(ip_prefix="", **_kw):
        if ip_prefix and not ip_prefix.endswith("."):
            ip_prefix += "."

        devices = find_all_devices(
            filt_func=lambda nm, nfo: nfo["addr"].startswith(ip_prefix)
        )
        num = len(devices)
        logger.info(
            "Found %d Prologix GPIB-ETHERNET controller%s.\n",
            num,
            "" if num == 1 else "s",
        )
        print("\n\n".join(format_controller_info(info) for info in devices.values()))
        print()

    def modify_network_settings(
        mac_addr: Union[int, bytes, str],
        ip_type: Union[str, IPType],
        ip_addr: str = "0.0.0.0",
        netmask: str = "0.0.0.0",
        gateway: str = "0.0.0.0",
        ip_prefix: str = "",
    ):
        mac_addr = mac_addr2str(mac_addr)

        if ip_prefix and not ip_prefix.endswith("."):
            ip_prefix += "."
        devices = find_all_devices(
            filt_func=lambda nm, nfo: nfo["addr"].startswith(ip_prefix)
        )
        if mac_addr not in devices:
            raise ValueError(
                "Prologix GPIB-ETHERNET Controller at MAC address "
                f'"{mac_addr}" not found.'
            )

        logger.info(
            "Updating network settings of Prologix GPIB-ETHERNET controller %s",
            mac_addr,
        )

        device = devices[mac_addr]

        if isinstance(ip_type, str):
            if ip_type.lower() == "static":
                ip_type = IPType.STATIC
            elif ip_type.lower() in {"dynamic", "dhcp"}:
                ip_type = IPType.DYNAMIC
            else:
                raise ValueError(f"{ip_type = } invalid")

        if IPType.STATIC not in {device["ip_type"], ip_type}:
            logging.warning(
                'Prologix GPIB-ETHERNET controller at MAC address "%s" '
                "already configured for Dynamic Host Configuration Protocol "
                "(DHCP).",
                mac_addr,
            )
            return

        if ip_type == IPType.STATIC:
            validate_network_params(
                ip_str=ip_addr, netmask_str=netmask, gateway_str=gateway
            )
        else:  # ip_type == IPType.DYNAMIC
            if ip_addr != "0.0.0.0":
                raise ValueError('--ip-addr not allowed if --ip-type is "DYNAMIC"')
            if netmask != "0.0.0.0":
                raise ValueError('--netmask not allowed if --ip-type is "DYNAMIC"')
            if gateway != "0.0.0.0":
                raise ValueError('--gateway not allowed if --ip-type is "DYNAMIC"')

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as send_skt:
            send_skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            send_skt.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

            port = 0

            try:
                send_skt.bind((device["host_ip"], port))
            except OSError as err:
                raise Exception(
                    f'Bind error on send socket {device["host_ip"]}:{port}'
                ) from err

            port = send_skt.getsockname()[1]

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as recv_skt:
                recv_skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                recv_skt.setblocking(True)
                recv_skt.settimeout(0.100)

                try:
                    recv_skt.bind(("", port))
                except OSError as err:
                    raise Exception(f"Bind error on receive socket :{port}") from err

                result = set_network_settings(
                    send_skt, recv_skt, mac_addr, ip_type, ip_addr, netmask, gateway
                )

        if not result or result["result"] != Result.SUCCESS:
            raise Exception("Network settings update failed.")

        logger.info("Network settings updated successfully.")

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(required=True)

    # ==

    parser_list = subparsers.add_parser("list", help="search for controllers")
    parser_list.set_defaults(func=list_devices)

    # ==

    parser_dynamic = subparsers.add_parser(
        "set-dynamic",
        help="""Configure Prologix controller with Dynamic Host Configuration
        Protocol (DHCP) network configuration.""",
    )
    parser_dynamic.set_defaults(
        func=partial(modify_network_settings, ip_type="dynamic")
    )

    parser_static = subparsers.add_parser(
        "set-static",
        help="Configure Prologix controller with static network configuration.",
    )
    parser_static.set_defaults(func=partial(modify_network_settings, ip_type="static"))

    for p in [parser_dynamic, parser_static]:
        p.add_argument(
            "--mac-addr",
            "-m",
            required=True,
            help="""Modify network settings of controller with this MAC address
            (this does NOT set the MAC address; MAC address is fixed)""",
        )

    parser_static.add_argument(
        "--ip-addr",
        "-a",
        required=True,
        help="Set controller's IP address to this value",
    )
    parser_static.add_argument(
        "--netmask",
        "-n",
        required=True,
        help="Set controller's netmask to this value",
    )
    parser_static.add_argument(
        "--gateway",
        "-g",
        required=True,
        help="Set controller's gateway address to this value",
    )

    for p in [parser_list, parser_dynamic, parser_static]:
        p.add_argument(
            "--ip-prefix",
            default="",
            help="""Only check for Prologix GPIB-ETHERNET if attached to
            adapter with address starting with this string (a dot is appended
            if not provided), effectively selecting a network (e.g., specify
            "192.168.0." to pick only adapters with an address with those
            first-three values)""",
        )

    # ==

    args = parser.parse_args()
    kwargs = vars(args)

    func = kwargs.pop("func")
    func(**kwargs)


if __name__ == "__main__":
    main()
