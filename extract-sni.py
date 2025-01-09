#!/usr/bin/env python3

from sys import (
    exit as sys_exit,
    stdout as sys_stdout,
    stderr as sys_stderr
)
from pathlib import Path
from typing import Any, NoReturn, Optional
from subprocess import run as subprocess_run
from collections import defaultdict
from ipaddress import ip_address
from argparse import ArgumentParser, Namespace
from json import dump

# Field for filtering frames/packets by presence of SNI in them
SERVER_NAME_FIELD = 'tls.handshake.extensions_server_name'

# Exclude servers within private networks; feel free to modify
PRIVATE_ADDRESSES_LIST = [
    '127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
PRIVATE_ADDRESSES_STR = ', '.join(PRIVATE_ADDRESSES_LIST)
PRIVATE_ADDRESSES_FILTER = 'not ip.dst in {' + PRIVATE_ADDRESSES_STR + '}'


def die(code: int, message: Optional[str] = None) -> NoReturn:
    """
    Terminates the program with a given exit code and optional message.

    Args:
        code (int): Exit code for the program.
        message (Optional[str]): Message to print to stdout or stderr\
            before exiting.
    """
    if message:
        if 0 != code:
            out = sys_stderr
        else:
            out = sys_stdout
        print(message, file=out)
    sys_exit(code)


def get_pairs_from_pcap(
        pcap_file_path_str: str,
        display_filter: Optional[str] = None
):
    """
    Extracts (IP address, server name) pairs from a pcap file using tshark.

    Args:
        pcap_file_path_str (str): Path to the pcap file.
        display_filter (Optional[str]): Optional display filter to apply\
            to the packet capture.

    Returns:
        set: A set of tuples containing (IP address, server name) pairs.
    """

    # construct the filter for further packet processing
    filter_parts = [PRIVATE_ADDRESSES_FILTER, SERVER_NAME_FIELD]
    if display_filter is None:
        resulting_display_filter = " and ".join(filter_parts)
    else:
        filter_parts.append(display_filter)
        resulting_display_filter = " and ".join(filter_parts)

    # the resulting command argv
    command = [
        "tshark", "-n", "-r", pcap_file_path_str,
        "-Y", resulting_display_filter,
        "-T", "fields", "-E", "separator=,",
        "-e", "ip.dst", "-e", SERVER_NAME_FIELD
    ]

    try:
        result = subprocess_run(
            command,
            check=False, capture_output=True,
            text=True, encoding='utf-8'
        )
        if 0 != result.returncode:
            die(result.returncode, f"Error: {result.stderr}")
        else:
            # deduplicate pairs
            pairs = set(result.stdout.splitlines())
    except Exception as e:
        raise e

    pairs = set(tuple(p.split(',')) for p in pairs)

    return pairs


def sort_aton_dict(aton_dict: dict) -> dict:
    """
    Sorts the address-to-server-names dictionary by IP address and server name.

    Args:
        aton_dict (dict): Dictionary mapping addresses to server names.

    Returns:
        dict: A sorted dictionary of addresses and corresponding server names.
    """
    # sort domains from top to bottom
    for address in aton_dict:
        aton_dict[address].sort(
            key=lambda k: k[0].split('.')[::-1])

    # sort IP addresses in a right way
    sorted_address_to_server_names = dict(
        sorted(
            aton_dict.items(),
            key=lambda item: ip_address(item[0])))

    return sorted_address_to_server_names


def sort_ntoa_dict(ntoa_dict: dict):
    """
    Sorts the server-name-to-address dictionary by server name and IP address.

    Args:
        ntoa_dict (dict): Dictionary mapping server names to addresses.

    Returns:
        dict: A sorted dictionary of server names and corresponding addresses.
    """
    # sort IP addresses in a right way
    for server_name in ntoa_dict:
        ntoa_dict[server_name].sort(key=ip_address)

    # sort domains from top-level to bottom
    sorted_server_name_to_addresses = dict(
        sorted(
            ntoa_dict.items(),
            key=lambda k: k[0].split('.')[::-1]))

    return sorted_server_name_to_addresses


def reassemble_pairs_to_dict(
        pairs: set,
        get_aton_flag: bool = False,
        get_ntoa_flag: bool = False
):
    """
    Converts (IP address, server name) pairs into sorted dictionaries.

    Args:
        pairs (set): Set of tuples containing (IP address, server name) pairs.
        get_aton_flag (bool): Whether to include address-to-server-names\
            mapping.
        get_ntoa_flag (bool): Whether to include server-name-to-address\
            mapping.

    Returns:
        dict: A dictionary containing one or both mappings based on the flags.
    """
    # if none of flags are set--set both
    if get_aton_flag is False and get_ntoa_flag is False:
        get_aton_flag = True
        get_ntoa_flag = True

    # initialize dict(s)
    if get_aton_flag and get_ntoa_flag:
        aton_dict: defaultdict[Any, list] = defaultdict(list)
        ntoa_dict: defaultdict[Any, list] = defaultdict(list)
    elif get_aton_flag:
        aton_dict = defaultdict(list)
    elif get_ntoa_flag:
        ntoa_dict = defaultdict(list)

    # process <address, server_name> pairs
    for address, server_name in pairs:
        if get_aton_flag:
            aton_dict[address].append(server_name)
        if get_ntoa_flag:
            ntoa_dict[server_name].append(address)

    # sort resulting dict(s)
    if get_aton_flag:
        sorted_aton_dict = sort_aton_dict(aton_dict)
    if get_ntoa_flag:
        sorted_ntoa_dict = sort_ntoa_dict(ntoa_dict)

    # add header(s) (key(s)) for resulting dict(s)
    if get_aton_flag and get_ntoa_flag:
        resulting_dict = {
            'address_to_server_names': sorted_aton_dict,
            'server_name_to_addresses': sorted_ntoa_dict
        }
    elif get_aton_flag:
        resulting_dict = {
            'address_to_server_names':  sorted_aton_dict
        }
    elif get_ntoa_flag:
        resulting_dict = {
            'server_name_to_addresses': sorted_ntoa_dict
        }

    return resulting_dict


def get_sni_dict(
        pcap_path: str,
        display_filter: Optional[str] = None,
        get_ntoa_flag: bool = False,
        get_aton_flag: bool = False,
):
    """
    Processes a pcap file and returns a dictionary of SNI mappings.

    Args:
        pcap_path (str): Path to the pcap file.
        display_filter (Optional[str]): Optional display filter for\
            packet selection.
        get_ntoa_flag (bool): Whether to include SNI-to-address mapping.
        get_aton_flag (bool): Whether to include address-to-SNI mapping.

    Returns:
        dict: A dictionary containing sorted mappings of SNIs to addresses\
            and vice versa.
    """
    pairs = get_pairs_from_pcap(
        pcap_path,
        display_filter=display_filter
    )

    data = reassemble_pairs_to_dict(
        pairs=pairs,
        get_aton_flag=get_aton_flag,
        get_ntoa_flag=get_ntoa_flag
    )

    return data


def parse_arguments() -> Namespace:
    """
    Parses command-line arguments for the script.

    Command-line arguments:
        - `pcap` (str, required): Path to the input pcap or pcapng file.
        - `-f` / `--filter` (str, optional): Display filter for narrowing
          down traffic (alternative to `-Y`).
        - `-i` / `--indent` (int, optional): Number of spaces for JSON output
          indentation.
        - `-N` / `--ntoa` (flag, optional): If provided, includes server names
          to their associated IP addresses in the output.
        - `-A` / `--aton` (flag, optional): If provided, includes IP addresses
          to their associated server names in the output.

    Returns:
        Namespace: An argparse Namespace object containing the parsed arguments
    """
    p = ArgumentParser(
        description='Process a pcap or pcapng file and save SNIs \
            as a JSON file.')
    p.add_argument('pcap', type=str,
                   help='Path to the pcap or pcapng file.')
    p.add_argument('-f', '--filter', type=str,
                   help='Display filter for narrowing down the traffic.')
    p.add_argument('-i', '--indent', type=int,
                   help='Indentation level for the JSON output \
                    (default: none).')
    p.add_argument('-N', '--ntoa', action='store_true',
                   help='Include server names to addresses mapping \
                    in the output.')
    p.add_argument('-A', '--aton', action='store_true',
                   help='Include addresses to server names mapping \
                    in the output.')

    args = p.parse_args()

    return args


def main():
    """
    Main entry point for the script. Parses arguments, processes the pcap file,
    and outputs the result as JSON.
    """
    args = parse_arguments()

    if not Path(args.pcap).exists():
        die(1, f"Error: The file {args.pcap} does not exist.")

    sni_dict = get_sni_dict(
        args.pcap,
        display_filter=args.filter,
        get_ntoa_flag=args.ntoa,
        get_aton_flag=args.aton
    )

    try:
        dump(
            sni_dict,
            fp=sys_stdout,
            ensure_ascii=False,
            indent=args.indent
        )
    except Exception as e:
        die(3, e)

    die(0)


if __name__ == '__main__':
    main()
