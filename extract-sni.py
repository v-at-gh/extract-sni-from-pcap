#!/usr/bin/env python3

from sys import (
    exit as sys_exit,
    stdout as sys_stdout,
    stderr as sys_stderr
)
from pathlib import Path
from typing import NoReturn, Optional
from subprocess import run as subprocess_run
from collections import defaultdict, OrderedDict
from ipaddress import ip_address
from argparse import ArgumentParser, Namespace
from json import dump as json_dump

TSHARK_BIN = "tshark"

# Field for filtering packets by presence of SNI/Host in them
TLS_SNI_FIELD = 'tls.handshake.extensions_server_name'
HTTP_HOST_FIELD = 'http.host'
SNI_FIELDS = [TLS_SNI_FIELD, HTTP_HOST_FIELD]
SNI_FIELDS_FILTER = '(' + ' or '.join(SNI_FIELDS) + ')'

# Exclude servers within private networks; feel free to modify
PRIVATE_NETWORKS_LIST = [
    '127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
PRIVATE_NETWORKS_STR = ', '.join(PRIVATE_NETWORKS_LIST)
PRIVATE_NETWORKS_FILTER = 'not ip.dst in {' + PRIVATE_NETWORKS_STR + '}'


def main() -> NoReturn:
    """
    Main entry point for the script. Parses arguments, processes the pcap file,
    and outputs the result as JSON.
    """
    args = parse_arguments()

    if not Path(args.pcap).exists():
        die(1, f"Error: File {args.pcap} does not exist.")

    if not args.outfile:
        outfile = sys_stdout
    elif Path(args.outfile).exists() and not args.overwrite:
        die(2, f"Error: File {args.outfile} exists.")
    else:
        outfile = Path(args.outfile)

    if args.decrypt:
        if Path(args.decrypt).exists():
            session_keys_file = args.decrypt
        elif not Path(args.decrypt).exists():
            die(3, f"Error: File {args.decrypt} does not exist.")
    else:
        session_keys_file = None

    sni_dict = get_sni_dict(
        args.pcap,
        display_filter=args.filter,
        get_ntoa_flag=args.ntoa,
        get_aton_flag=args.aton,
        sort=args.sort,
        session_keys_file=session_keys_file
    )

    try:
        if outfile is sys_stdout:
            json_dump(
                sni_dict,
                fp=outfile,
                ensure_ascii=False,
                indent=args.indent
            )
        else:
            with open(outfile, mode='w', encoding='utf-8') as f:
                json_dump(
                    sni_dict,
                    fp=f,
                    ensure_ascii=False,
                    indent=args.indent
                )
    except Exception as e:
        die(3, e)

    die(0)


def parse_arguments() -> Namespace:
    """
    Parses command-line arguments for the script.

    Command-line arguments:
        - `pcap` (str, required): Path to the input pcap or pcapng files.
        - `-o` / `--outfile` (str, optional): Path to save the resulting
          JSON file.
        - `-O` / `--ovewwrite` (flag, optional): Overwrite the outfile.
        - `-f` / `--filter` (str, optional): Display filter for narrowing
          down traffic (the `tshark`'s `-Y`).
        - `-i` / `--indent` (int, optional): Number of spaces for JSON output
          indentation.
        - `-N` / `--ntoa` (flag, optional): If provided, includes server names
          to their associated IP addresses in the output.
        - `-A` / `--aton` (flag, optional): If provided, includes IP addresses
          to their associated server names in the output.
        - `-s` / `--sort` (flag, optional): If provided, sort keys and values
          of resulting dictionary.
        - `-D` / `--decrypt` (str, optional): Decrypt TLS/SSL traffic using
          session keys from a file provided with this option.

    Returns:
        Namespace: An argparse Namespace object containing the parsed arguments
    """
    p = ArgumentParser(
        description='Process a pcap or pcapng file and save SNIs \
            as a JSON file.')
    p.add_argument('pcap', type=str,
                   help='Path to the pcap or pcapng files.')
    p.add_argument('-o', '--outfile', type=str,
                   help='Path to save the resulting JSON file.')
    p.add_argument('-O', '--overwrite', action='store_true',
                   help='Overwrite the output file.')
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
    p.add_argument('-s', '--sort', action='store_true',
                   help='Sort keys and values of resulting mappings.')
    p.add_argument('-D', '--decrypt', type=str,
                   help='Path to the file containing TLS/SSL session keys.')

    args = p.parse_args()

    return args


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


def get_sni_dict(
        pcap_path: str,
        display_filter: Optional[str] = None,
        get_ntoa_flag: bool = False,
        get_aton_flag: bool = False,
        sort: bool = False,
        session_keys_file: Optional[str] = None
):
    """
    Processes a pcap file and returns a dictionary of SNI mappings.

    Args:
        pcap_path (str): Path to the pcap file.
        display_filter (Optional[str]): Optional display filter for\
            packet selection.
        get_ntoa_flag (bool): Whether to include SNI-to-address mapping.
        get_aton_flag (bool): Whether to include address-to-SNI mapping.
        sort (bool): Whether to sort keys and values of resulting dictionary.

    Returns:
        dict: A dictionary containing sorted mappings of SNIs to addresses\
            and vice versa.
    """
    # if neither flag is set, set both
    if get_aton_flag is False and get_ntoa_flag is False:
        get_aton_flag = True
        get_ntoa_flag = True

    pairs = get_pairs_from_pcap(
        pcap_path,
        display_filter=display_filter,
        session_keys_file=session_keys_file
    )

    data = reassemble_pairs_to_dict(
        pairs=pairs,
        get_aton_flag=get_aton_flag,
        get_ntoa_flag=get_ntoa_flag,
        sort=sort
    )

    return data


def get_pairs_from_pcap(
        pcap_file_path_str: str,
        display_filter: Optional[str],
        session_keys_file: Optional[str]
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
    filter_parts = [PRIVATE_NETWORKS_FILTER, SNI_FIELDS_FILTER]
    if display_filter is None:
        resulting_display_filter = " and ".join(filter_parts)
    else:
        filter_parts.append(display_filter)
        resulting_display_filter = " and ".join(filter_parts)

    # the resulting command argv
    command = [
        TSHARK_BIN, "-n", "-r", pcap_file_path_str,
        "-Y", resulting_display_filter,
        "-T", "fields", "-E", "separator=,",
        "-e", "ip.dst",
        "-e", TLS_SNI_FIELD,
        "-e", HTTP_HOST_FIELD
    ]

    if session_keys_file:
        command.extend(["-o", f"tls.keylog_file:{session_keys_file}"])

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
            return set(tuple(p.split(',')) for p in result.stdout.splitlines())
    except Exception as e:
        raise e


def reassemble_pairs_to_dict(
        pairs: set,
        get_aton_flag: bool,
        get_ntoa_flag: bool,
        sort: bool
):
    """
    Converts (IP address, server name) pairs into sorted dictionaries.

    Args:
        pairs (set): Set of tuples containing (IP address, server name) pairs.
        get_aton_flag (bool): Whether to include address-to-server-names\
            mapping.
        get_ntoa_flag (bool): Whether to include server-name-to-address\
            mapping.
        sort (bool): Whether to sort keys and values of resulting dictionary.

    Returns:
        dict: A dictionary containing one or both mappings based on the flags.
    """
    # initialize dict(s)
    if get_aton_flag:
        aton_dict = defaultdict(set)
    if get_ntoa_flag:
        ntoa_dict = defaultdict(set)

    # process <address, tls, http> tuples
    for address, server_name_tls, server_name_http in pairs:
        if get_aton_flag:
            if server_name_tls:
                aton_dict[address].add(server_name_tls)
            if server_name_http:
                aton_dict[address].add(server_name_http)
        if get_ntoa_flag:
            if server_name_tls:
                ntoa_dict[server_name_tls].add(address)
            if server_name_http:
                ntoa_dict[server_name_http].add(address)

    if get_aton_flag:
        for k in aton_dict.keys():
            aton_dict[k] = list(aton_dict[k])
    if get_ntoa_flag:
        for k in ntoa_dict.keys():
            ntoa_dict[k] = list(ntoa_dict[k])

    if sort:
        # sort resulting dict(s)
        aton_dict = sort_aton_dict(aton_dict) # if get_aton_flag else None
        ntoa_dict = sort_ntoa_dict(ntoa_dict) # if get_ntoa_flag else None

    # add header(s) (key(s)) for resulting dict(s)
    if get_aton_flag and get_ntoa_flag:
        return {
            'address_to_server_names':  aton_dict,
            'server_name_to_addresses': ntoa_dict
        }
    if get_aton_flag:
        return {'address_to_server_names':  aton_dict}
    if get_ntoa_flag:
        return {'server_name_to_addresses': ntoa_dict}


def sort_aton_dict(aton_dict: dict) -> OrderedDict:
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
    sorted_address_to_server_names = OrderedDict(
        sorted(
            aton_dict.items(),
            key=lambda item: ip_address(item[0])))

    return sorted_address_to_server_names


def sort_ntoa_dict(ntoa_dict: dict) -> OrderedDict:
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
    sorted_server_name_to_addresses = OrderedDict(
        sorted(
            ntoa_dict.items(),
            key=lambda k: k[0].split('.')[::-1]))

    return sorted_server_name_to_addresses


if __name__ == '__main__':
    main()
