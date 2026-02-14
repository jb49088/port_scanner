# ================================================================================
# =                                 PORT_SCANNER                                 =
# ================================================================================

"""
TCP Packet Structure
----------------------------------
Header: 20+ bytes
  Source Port:              2 bytes
  Destination Port:         2 bytes
  Sequence Number:          4 bytes
  Acknowledgement Number:   4 bytes
  Data Offset:              4 bits
  Reserved:                 3 bits
  Flags:                    9 bits
  Window Size:              2 bytes
  Checksum:                 2 bytes
  Urgent Pointer:           2 bytes
  Options:                  0–40 bytes

Data: 0+ bytes

Total: 20+ bytes
"""

import argparse
import socket
import subprocess


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("host", help="Host to scan.")

    args = parser.parse_args()

    return args


def is_host_reachable(address: str):
    result = subprocess.run(
        ["ping", "-c", "1", "-w", "1", address], capture_output=True
    )

    if result.returncode != 0:
        return False

    return True


def port_scanner():
    args = parse_args()
    hostname = args.host

    try:
        address = socket.gethostbyname(hostname)
    except socket.gaierror:
        print("\nAddress resolution failed.\n")
        return

    if not is_host_reachable(address):
        print("\nHost unreachable.\n")
        return

    for port in range(1, 1025):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.01)
        result = sock.connect_ex((address, port))
        if result == 0:
            print(f"Port {port} open.")


if __name__ == "__main__":
    port_scanner()
