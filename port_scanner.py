# ================================================================================
# =                                 PORT_SCANNER                                 =
# ================================================================================

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
        return False


if __name__ == "__main__":
    port_scanner()
